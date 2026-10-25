use super::*;

const POLICY: DevicePolicy = DevicePolicy {
    near_rssi: -60,
    far_rssi: -80,
};
const LOCKED: Session = Session { generation: 1, locked: true };

fn observe(device: &DeviceAuthority, origin: Instant, milliseconds: u64, rssi: i16) -> SignalTransition {
    device.observe(LOCKED, rssi, origin + Duration::from_millis(milliseconds), milliseconds).unwrap()
}

fn ready() -> SubmissionConditions {
    SubmissionConditions { locked: true, provider_ready: true, verified_locked: true,
        credential_configured: true, scanner_running: true }
}

fn at(origin: Instant, milliseconds: u64) -> Instant { origin + Duration::from_millis(milliseconds) }

#[test]
fn nearby_lock_and_repeated_display_wakes_never_create_authority() {
    let origin = Instant::now();
    let initial = observe(&DeviceAuthority::new(POLICY), origin, 0, -40);
    assert_eq!(initial.decision, Decision::None);
    // A display wake keeps a healthy scanner, but contributes no signal or authority.
    let next = observe(&initial.authority, origin, 1000, -40);
    let (_, submit) = SubmissionGate::default().reserve(ready(), next.authority.authorized(at(origin, 1000)));
    assert!(!submit);
    assert!(!next.authority.armed());
    assert_eq!(next.decision, Decision::None);
}

#[test]
fn real_far_then_first_near_after_hours_of_healthy_silence_can_submit_once() {
    let origin = Instant::now();
    let far = observe(&DeviceAuthority::new(POLICY), origin, 1, -80);
    assert!(far.crossed_far);
    assert!(far.authority.rssi(origin + Duration::from_secs(3600)).is_none());
    let returned = observe(&far.authority, origin, 3_600_001, -60);
    assert_eq!(returned.decision, Decision::ReturnUnlock);
    let (reserved, submit) = SubmissionGate::default().reserve(ready(), returned.authority.authorized(at(origin, 3_600_001)));
    assert!(submit);
    // Reserving before IPC means a failed send, another device or a config reload
    // cannot create a second attempt in the same Windows lock cycle.
    let (again, duplicate) = reserved.reserve(ready(), true);
    assert!(!duplicate);
    assert!(again.submitted());
}

#[test]
fn lock_floor_discards_queued_prelock_far_and_adapter_failure_rejects_queue() {
    let origin = Instant::now();
    let floor = origin + Duration::from_millis(100);
    assert!(!accepts_signal(origin, floor, floor, true));
    assert!(!accepts_signal(floor, floor, floor, false));
    assert!(accepts_signal(floor, floor, floor, true));
    assert!(!accepts_signal(floor, floor + SIGNAL_FRESH + Duration::from_millis(1), floor, true));
    assert!(!accepts_signal(floor + Duration::from_millis(1), floor, floor, true));
    let nearby = observe(&DeviceAuthority::new(POLICY), origin, 101, -40);
    assert_eq!(nearby.decision, Decision::None);
    assert!(!nearby.authority.authorized(at(origin, 101)));
}

#[test]
fn failed_scanner_suspend_restart_and_relock_revoke_observed_far() {
    let origin = Instant::now();
    let far = observe(&DeviceAuthority::new(POLICY), origin, 0, -90);
    for revoked in [
        far.authority.invalidate(LOCKED, 1).unwrap(),
        DeviceAuthority::new(POLICY),
        far.authority.invalidate(Session { generation: 2, locked: true }, 1).unwrap(),
    ] {
        let generation = revoked.state.generation().max(1);
        let next = revoked.observe(Session { generation, locked: true }, -40, at(origin, 2), 2).unwrap();
        assert_eq!(next.decision, Decision::None);
        assert!(!next.authority.authorized(at(origin, 2)));
    }
    // If the scanner dies after signal evaluation, the final side-effect gate
    // still rejects the otherwise-valid arrival until invalidation is processed.
    let returned = observe(&far.authority, origin, 1, -40);
    let (_, submit) = SubmissionGate::default().reserve(SubmissionConditions { scanner_running: false, ..ready() },
        returned.authority.authorized(at(origin, 1)));
    assert!(!submit);
}

#[test]
fn out_of_order_callbacks_cannot_invent_a_far_return_after_a_newer_near() {
    let origin = Instant::now();
    let nearby = observe(&DeviceAuthority::new(POLICY), origin, 20, -40);
    let delayed_far = observe(&nearby.authority, origin, 10, -90);
    assert!(!delayed_far.crossed_far);
    assert!(!delayed_far.authority.armed());
    let later = observe(&delayed_far.authority, origin, 21, -40);
    assert!(!later.authority.authorized(at(origin, 21)));
}

#[test]
fn different_devices_keep_thresholds_and_evidence_separate() {
    let origin = Instant::now();
    let first = observe(&DeviceAuthority::new(POLICY), origin, 0, -85);
    let strict_policy = DevicePolicy { near_rssi: -35, far_rssi: -95 };
    let second = observe(&DeviceAuthority::new(strict_policy), origin, 1, -85);
    assert!(first.authority.armed());
    assert!(!second.authority.armed());
    let first_return = observe(&first.authority, origin, 2, -50);
    let second_middle = observe(&second.authority, origin, 2, -50);
    assert!(first_return.authority.authorized(at(origin, 2)));
    assert!(!second_middle.authority.authorized(at(origin, 2)));
    let second_near = observe(&second_middle.authority, origin, 3, -30);
    assert_eq!(second_near.decision, Decision::None);
    assert!(!second_near.authority.authorized(at(origin, 3)));
}

#[test]
fn expired_unsubmitted_arrival_needs_a_fresh_far_crossing() {
    let origin = Instant::now();
    let far = observe(&DeviceAuthority::new(POLICY), origin, 0, -90);
    let returned = observe(&far.authority, origin, 1, -40);
    let (_, submit) = SubmissionGate::default().reserve(SubmissionConditions { provider_ready: false, ..ready() },
        returned.authority.authorized(at(origin, 1)));
    assert!(!submit);
    let (expired, did_expire) = returned.authority.expire_return(at(origin, 2002));
    assert!(did_expire);
    assert!(!expired.armed());
    let nearby = observe(&expired, origin, 2003, -40);
    assert_eq!(nearby.decision, Decision::None);
    assert!(!nearby.authority.authorized(at(origin, 2003)));
    let fresh_far = observe(&nearby.authority, origin, 2004, -90);
    assert!(fresh_far.crossed_far);
    let fresh_return = observe(&fresh_far.authority, origin, 2005, -40);
    assert!(fresh_return.authority.authorized(at(origin, 2005)));
}

#[test]
fn scanner_failure_after_arrival_before_submission_allows_secure_retry() {
    let origin = Instant::now();
    let far = observe(&DeviceAuthority::new(POLICY), origin, 0, -90);
    let returned = observe(&far.authority, origin, 1, -40);
    let failed = returned.authority.invalidate(LOCKED, 2).unwrap();
    let nearby = observe(&failed, origin, 3, -40);
    assert_eq!(nearby.decision, Decision::None);
    assert!(!nearby.authority.authorized(at(origin, 3)));
    let fresh_far = observe(&nearby.authority, origin, 4, -90);
    assert!(fresh_far.crossed_far);
    // A consumed submission is distinct from a failed/unsubmitted arrival.
    let consumed = returned.authority.consume_submission().invalidate(LOCKED, 2).unwrap();
    let after_submission = observe(&consumed, origin, 3, -40);
    assert_eq!(after_submission.decision, Decision::None);
    assert!(!after_submission.authority.authorized(at(origin, 3)));
}

#[test]
fn every_platform_precondition_fails_closed_before_ipc_is_reserved() {
    for unavailable in [
        SubmissionConditions { locked: false, ..ready() },
        SubmissionConditions { provider_ready: false, ..ready() },
        SubmissionConditions { verified_locked: false, ..ready() },
        SubmissionConditions { credential_configured: false, ..ready() },
        SubmissionConditions { scanner_running: false, ..ready() },
    ] {
        let (gate, submit) = SubmissionGate::default().reserve(unavailable, true);
        assert!(!submit);
        assert!(!gate.submitted());
    }
    let (_, no_authority) = SubmissionGate::default().reserve(ready(), false);
    assert!(!no_authority);
}

#[test]
fn ipc_grant_uses_the_earlier_of_signal_freshness_and_return_window() {
    let origin = Instant::now();
    let far = observe(&DeviceAuthority::new(POLICY), origin, 0, -90);
    let arrived = observe(&far.authority, origin, 1, -40);
    let later_near = observe(&arrived.authority, origin, 1000, -40);
    // Default window equals signal freshness: the return at 1 ms bounds it.
    assert_eq!(later_near.authority.authorization_deadline(at(origin, 1000)), Some(at(origin, 2001)));
    let windowed = observe(&far.authority.with_return_window(Duration::from_secs(30)), origin, 1, -40);
    let later = observe(&windowed.authority, origin, 1000, -40);
    assert_eq!(later.authority.authorization_deadline(at(origin, 1000)), Some(at(origin, 1000) + SIGNAL_FRESH));
    let nearby = observe(&DeviceAuthority::new(POLICY), origin, 0, -40);
    assert!(nearby.authority.authorization_deadline(origin).is_none());
}

#[test]
fn return_waits_for_the_logon_ui_within_the_configured_window() {
    let origin = Instant::now();
    let device = DeviceAuthority::new(POLICY).with_return_window(Duration::from_secs(30));
    let far = observe(&device, origin, 0, -90);
    let returned = observe(&far.authority, origin, 1, -40);
    // The logon UI connects 10 s later while the watch keeps advertising nearby.
    let (kept, expired) = returned.authority.expire_return(origin + Duration::from_secs(10));
    assert!(!expired);
    let still_near = observe(&kept, origin, 10_000, -45);
    assert!(still_near.authority.authorized(origin + Duration::from_secs(10)));
    // Seamless: the window counts from the return, however long the watch stays near.
    let (_, gone) = still_near.authority.expire_return(at(origin, 30_002));
    assert!(gone);
}

#[test]
fn held_return_waits_for_input_while_the_watch_stays_near() {
    let origin = Instant::now();
    let device = DeviceAuthority::new(POLICY).with_return_window(Duration::from_secs(30)).with_hold_while_near(true);
    let far = observe(&device, origin, 0, -90);
    let mut current = observe(&far.authority, origin, 1, -40).authority;
    // The user sits down and only touches the mouse two minutes later.
    for second in 1..=120u64 {
        current = observe(&current, origin, second * 1000, -45).authority;
        let (kept, expired) = current.expire_return(at(origin, second * 1000));
        assert!(!expired);
        current = kept;
    }
    assert!(current.authorized(at(origin, 120_000)));
    // Out of range for longer than the window ends it.
    let (_, gone) = current.expire_return(at(origin, 150_001));
    assert!(gone);
    // Crossing the far threshold again also ends it; only a new return authorizes.
    let left = observe(&current, origin, 121_000, -90);
    assert!(left.crossed_far);
    assert!(!left.authority.authorized(at(origin, 121_000)));
}

#[test]
fn input_must_follow_the_return_tick_even_across_wraparound() {
    assert!(!input_after(None, 100));
    assert!(!input_after(Some(100), 100));
    assert!(!input_after(Some(99), 100));
    assert!(input_after(Some(101), 100));
    assert!(input_after(Some(5), u32::MAX - 5));
}

#[test]
fn a_kept_return_needs_a_fresh_near_signal_and_ends_when_leaving_again() {
    let origin = Instant::now();
    let device = DeviceAuthority::new(POLICY).with_return_window(Duration::from_secs(30));
    let far = observe(&device, origin, 0, -90);
    let returned = observe(&far.authority, origin, 1, -40);
    // No advertisement for 10 s: the return is kept but cannot submit on stale distance.
    assert!(!returned.authority.authorized(origin + Duration::from_secs(10)));
    let left = observe(&returned.authority, origin, 5_000, -90);
    assert!(left.crossed_far);
    // Leaving discards the pending return, so nothing remains to expire.
    assert!(!left.authority.expire_return(origin + Duration::from_secs(60)).1);
    // Coming back again is a new return with its own window.
    let back = observe(&left.authority, origin, 6_000, -40);
    assert_eq!(back.decision, Decision::ReturnUnlock);
    assert!(back.authority.authorized(at(origin, 6_000)));
}
