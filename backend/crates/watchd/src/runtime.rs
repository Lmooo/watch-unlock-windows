//! Device-independent policy and Windows side effects.

use anyhow::Result;
use serde_json::json;
use std::collections::BTreeSet;
use std::sync::{mpsc,Arc};
use std::sync::atomic::{AtomicU64,Ordering};
use std::time::{Duration,Instant,SystemTime};
use watch_unlock_domain::{Decision,Session};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle,GetLastError,ERROR_ALREADY_EXISTS};
use windows::Win32::System::Com::{CoInitializeEx,COINIT_MULTITHREADED};
use windows::Win32::System::Power::{SetThreadExecutionState,ES_CONTINUOUS,ES_DISPLAY_REQUIRED};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{CreateMutexW,GetCurrentProcessId};
use windows::Win32::System::SystemInformation::GetTickCount;
use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo,LASTINPUTINFO};
use crate::{adapters,audit,ble,pipe,registry,session};

#[path = "runtime_policy.rs"]
mod policy;
use policy::{accepts_signal, input_after, DeviceAuthority, SubmissionConditions, SubmissionGate};

struct DeviceRuntime {
    config:registry::Device,
    adapter:Box<dyn adapters::DeviceAdapter>,
    authority:DeviceAuthority,
    /// Tick of this lock cycle's far-then-near return. With seamless unlock off, only
    /// keyboard or mouse input after it may submit.
    return_tick:Option<u32>,
}

fn devices(previous:&[DeviceRuntime])->Result<Vec<DeviceRuntime>> {
    registry::load_devices()?.into_iter().filter(|d|d.enabled).map(|config| {
        let authority=previous.iter().find(|device|device.config.id==config.id)
            .map_or_else(||DeviceAuthority::new(config.policy()),|device|device.authority.with_policy(config.policy()))
            .with_return_window(config.return_window())
            .with_hold_while_near(!config.auto_unlock_on_return);
        let return_tick=previous.iter().find(|device|device.config.id==config.id).and_then(|device|device.return_tick);
        Ok(DeviceRuntime {adapter:adapters::create(&config)?,authority,config,return_tick})
    }).collect()
}

fn revision()->Vec<(String,Option<(SystemTime,u64)>)> {
    let dir=registry::data_dir().ok();
    let names=["devices.json","notifications.json","cred.blob","bark-key.dpapi"]
        .into_iter().map(String::from)
        .chain(registry::load_devices().unwrap_or_default().into_iter()
            .map(|device|format!("device-{}.dpapi",device.id))).collect::<BTreeSet<_>>();
    names.into_iter().map(|name| {
        let metadata=dir.as_ref().and_then(|dir|std::fs::metadata(dir.join(&name)).ok());
        let stamp=metadata.and_then(|value|Some((value.modified().ok()?,value.len())));
        (name,stamp)
    }).collect()
}

/// Tick of the last keyboard or mouse input in this session (GetLastInputInfo is session-wide).
fn last_input_tick()->Option<u32> {
    let mut info=LASTINPUTINFO{cbSize:std::mem::size_of::<LASTINPUTINFO>() as u32,dwTime:0};
    unsafe {GetLastInputInfo(&mut info)}.as_bool().then_some(info.dwTime)
}

fn watcher(sender:&mpsc::SyncSender<ble::Advertisement>,counter:&Arc<AtomicU64>)->Result<ble::AdvertisementWatcher> {
    let output=sender.clone();let count=Arc::clone(counter);
    let watcher=ble::make_watcher(move |adv| {
        count.fetch_add(1,Ordering::Relaxed);
        let _=output.try_send(adv.clone());
    })?;
    watcher.start()?;
    Ok(watcher)
}

pub fn run()->Result<()> {
    let mut session_id=0;
    unsafe {ProcessIdToSessionId(GetCurrentProcessId(),&mut session_id)?;}
    let mutex_name=format!("Local\\WatchUnlockWindowsDaemon-{session_id}\0").encode_utf16().collect::<Vec<_>>();
    let mutex=unsafe {CreateMutexW(None,true,PCWSTR(mutex_name.as_ptr()))?};
    if unsafe {GetLastError()}==ERROR_ALREADY_EXISTS {unsafe {let _=CloseHandle(mutex);} anyhow::bail!("Already running");}
    // The process owns this mutex until exit; the OS closes it on termination.
    let _mutex=mutex;
    // Do not reset: a stop requested while this process starts must still be honoured.
    let stop=crate::stop::StopSignal::open(false)?;
    if registry::remove_legacy_confirmation().is_err() {
        audit::record("legacy_cleanup_failed",None,"旧版手表确认功能的残留数据未能清理");
    }
    unsafe {let _=CoInitializeEx(None,COINIT_MULTITHREADED);}
    let (session_tx,session_rx)=mpsc::channel();
    let (adv_tx,adv_rx)=mpsc::sync_channel(64);
    let (pipe_tx,pipe_rx)=mpsc::channel();
    let (command_tx,command_rx)=mpsc::channel();
    session::start_session_events(session_tx)?;
    pipe::start_pipe_server(pipe_tx,command_rx)?;
    let counter=Arc::new(AtomicU64::new(0));
    let mut scanner=Some(watcher(&adv_tx,&counter)?);
    let mut active=devices(&[])?;
    let origin=Instant::now();
    let mut lock=Session{generation:1,locked:session::current_session_locked().unwrap_or(false)};
    let mut submissions=SubmissionGate::default();
    let mut provider=None;
    let mut scan_requested=true;
    let mut previous_revision=revision();
    let mut last_housekeeping=Instant::now();
    let mut last_rebuild=Instant::now();
    let mut evidence_floor=Instant::now();
    let mut deferred_session=None;
    let mut session_known=true;
    // Set when the lock-state probes fail, so a silent monitor outage stays visible.
    let mut session_query_failed=false;
    // Set when this lock cycle submitted an unlock, for the post-unlock notification.
    let mut notify_on_unlock=false;
    audit::record("backend_started",None,"后台已启动；佩戴与手表锁定状态未知");
    loop {
        if stop.requested() {
            audit::record("backend_stopped",None,"后台已按请求停止，不再参与解锁");
            let _=registry::write_json("status.json",&json!({"running":false,"at_ms":audit::epoch_ms()}));
            return Ok(());
        }
        let now=Instant::now();
        let at_ms=origin.elapsed().as_millis() as u64;
        let mut invalidate=false;
        let mut new_lock=false;
        let mut write_status=false;
        loop {
            let event=match deferred_session.take().map(Ok).unwrap_or_else(||session_rx.try_recv()) {
                Ok(event)=>event,
                Err(mpsc::TryRecvError::Empty)=>break,
                Err(mpsc::TryRecvError::Disconnected)=>anyhow::bail!("Session monitoring unavailable"),
            };
            match event {
                session::SessionEvent::Lock if !lock.locked=>{
                    lock=Session{generation:lock.generation+1,locked:true};
                    session_known=true;
                    submissions=SubmissionGate::default();invalidate=true;new_lock=true;notify_on_unlock=false;
                    audit::record("session_locked",None,"新锁屏周期，等待手表远离后返回");
                }
                session::SessionEvent::Unlock=>{
                    if lock.locked && std::mem::take(&mut notify_on_unlock) {crate::notify::notify_unlock_async();}
                    lock.locked=false;session_known=true;invalidate=true;provider=None;
                    // A WTS event cannot prove which credential provider succeeded.
                    audit::record("session_unlocked",None,"Windows 会话已解锁；认证来源未归因");
                }
                session::SessionEvent::Pause(session::PauseReason::DisplayOff)=>{},
                session::SessionEvent::Pause(_)=>{
                    scan_requested=false;scanner=None;invalidate=true;
                }
                session::SessionEvent::Resume=>{scan_requested=true;invalidate=true;}
                session::SessionEvent::Wake(_)=>{
                    scan_requested=true;
                    // Display wake never creates authority. A healthy running scanner
                    // retains previously observed far evidence across display-off.
                    if scanner.is_none(){invalidate=true;}
                }
                _=>{}
            }
        }
        while let Ok(event)=pipe_rx.try_recv() {
            match event {
                pipe::PipeEvent::Hello(connection)=>{
                    // Once per connection: shows when the logon UI actually became ready.
                    if provider.is_none() {
                        audit::record("provider_connected",None,"登录界面组件已连接，可以接收解锁");
                    }
                    provider=Some(connection)
                }
                pipe::PipeEvent::Gone=>provider=None,
            }
        }
        // Revoke as soon as a stopped adapter is observed, independently of the
        // slower rebuild backoff. No queued packet can revive a failed scanner.
        if scanner.as_ref().is_some_and(|scanner|!scanner.is_running()) {
            scanner=None;invalidate=true;
            audit::record("scanner_unavailable",None,"扫描器已停止，旧距离证据已立即撤销");
        }
        if last_housekeeping.elapsed()>=Duration::from_secs(1) {
            last_housekeeping=now;
            write_status=true;
            let observed=session::current_session_locked();
            session_known=observed.is_ok();
            if observed.is_err()!=session_query_failed {
                session_query_failed=observed.is_err();
                audit::record(if session_query_failed {"session_state_unknown"} else {"session_state_recovered"},
                    None, if session_query_failed {
                        "无法读取锁屏状态，距离证据暂停采信"
                    } else {"锁屏状态恢复可读"});
            }
            match observed {
                Ok(locked) if locked!=lock.locked=>{
                    if !locked && std::mem::take(&mut notify_on_unlock) {crate::notify::notify_unlock_async();}
                    lock=Session{generation:lock.generation+1,locked};
                    if locked {submissions=SubmissionGate::default();new_lock=true;notify_on_unlock=false;}
                    invalidate=true;
                    audit::record("session_reconciled",None,"会话状态已重新核对，旧授权已撤销");
                }
                Err(_)=>{invalidate=true;},
                _=>{}
            }
            let next_revision=revision();
            if next_revision!=previous_revision {
                active=devices(&active)?;previous_revision=next_revision;invalidate=true;
                lock.generation+=1;
                audit::record("configuration_reloaded",None,"配置变更，旧授权已撤销");
            }
            if scan_requested && scanner.as_ref().is_none_or(|scanner|!scanner.is_running())
                && last_rebuild.elapsed()>Duration::from_secs(5) {
                drop(scanner.take());invalidate=true;last_rebuild=now;
                scanner=watcher(&adv_tx,&counter).ok();
                audit::record("scanner_reset",None,"扫描器已重建，旧距离证据已撤销");
            }
        }
        if invalidate {
            evidence_floor=Instant::now();
            let _=command_tx.send(pipe::PipeCommand::Cancel);
            for device in &mut active {
                device.authority=device.authority.invalidate(lock,at_ms)?;
                if new_lock {device.return_tick=None;}
            }
            for _ in adv_rx.try_iter().take(64) {}
        }
        // Bound each batch so BLE traffic cannot starve power/session revocation.
        for adv in adv_rx.try_iter().take(64) {
            let sample_now=Instant::now();
            if !accepts_signal(adv.received_at,sample_now,evidence_floor,
                session_known && scan_requested && scanner.as_ref().is_some_and(|scanner|scanner.is_running())) {continue;}
            if !(-127..=20).contains(&adv.rssi) {continue;}
            for device in &mut active {
                if !device.adapter.matches(&adv){continue;}
                let transition=device.authority.observe(lock,adv.rssi,adv.received_at,at_ms)?;
                device.authority=transition.authority;
                if transition.crossed_far {
                    audit::record("far_threshold_crossed",Some(&device.config.id),"已观察到远阈值越界，无驻留等待");
                }
                if transition.decision==Decision::ReturnUnlock {
                    device.return_tick=Some(unsafe {GetTickCount()});
                    audit::record("return_detected",Some(&device.config.id),if device.config.auto_unlock_on_return {
                        "已观察到远离后的首次近阈值返回"
                    } else {"已观察到远离后返回；无感解锁已关闭，等待键盘或鼠标操作"});
                }
            }
        }
        for device in &mut active {
            let (authority,expired)=device.authority.expire_return(Instant::now());
            device.authority=authority;
            if expired {
                device.return_tick=None;
                audit::record("return_authorization_expired",Some(&device.config.id),"返回授权已过期，需要新的远离证据");
            }
        }
        let now=Instant::now();
        let last_input=last_input_tick();
        let authorized=active.iter().find(|device| device.authority.authorized(now)
            && (device.config.auto_unlock_on_return || device.return_tick.is_some_and(|tick|input_after(last_input,tick))));
        if let Some(device)=authorized {
            let verified_locked=session::current_session_locked().unwrap_or(false);
            let credential_configured=crate::enroll::credential_configured();
            // OS/storage checks may block. Re-evaluate absolute signal deadlines
            // afterwards, and handle any intervening session event before the
            // next attempt instead of dropping it from the queue.
            let session_event_pending=match session_rx.try_recv() {
                Ok(event)=>{deferred_session=Some(event);true},
                Err(mpsc::TryRecvError::Empty)=>false,
                Err(mpsc::TryRecvError::Disconnected)=>anyhow::bail!("Session monitoring unavailable"),
            };
            let configuration_current=revision()==previous_revision;
            if !configuration_current {
                last_housekeeping=Instant::now()-Duration::from_secs(1);
            }
            let deadline=device.authority.authorization_deadline(Instant::now());
            let conditions=SubmissionConditions {locked:lock.locked,provider_ready:provider.is_some(),
                verified_locked:verified_locked && session_known && !session_event_pending && configuration_current,credential_configured,
                scanner_running:scan_requested && scanner.as_ref().is_some_and(|scanner|scanner.is_running())};
            let (next,submit)=submissions.reserve(conditions,deadline.is_some());
            submissions=next;
            if submit {
                // Mark before IPC: any outcome consumes this lock cycle's attempt.
                let device_id=device.config.id.clone();
                for device in &mut active {device.authority=device.authority.consume_submission();device.return_tick=None;}
                if let (Some(connection),Some(valid_until))=(provider.clone(),deadline) {
                    let _=command_tx.send(pipe::PipeCommand::Unlock(pipe::UnlockGrant::new(connection,valid_until)));
                }
                notify_on_unlock=true;
                audit::record("unlock_submitted",Some(&device_id),"已向验证过的 Credential Provider 提交一次请求");
                unsafe {SetThreadExecutionState(ES_CONTINUOUS|ES_DISPLAY_REQUIRED);SetThreadExecutionState(ES_CONTINUOUS);}
            }
        }
        if write_status {
            let status_now=Instant::now();
            let status=active.iter().map(|device|json!({"id":device.config.id,
                "rssi":device.authority.rssi(status_now),
                "presence":if device.authority.near(status_now){"near"}else if device.authority.armed(){"away"}else{"unknown"},
                "armed":device.authority.armed(),"wearer_state":"unknown"})).collect::<Vec<_>>();
            let _=registry::write_json("status.json",&json!({"running":true,"at_ms":audit::epoch_ms(),
                "locked":lock.locked,"provider_ready":provider.is_some(),"scanner_active":scanner.as_ref().is_some_and(|s|s.is_running()),
                "submitted_this_lock":submissions.submitted(),"devices":status}));
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}
