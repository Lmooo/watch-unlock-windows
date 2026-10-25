use std::io::{BufRead, BufReader, Read, Write};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::backend;
use crate::processes::Processes;

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Started,
    Waiting,
    Stopped,
}

#[derive(Clone, Deserialize, Serialize)]
struct PairingStatus {
    event: String,
    status: Status,
    paired: bool,
    irk_verified: bool,
    watch_identity_verified: bool,
    advertising: String,
    subscriptions: u32,
    encrypted_reads: u32,
    remaining_seconds: u64,
    reason: String,
}

pub fn stop(processes: &Processes) -> Result<(), String> {
    if let Some(cancel) = processes.pairing.lock().map_err(|_| "process_state_failed")?.as_ref() {
        cancel.store(true, Ordering::SeqCst);
    }
    Ok(())
}

pub fn start(app: AppHandle, processes: &Processes) -> Result<(), String> {
    let mut slot = processes.pairing.lock().map_err(|_| "process_state_failed")?;
    if slot.is_some() { return Err("pairing_already_running".into()); }
    let mut child = backend::command()?
        .args(["pair", "--seconds", "120"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| "pairing_start_failed")?;
    let stdout = child.stdout.take().ok_or("pairing_output_unavailable")?;
    let cancel = Arc::new(AtomicBool::new(false));
    *slot = Some(cancel.clone());
    drop(slot);
    let state = processes.pairing.clone();
    let app_reader = app.clone();
    let failed = Arc::new(AtomicBool::new(false));
    let reader_failed = failed.clone();
    let paired = Arc::new(AtomicBool::new(false));
    let reader_paired = paired.clone();
    let terminal = Arc::new(AtomicBool::new(false));
    let reader_terminal = terminal.clone();
    let reader = std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut bytes = Vec::new();
            match reader.by_ref().take(8193).read_until(b'\n', &mut bytes) {
                Ok(0) => break,
                Ok(_) if bytes.len() <= 8192 && bytes.last() == Some(&b'\n') => {},
                _ => { reader_failed.store(true, Ordering::SeqCst); break; }
            }
            let Ok(event) = serde_json::from_slice::<PairingStatus>(&bytes) else {
                reader_failed.store(true, Ordering::SeqCst);
                break;
            };
            if event.event != "pairing_window" || event.advertising.len() > 64
                || event.reason.len() > 128 || event.remaining_seconds > 120
                || event.irk_verified || event.watch_identity_verified {
                reader_failed.store(true, Ordering::SeqCst);
                break;
            }
            if event.paired { reader_paired.store(true, Ordering::SeqCst); }
            let stopped = matches!(event.status, Status::Stopped);
            if stopped { reader_terminal.store(true, Ordering::SeqCst); }
            let _ = app_reader.emit("pairing-status", event);
            if stopped { break; }
        }
    });
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(130);
        let mut shutdown_at: Option<Instant> = None;
        let mut error = false;
        loop {
            if failed.load(Ordering::SeqCst) || Instant::now() >= deadline {
                error = true;
                cancel.store(true, Ordering::SeqCst);
            }
            if cancel.load(Ordering::SeqCst) && shutdown_at.is_none() {
                if let Some(mut input) = child.stdin.take() { let _ = input.write_all(b"cancel\n"); }
                shutdown_at = Some(Instant::now());
            }
            if shutdown_at.is_some_and(|at| at.elapsed() >= Duration::from_secs(2)) { break; }
            match child.try_wait() {
                Ok(Some(exit)) => { error |= !exit.success(); break; },
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => { error = true; break; },
            }
        }
        let _ = child.kill();
        let _ = child.wait();
        let _ = reader.join();
        cancel.store(true, Ordering::SeqCst);
        if let Ok(mut slot) = state.lock() { *slot = None; }
        if !terminal.load(Ordering::SeqCst) {
            let _ = app.emit("pairing-status", PairingStatus {
                event: "pairing_window".into(), status: Status::Stopped,
                paired: paired.load(Ordering::SeqCst),
                irk_verified: false, watch_identity_verified: false,
                advertising: "stopped".into(), subscriptions: 0, encrypted_reads: 0,
                remaining_seconds: 0, reason: "native_process_stopped".into(),
            });
        }
        if error { let _ = app.emit("pairing-error", "pairing_failed"); }
    });
    Ok(())
}
