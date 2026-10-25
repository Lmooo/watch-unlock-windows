use std::io::{BufRead, BufReader, Read};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};

use crate::backend;

#[derive(Default)]
pub struct Processes {
    pub daemon: Mutex<Option<Child>>,
    pub scan: Arc<Mutex<Option<Arc<AtomicBool>>>>,
    pub pairing: Arc<Mutex<Option<Arc<AtomicBool>>>>,
}

#[derive(Serialize)]
pub struct RuntimeStatus {
    backend_available: bool,
    daemon_running: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Advertisement {
    address: String,
    name: Option<String>,
    rssi: i16,
    apple: bool,
    matched_device_id: Option<String>,
    matched_name: Option<String>,
}

pub fn status(processes: &Processes) -> Result<RuntimeStatus, String> {
    let mut daemon = processes.daemon.lock().map_err(|_| "process_state_failed")?;
    if let Some(child) = daemon.as_mut() {
        if child.try_wait().map_err(|_| "process_status_failed")?.is_some() {
            *daemon = None;
        }
    }
    Ok(RuntimeStatus {
        backend_available: backend::backend_path().is_some(),
        daemon_running: daemon.is_some(),
    })
}

/// Starts the background for the session. Prefers the supervisor next to `watchd.exe`, detached
/// from this window so the daemon outlives it and restarts after failures; it is stopped through
/// `watchd stop`. Falls back to a window-owned `watchd run` when no supervisor is installed.
pub fn start_daemon(processes: &Processes) -> Result<RuntimeStatus, String> {
    let mut daemon = processes.daemon.lock().map_err(|_| "process_state_failed")?;
    let running = match daemon.as_mut() {
        Some(child) => child.try_wait().map_err(|_| "process_status_failed")?.is_none(),
        None => false,
    };
    if !running {
        // Only the installed copy's background is trusted by the login component.
        if crate::setup::other_copy_installed() { return Err("use_installed_copy".into()); }
        let backend = backend::backend_path().ok_or("backend_not_found")?;
        let supervisor = backend.with_file_name("watchd-supervisor.exe");
        if supervisor.is_file() {
            // Dropping the Child handle does not terminate the process.
            let mut command = Command::new(&supervisor);
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x08000000);
            }
            command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null())
                .spawn().map_err(|_| "daemon_start_failed")?;
            *daemon = None;
        } else {
            *daemon = Some(backend::command()?.arg("run").spawn().map_err(|_| "daemon_start_failed")?);
        }
    }
    drop(daemon);
    status(processes)
}

/// Stops the background for the whole session, whichever window, task or supervisor started it.
pub fn stop_daemon(processes: &Processes) -> Result<RuntimeStatus, String> {
    // The session stop signal makes `watchd run` exit cleanly and its supervisor not relaunch it.
    let _ = backend::command()?.arg("stop").status();
    if let Some(mut child) = processes.daemon.lock().map_err(|_| "process_state_failed")?.take() {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && matches!(child.try_wait(), Ok(None)) {
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    status(processes)
}

pub fn stop_scan(processes: &Processes) -> Result<(), String> {
    if let Some(cancel) = processes.scan.lock().map_err(|_| "process_state_failed")?.as_ref() {
        cancel.store(true, Ordering::SeqCst);
    }
    Ok(())
}

pub fn start_scan(app: AppHandle, processes: &Processes) -> Result<(), String> {
    let mut slot = processes.scan.lock().map_err(|_| "process_state_failed")?;
    if slot.is_some() { return Err("scan_already_running".into()); }
    let mut child = backend::command()?
        .args(["scan-json", "--seconds", "30"])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| "scan_start_failed")?;
    let stdout = child.stdout.take().ok_or("scan_output_unavailable")?;
    let cancel = Arc::new(AtomicBool::new(false));
    *slot = Some(cancel.clone());
    drop(slot);
    let state = processes.scan.clone();
    let app_reader = app.clone();
    let reader_cancel = cancel.clone();
    let failed = Arc::new(AtomicBool::new(false));
    let reader_failed = failed.clone();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        loop {
            let mut bytes = Vec::new();
            match reader.by_ref().take(8193).read_until(b'\n', &mut bytes) {
                Ok(0) => break,
                Ok(_) if bytes.len() <= 8192 && bytes.last() == Some(&b'\n') => {},
                _ => { reader_failed.store(true, Ordering::SeqCst); break; }
            }
            if reader_cancel.load(Ordering::SeqCst) { break; }
            let Ok(advertisement) = serde_json::from_slice::<Advertisement>(&bytes) else {
                reader_failed.store(true, Ordering::SeqCst);
                break;
            };
            if advertisement.address.len() > 32
                || advertisement.name.as_ref().is_some_and(|name| name.len() > 256)
                || !(-127..=20).contains(&advertisement.rssi)
            {
                reader_failed.store(true, Ordering::SeqCst);
                break;
            }
            let _ = app_reader.emit("advertisement", advertisement);
        }
    });
    let _ = app.emit("scan-status", "running");
    std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(35);
        let result = loop {
            if failed.load(Ordering::SeqCst) { break "failed"; }
            if cancel.load(Ordering::SeqCst) { break "stopped"; }
            if Instant::now() >= deadline { break "failed"; }
            match child.try_wait() {
                Ok(Some(exit)) => break if exit.success() { "finished" } else { "failed" },
                Ok(None) => std::thread::sleep(Duration::from_millis(50)),
                Err(_) => break "failed",
            }
        };
        cancel.store(true, Ordering::SeqCst);
        let _ = child.kill();
        let _ = child.wait();
        if let Ok(mut slot) = state.lock() { *slot = None; }
        let _ = app.emit("scan-status", result);
    });
    Ok(())
}
