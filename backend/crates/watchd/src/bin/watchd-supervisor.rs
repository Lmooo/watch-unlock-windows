#![windows_subsystem = "windows"]

//! Minimal process supervisor for the long-running user-session daemon.
//!
//! Task Scheduler or the desktop UI starts this process. The supervisor owns
//! `watchd run` and relaunches it whenever the child exits, unless the
//! session stop signal (`watchd stop`) was raised; then both exit cleanly.
//! Stopping the scheduled task still terminates the whole process tree.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::AsRawHandle;
use std::os::windows::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_ALREADY_EXISTS, HANDLE};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{CreateMutexW, GetCurrentProcessId, CREATE_NO_WINDOW};
use windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

#[path = "../config.rs"]
mod config;
#[allow(dead_code)]
#[path = "../vault.rs"]
mod vault;
#[path = "../stop.rs"]
mod stop;

const QUICK_FAILURE_BACKOFF: Duration = Duration::from_secs(10);
const NORMAL_RESTART_DELAY: Duration = Duration::from_secs(2);
const MAX_SUPERVISOR_LOG_BYTES: u64 = 1024 * 1024;

struct KillOnCloseJob(HANDLE);

impl KillOnCloseJob {
    fn create() -> windows::core::Result<Self> {
        unsafe {
            let handle = CreateJobObjectW(None, None)?;
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if let Err(error) = SetInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                (&raw const limits).cast(),
                std::mem::size_of_val(&limits) as u32,
            ) {
                let _ = CloseHandle(handle);
                return Err(error);
            }
            Ok(Self(handle))
        }
    }

    fn assign(&self, child: &std::process::Child) -> windows::core::Result<()> {
        let process = HANDLE(child.as_raw_handle());
        unsafe { AssignProcessToJobObject(self.0, process) }
    }
}

impl Drop for KillOnCloseJob {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

fn supervisor_log(message: &str) {
    let Some(dir) = config::app_dir() else { return };
    if vault::ensure_private_dir(&dir).is_err() { return; }
    let log_path = dir.join("supervisor.log");
    if !safe_log_target(&log_path) { return; }
    if std::fs::symlink_metadata(&log_path).is_ok()
        && vault::ensure_private_file(&log_path).is_err() { return; }
    if std::fs::metadata(&log_path)
        .map(|metadata| metadata.len() >= MAX_SUPERVISOR_LOG_BYTES)
        .unwrap_or(false)
    {
        let backup = dir.join("supervisor.log.previous");
        let _ = std::fs::remove_file(&backup);
        let _ = std::fs::rename(&log_path, backup);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&log_path) {
        if vault::ensure_private_file(&log_path).is_err() { return; }
        let _ = writeln!(file, "{:?} {message}", SystemTime::now());
    }
}

fn safe_log_target(path: &Path) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata.is_file()
            && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0,
        Err(error) => error.kind() == std::io::ErrorKind::NotFound,
    }
}

/// One supervisor per session: a second one (task plus UI start) would fight over `watchd run`.
/// The OS releases the mutex when this process exits.
fn single_instance() -> Option<HANDLE> {
    let mut session = 0u32;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session).ok()? };
    let name = format!("Local\\WatchUnlockWindowsSupervisor-{session}\0").encode_utf16().collect::<Vec<_>>();
    let mutex = unsafe { CreateMutexW(None, true, PCWSTR(name.as_ptr())).ok()? };
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        unsafe { let _ = CloseHandle(mutex); }
        return None;
    }
    Some(mutex)
}

fn child_path() -> Option<PathBuf> {
    let executable = std::env::current_exe().ok()?;
    let directory = executable.parent()?;
    directory.is_absolute().then(|| directory.join("watchd.exe"))
}

fn main() {
    let Some(directory) = config::app_dir() else { std::process::exit(1) };
    if vault::ensure_private_dir(&directory).is_err() { std::process::exit(1); }
    let Some(_instance) = single_instance() else {
        supervisor_log("supervisor_already_running");
        std::process::exit(0);
    };
    let Some(watchd) = child_path() else {
        supervisor_log("child_location_unavailable");
        std::process::exit(1);
    };
    let job = match KillOnCloseJob::create() {
        Ok(job) => job,
        Err(error) => {
            supervisor_log(&format!("job_creation_failed; code={}", error.code().0));
            std::process::exit(1);
        }
    };
    // Reset: a request left by a previous, still-exiting instance must not stop this one.
    let stop = match stop::StopSignal::open(true) {
        Ok(stop) => stop,
        Err(error) => {
            supervisor_log(&format!("stop_signal_unavailable; code={}", error.code().0));
            std::process::exit(1);
        }
    };
    supervisor_log("supervisor_started");

    loop {
        if stop.requested() {
            supervisor_log("stop_requested");
            std::process::exit(0);
        }
        let started_at = Instant::now();
        let mut command = Command::new(&watchd);
        command.arg("run").creation_flags(CREATE_NO_WINDOW.0)
            .stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        match command.spawn() {
            Ok(mut child) => {
                if let Err(error) = job.assign(&child) {
                    supervisor_log(&format!("job_assignment_failed; code={}", error.code().0));
                    let _ = child.kill();
                    let _ = child.wait();
                    thread::sleep(QUICK_FAILURE_BACKOFF);
                    continue;
                }
                supervisor_log("watchd_started");
                match child.wait() {
                    Ok(status) => supervisor_log(&format!("watchd_exited; code={:?}", status.code())),
                    Err(error) => supervisor_log(&format!("watchd_wait_failed; code={:?}", error.raw_os_error())),
                }
            }
            Err(error) => supervisor_log(&format!("watchd_start_failed; code={:?}", error.raw_os_error())),
        }

        let delay = if started_at.elapsed() < QUICK_FAILURE_BACKOFF {
            QUICK_FAILURE_BACKOFF
        } else {
            NORMAL_RESTART_DELAY
        };
        // Sleep in slices so a stop request during the backoff takes effect promptly.
        let resume_at = Instant::now() + delay;
        while Instant::now() < resume_at && !stop.requested() {
            thread::sleep(Duration::from_millis(100));
        }
    }
}
