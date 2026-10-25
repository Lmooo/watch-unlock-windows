//! Session-local stop signal shared by the daemon, its supervisor and `watchd stop`.
//!
//! A manual-reset named event in the caller's `Local\` namespace, so only processes in the same
//! logon session can reach it. Signalling it asks a running daemon to exit cleanly and tells the
//! supervisor not to relaunch it. The event disappears once no process holds a handle, so a stop
//! request never outlives the daemon it was meant for.

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows::Win32::System::Threading::{
    CreateEventW, GetCurrentProcessId, OpenEventW, ResetEvent, SetEvent, WaitForSingleObject,
    EVENT_MODIFY_STATE,
};

fn event_name() -> windows::core::Result<Vec<u16>> {
    let mut session = 0u32;
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session)? };
    Ok(format!("Local\\WatchUnlockWindowsStop-{session}\0").encode_utf16().collect())
}

pub struct StopSignal(HANDLE);

impl StopSignal {
    /// Opens or creates the event. `reset` clears a request left by a process that is still exiting.
    pub fn open(reset: bool) -> windows::core::Result<Self> {
        let name = event_name()?;
        let handle = unsafe { CreateEventW(None, true, false, PCWSTR(name.as_ptr()))? };
        let signal = Self(handle);
        if reset { unsafe { ResetEvent(signal.0)? }; }
        Ok(signal)
    }

    pub fn requested(&self) -> bool {
        unsafe { WaitForSingleObject(self.0, 0) == WAIT_OBJECT_0 }
    }
}

impl Drop for StopSignal {
    fn drop(&mut self) { unsafe { let _ = CloseHandle(self.0); } }
}

/// Asks the running daemon to stop. Returns `false` when no daemon or supervisor is listening.
#[allow(dead_code)] // The supervisor shares this module but only listens.
pub fn request() -> windows::core::Result<bool> {
    let name = event_name()?;
    let Ok(handle) = (unsafe { OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(name.as_ptr())) }) else {
        return Ok(false);
    };
    let result = unsafe { SetEvent(handle) };
    unsafe { let _ = CloseHandle(handle); }
    result.map(|()| true)
}
