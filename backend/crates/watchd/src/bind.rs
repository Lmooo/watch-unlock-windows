//! One-time binding of a Windows-paired watch's IRK, without manual key entry.
//!
//! The UI requests this through `bind_paired`, which starts this same executable elevated
//! (UAC). The elevated process reads the bonded IRK for one device under the Winlogon
//! (SYSTEM) token, reverts immediately, verifies the key against a live resolvable-private-
//! address advertisement, and stores it with CurrentUser DPAPI. Only an exit code is returned;
//! the key is never printed, logged or passed on a command line.

use std::mem::size_of;
use std::path::Path;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, ensure, Context, Result};
use serde_json::json;
use windows::core::PCWSTR;
use windows::Devices::Bluetooth::BluetoothAdapter;
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_NOT_ALL_ASSIGNED, HANDLE, HLOCAL, LUID, WAIT_OBJECT_0,
};
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, EqualSid, GetTokenInformation, LookupPrivilegeValueW,
    RevertToSelf, SecurityImpersonation, TokenElevation, TokenImpersonation, LUID_AND_ATTRIBUTES,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_DUPLICATE, TOKEN_ELEVATION, TOKEN_IMPERSONATE, TOKEN_PRIVILEGES,
    TOKEN_QUERY,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::RemoteDesktop::{ProcessIdToSessionId, WTSGetActiveConsoleSessionId};
use windows::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_BINARY,
    REG_VALUE_TYPE,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcess, OpenProcessToken, SetThreadToken,
    WaitForSingleObject, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};
use windows::Win32::UI::WindowsAndMessaging::SW_HIDE;
use windows::Win32::System::WinRT::{RoInitialize, RO_INIT_MULTITHREADED};

use crate::registry::{self, Device};

/// Process exit code for a completed binding.
const EXIT_BOUND: i32 = 0;
const SCAN_SECONDS: u64 = 30;
/// UAC approval plus the verification scan, with headroom.
const LAUNCH_TIMEOUT_MS: u32 = 180_000;

struct HandleGuard(HANDLE);
impl Drop for HandleGuard {
    fn drop(&mut self) { if !self.0.is_invalid() { unsafe { let _ = CloseHandle(self.0); } } }
}

struct KeyGuard(HKEY);
impl Drop for KeyGuard {
    fn drop(&mut self) { unsafe { let _ = RegCloseKey(self.0); } }
}

/// Scope in which the calling thread runs as the Winlogon (SYSTEM) token. Dropping reverts.
struct SystemScope {
    // Held only so the impersonation handle closes after RevertToSelf runs in Drop.
    _token: HandleGuard,
}

impl SystemScope {
    fn enter() -> Result<Self> {
        enable_debug_privilege()?;
        let session = unsafe { WTSGetActiveConsoleSessionId() };
        ensure!(session != u32::MAX, "No active console session");
        let pid = winlogon_pid(session)?;
        let process = HandleGuard(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)? });
        let mut primary = HANDLE::default();
        unsafe { OpenProcessToken(process.0, TOKEN_DUPLICATE | TOKEN_QUERY, &mut primary)? };
        let primary = HandleGuard(primary);
        let mut impersonation = HANDLE::default();
        unsafe {
            DuplicateTokenEx(primary.0, TOKEN_IMPERSONATE | TOKEN_QUERY, None,
                SecurityImpersonation, TokenImpersonation, &mut impersonation)?;
        }
        let token = HandleGuard(impersonation);
        unsafe { SetThreadToken(None, token.0)? };
        Ok(Self { _token: token })
    }
}

impl Drop for SystemScope {
    fn drop(&mut self) {
        // Revert before the token handle is closed by its guard.
        unsafe { let _ = RevertToSelf(); }
    }
}

fn enable_debug_privilege() -> Result<()> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut token)? };
    let token = HandleGuard(token);
    let mut luid = LUID::default();
    unsafe { LookupPrivilegeValueW(PCWSTR::null(), SE_DEBUG_NAME, &mut luid)? };
    let privileges = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }],
    };
    unsafe { AdjustTokenPrivileges(token.0, false, Some(&privileges), 0, None, None)? };
    // AdjustTokenPrivileges can report success while granting nothing.
    ensure!(unsafe { GetLastError() } != ERROR_NOT_ALL_ASSIGNED, "SeDebugPrivilege unavailable");
    Ok(())
}

fn winlogon_pid(session: u32) -> Result<u32> {
    let snapshot = HandleGuard(unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)? });
    let mut entry = PROCESSENTRY32W { dwSize: size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
    unsafe { Process32FirstW(snapshot.0, &mut entry)? };
    loop {
        let length = entry.szExeFile.iter().position(|&c| c == 0).unwrap_or(entry.szExeFile.len());
        let name = String::from_utf16_lossy(&entry.szExeFile[..length]);
        if name.eq_ignore_ascii_case("winlogon.exe") {
            let mut found = 0u32;
            if unsafe { ProcessIdToSessionId(entry.th32ProcessID, &mut found) }.is_ok() && found == session {
                return Ok(entry.th32ProcessID);
            }
        }
        if unsafe { Process32NextW(snapshot.0, &mut entry) }.is_err() { break; }
    }
    bail!("Winlogon for the active session was not found")
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Reads exactly one 16-byte REG_BINARY value. Runs only inside a `SystemScope`.
fn read_irk_value(key_path: &str) -> Result<[u8; 16]> {
    let path = wide(key_path);
    let mut key = HKEY::default();
    unsafe { RegOpenKeyExW(HKEY_LOCAL_MACHINE, PCWSTR(path.as_ptr()), 0, KEY_READ, &mut key).ok()? };
    let key = KeyGuard(key);
    let name = wide("IRK");
    let mut kind = REG_VALUE_TYPE(0);
    let mut length = 0u32;
    unsafe { RegQueryValueExW(key.0, PCWSTR(name.as_ptr()), None, Some(&mut kind), None, Some(&mut length)).ok()? };
    ensure!(kind == REG_BINARY && length == 16, "Bonded key has an unexpected shape");
    let mut value = [0u8; 16];
    let mut read = 16u32;
    unsafe {
        RegQueryValueExW(key.0, PCWSTR(name.as_ptr()), None, Some(&mut kind),
            Some(value.as_mut_ptr()), Some(&mut read)).ok()?;
    }
    ensure!(kind == REG_BINARY && read == 16, "Bonded key has an unexpected shape");
    Ok(value)
}

/// Local adapter address in the BTHPORT key layout (12 lowercase hex digits, no separators).
fn local_adapter_key() -> Result<String> {
    // Already-initialized apartments return an error that is safe to ignore.
    unsafe { let _ = RoInitialize(RO_INIT_MULTITHREADED); }
    let adapter = BluetoothAdapter::GetDefaultAsync()?.get()?;
    Ok(format!("{:012x}", adapter.BluetoothAddress()?))
}

/// Reads the IRK for one identity address. The thread is SYSTEM only for the registry read.
fn read_bonded_irk(address: &str) -> Result<[u8; 16]> {
    let adapter = local_adapter_key()?;
    let remote = address.replace(':', "").to_ascii_lowercase();
    let key = format!(r"SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Keys\{adapter}\{remote}");
    let _scope = SystemScope::enter()?;
    read_irk_value(&key)
}

/// Windows and BlueZ disagree on IRK byte order, so both orders are candidates.
fn key_orders(irk: [u8; 16]) -> [[u8; 16]; 2] {
    let mut reversed = irk;
    reversed.reverse();
    [irk, reversed]
}

/// Index of the first candidate that resolves `address` as this watch's private address.
fn matching_order(candidates: &[[u8; 16]; 2], address: &str) -> Option<usize> {
    candidates.iter().position(|candidate| crate::irk::is_my_watch(candidate, address))
}

/// Returns the key ordering that resolves a live advertisement, or `None` within the window.
fn verify_identity(irk: [u8; 16]) -> Result<Option<[u8; 16]>> {
    let candidates = key_orders(irk);
    let matched: Arc<Mutex<Option<usize>>> = Arc::new(Mutex::new(None));
    let sink = Arc::clone(&matched);
    crate::ble::scan(move |advertisement| {
        let Ok(mut slot) = sink.lock() else { return };
        if slot.is_none() {
            *slot = matching_order(&candidates, &advertisement.address_string());
        }
    }, Some(SCAN_SECONDS))?;
    let index = *matched.lock().map_err(|_| anyhow!("Verification state unavailable"))?;
    Ok(index.map(|index| candidates[index]))
}

/// The elevated token must belong to the same account that owns the application data.
/// DPAPI CurrentUser keys are per account, so a different administrator account would store
/// a secret the normal application can never decrypt.
fn data_dir_owned_by_current_user(dir: &Path) -> Result<bool> {
    let path = wide(&dir.to_string_lossy());
    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        GetNamedSecurityInfoW(PCWSTR(path.as_ptr()), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION,
            Some(&mut owner), None, None, None, &mut descriptor).ok()?;
    }
    let _free = scopeguard_free(descriptor);
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)? };
    let token = HandleGuard(token);
    let user = crate::enroll::token_user_buffer(token.0).context("Token user unavailable")?;
    let user = unsafe { &*(user.as_ptr().cast::<windows::Win32::Security::TOKEN_USER>()) };
    Ok(unsafe { EqualSid(owner, user.User.Sid) }.is_ok())
}

struct LocalFreeGuard(PSECURITY_DESCRIPTOR);
fn scopeguard_free(descriptor: PSECURITY_DESCRIPTOR) -> LocalFreeGuard { LocalFreeGuard(descriptor) }
impl Drop for LocalFreeGuard {
    fn drop(&mut self) {
        if !self.0 .0.is_null() { unsafe { let _ = LocalFree(HLOCAL(self.0 .0)); } }
    }
}

fn is_elevated() -> Result<bool> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)? };
    let token = HandleGuard(token);
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    unsafe {
        GetTokenInformation(token.0, TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32, &mut returned)?;
    }
    Ok(elevation.TokenIsElevated != 0)
}

fn valid_name(name: &str) -> bool {
    let trimmed = name.trim();
    !trimmed.is_empty() && trimmed.chars().count() <= 64
        && !trimmed.chars().any(|c| c.is_control() || c == '"')
}

/// Elevated entry point. Requires a matching advertisement; saves nothing otherwise.
pub fn run(address: &str, name: &str) -> Result<()> {
    ensure!(registry::valid_address(address), "Invalid device address");
    ensure!(valid_name(name), "Invalid device name");
    ensure!(is_elevated()?, "Administrator approval is required");
    let dir = registry::data_dir()?;
    ensure!(dir.exists(), "Start the application once before binding");
    ensure!(data_dir_owned_by_current_user(&dir)?, "Elevated account does not own the application data");

    let devices = registry::load_devices()?;
    ensure!(!devices.iter().any(|d| d.address.as_deref() == Some(address)), "Device is already bound");
    ensure!(devices.len() < 16, "Too many devices");

    let mut irk = read_bonded_irk(address)?;
    let verified = verify_identity(irk);
    crate::vault::erase(&mut irk);
    let mut key = verified?.ok_or_else(|| anyhow!("No live advertisement matched within the window"))?;
    let outcome = store_identity(&dir, devices, address, name, &key);
    crate::vault::erase(&mut key);
    let id = outcome?;
    println!("{}", json!({"status":"bound","device_id":id}));
    Ok(())
}

/// Saves the verified key as a DPAPI secret and the public metadata. Rolls back on failure.
fn store_identity(dir: &Path, devices: Vec<Device>, address: &str, name: &str, key: &[u8; 16]) -> Result<String> {
    let id = registry::random_hex(16)?;
    let device = Device { id: id.clone(), name: name.trim().into(), adapter: "apple-ble".into(),
        near_rssi: -60, far_rssi: -75, auto_unlock_on_return: true, enabled: true,
        address: Some(address.into()), return_window_seconds: registry::default_return_window() };
    device.validate()?;
    let secret = format!("device-{id}.dpapi");
    crate::vault::save_secret(dir, &secret, key)?;
    let next = devices.into_iter().chain(Some(device)).collect::<Vec<_>>();
    if let Err(error) = registry::save_devices(&next) {
        let _ = crate::vault::delete_secret(dir, &secret);
        return Err(error);
    }
    crate::audit::record("device_saved", Some(&id), "已从 Windows 配对的手表绑定身份（一次性提权读取）");
    Ok(id)
}

/// Starts `watchd bind-paired` elevated and waits for its exit. Called from the UI request path.
pub fn launch(address: &str, name: &str) -> Result<serde_json::Value> {
    ensure!(registry::valid_address(address), "Invalid device address");
    ensure!(valid_name(name), "Invalid device name");
    let exe = std::env::current_exe()?;
    let exe_wide = wide(&exe.to_string_lossy());
    let parameters = wide(&format!("bind-paired --address {address} --name \"{}\"", name.trim()));
    let verb = wide("runas");
    let mut info = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(exe_wide.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: SW_HIDE.0 as i32,
        ..Default::default()
    };
    unsafe { ShellExecuteExW(&mut info)? };
    let process = HandleGuard(info.hProcess);
    ensure!(!process.0.is_invalid(), "Elevation was cancelled or unavailable");
    // Bounded wait: an unanswered UAC prompt must not block the UI request forever.
    let waited = unsafe { WaitForSingleObject(process.0, LAUNCH_TIMEOUT_MS) };
    ensure!(waited == WAIT_OBJECT_0, "Binding timed out or was cancelled");
    let mut code = 1u32;
    unsafe { GetExitCodeProcess(process.0, &mut code)? };
    ensure!(code as i32 == EXIT_BOUND, "Binding did not complete");
    Ok(json!({"status":"bound"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a resolvable private address for `irk` with a fixed prand, exactly as a watch would.
    fn rpa_for(irk: &[u8; 16]) -> String {
        let prand = [0x52u8, 0x34, 0x56];
        let hash = crate::irk::ah(irk, &[prand[0], prand[1], prand[2]]);
        format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            prand[0], prand[1], prand[2], hash[0], hash[1], hash[2])
    }

    #[test]
    fn matches_the_key_in_its_original_order() {
        let irk: [u8; 16] = core::array::from_fn(|i| i as u8 + 1);
        let address = rpa_for(&irk);
        assert_eq!(matching_order(&key_orders(irk), &address), Some(0));
    }

    #[test]
    fn selects_the_reversed_order_when_windows_stored_it_that_way() {
        let irk: [u8; 16] = core::array::from_fn(|i| i as u8 + 1);
        let mut stored = irk;
        stored.reverse();
        let address = rpa_for(&irk);
        let candidates = key_orders(stored);
        assert_eq!(matching_order(&candidates, &address), Some(1));
        assert_eq!(candidates[1], irk);
    }

    #[test]
    fn unrelated_addresses_match_neither_order() {
        let irk: [u8; 16] = core::array::from_fn(|i| i as u8 + 1);
        let other: [u8; 16] = core::array::from_fn(|i| 0xA0 ^ i as u8);
        assert_eq!(matching_order(&key_orders(irk), &rpa_for(&other)), None);
    }

    #[test]
    fn name_rules_reject_blank_control_quote_and_overlong_values() {
        assert!(valid_name("Living room watch"));
        assert!(!valid_name("   "));
        assert!(!valid_name("bad\"quote"));
        assert!(!valid_name("bad\nline"));
        assert!(!valid_name(&"x".repeat(65)));
    }
}
