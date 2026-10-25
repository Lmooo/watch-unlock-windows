//! Isolated negative integration coverage of the production peer verifier.
//! No Windows account credentials, installed pipe, registration, or unlock is used.

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_GENERIC_READ, FILE_GENERIC_WRITE,
    FILE_SHARE_MODE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, SECURITY_IDENTIFICATION,
    SECURITY_SQOS_PRESENT,
};
use windows::Win32::System::Pipes::{
    CreateNamedPipeW, PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE,
};
use windows::Win32::Security::Cryptography::{BCryptGenRandom, BCRYPT_USE_SYSTEM_PREFERRED_RNG};

struct OwnedHandle(HANDLE);
impl Drop for OwnedHandle {
    fn drop(&mut self) { unsafe { let _ = CloseHandle(self.0); } }
}

#[test]
fn production_verifier_rejects_a_same_user_mock_daemon() {
    let mut random = [0u8; 16];
    unsafe { BCryptGenRandom(None, &mut random, BCRYPT_USE_SYSTEM_PREFERRED_RNG).ok().unwrap(); }
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    let name: Vec<u16> = format!("\\\\.\\pipe\\WatchUnlockWindows-Untrusted-Test-{suffix}")
        .encode_utf16().chain(Some(0)).collect();
    let server = OwnedHandle(unsafe {
        CreateNamedPipeW(PCWSTR(name.as_ptr()), PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1, 4096, 4096, 0, None)
    });
    assert!(!server.0.is_invalid(), "isolated mock endpoint must be created");
    let client = OwnedHandle(unsafe {
        CreateFileW(PCWSTR(name.as_ptr()), FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_MODE(0), None, OPEN_EXISTING,
            SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION, None).unwrap()
    });
    assert!(!watch_unlock_provider::is_trusted_daemon_pipe(client.0),
        "matching a pipe protocol or session cannot authenticate an uninstalled mock executable");
}
