//! CurrentUser encryption protects storage, not a compromised Windows user session.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{bail, ensure, Context, Result};
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, BOOL, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows::Win32::Security::Cryptography::{
    BCryptGenRandom, CryptProtectData, CryptUnprotectData, BCRYPT_USE_SYSTEM_PREFERRED_RNG,
    CRYPT_INTEGER_BLOB,
};
use windows::Win32::Security::{
    GetSecurityDescriptorDacl, GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, PSID,
    DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SECURITY_ATTRIBUTES,
    TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, MoveFileExW, FILE_ATTRIBUTE_REPARSE_POINT, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

const MAX_BLOB: u64 = 1024 * 1024;
const UI_FORBIDDEN: u32 = 1;

pub struct SecretBytes(pub Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) { erase(&mut self.0); }
}

pub fn erase(value: &mut [u8]) {
    for byte in value { unsafe { std::ptr::write_volatile(byte, 0); } }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

fn wide(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

fn valid_name(name: &str) -> bool {
    let base = name.split('.').next().unwrap_or("").to_ascii_uppercase();
    let reserved = matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || (base.len() == 4 && (base.starts_with("COM") || base.starts_with("LPT"))
            && matches!(base.as_bytes()[3], b'1'..=b'9'));
    !reserved && !name.is_empty() && name.len() <= 96 && !name.starts_with('.')
        && !name.ends_with('.') && !name.contains("..")
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn reject_reparse(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) => ensure!(meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0,
                "Secret storage cannot use reparse points"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {},
            Err(error) => return Err(error).context("Cannot inspect secret storage"),
        }
    }
    Ok(())
}

fn private_descriptor() -> Result<PSECURITY_DESCRIPTOR> {
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)?;
        let mut size = 0;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);
        let mut buffer = vec![0usize; (size as usize + 7) / std::mem::size_of::<usize>()];
        let result = GetTokenInformation(token, TokenUser, Some(buffer.as_mut_ptr().cast()),
            size, &mut size);
        let _ = CloseHandle(token);
        result?;
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut sid = PWSTR::null();
        ConvertSidToStringSidW(user.User.Sid, &mut sid)?;
        let sid_text = sid.to_string();
        let _ = LocalFree(HLOCAL(sid.0.cast()));
        let sddl: Vec<u16> = format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{})", sid_text?)
            .encode_utf16().chain(Some(0)).collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(sddl.as_ptr()),
            SDDL_REVISION_1, &mut descriptor, None)?;
        Ok(descriptor)
    }
}

fn apply_private_acl(path: &Path, descriptor: PSECURITY_DESCRIPTOR) -> Result<()> {
    unsafe {
        let mut present = BOOL::default();
        let mut defaulted = BOOL::default();
        let mut dacl = std::ptr::null_mut();
        GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)?;
        ensure!(present.as_bool() && !dacl.is_null(), "Private DACL is unavailable");
        let name = wide(path);
        SetNamedSecurityInfoW(PCWSTR(name.as_ptr()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            PSID::default(), PSID::default(), Some(dacl), None).ok()?;
    }
    Ok(())
}

pub fn ensure_private_dir(dir: &Path) -> Result<()> {
    ensure!(dir.is_absolute(), "Secret directory must be absolute");
    reject_reparse(dir)?;
    if let Some(parent) = dir.parent() { fs::create_dir_all(parent)?; }
    let descriptor = private_descriptor()?;
    let result = (|| {
        let name = wide(dir);
        let attrs = SECURITY_ATTRIBUTES { nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0, bInheritHandle: false.into() };
        let created = unsafe { CreateDirectoryW(PCWSTR(name.as_ptr()), Some(&attrs)) };
        if created.is_err() && !dir.is_dir() { bail!("Cannot create private directory"); }
        reject_reparse(dir)?;
        apply_private_acl(dir, descriptor)
    })();
    unsafe { let _ = LocalFree(HLOCAL(descriptor.0)); }
    result
}

/// Restrict an existing regular file without following reparse points.
pub fn ensure_private_file(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "Private file path must be absolute");
    reject_reparse(path)?;
    ensure!(fs::symlink_metadata(path)?.is_file(), "Private path must be a regular file");
    let descriptor = private_descriptor()?;
    let result = apply_private_acl(path, descriptor);
    unsafe { let _ = LocalFree(HLOCAL(descriptor.0)); }
    result
}

/// Bound allocation even if a file grows between metadata inspection and reading.
pub fn read_limited_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    reject_reparse(path)?;
    let file = OpenOptions::new().read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0).open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file() && metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT.0 == 0,
        "Private storage must be a regular file");
    ensure!(metadata.len() <= maximum, "Private file is too large");
    let mut bytes = Vec::new();
    file.take(maximum.saturating_add(1)).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "Private file is too large");
    Ok(bytes)
}

pub fn protect(data: &[u8]) -> Result<Vec<u8>> {
    ensure!(!data.is_empty() && data.len() as u64 <= MAX_BLOB / 2, "Invalid secret size");
    let input = CRYPT_INTEGER_BLOB { cbData: data.len() as u32, pbData: data.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptProtectData(&input, PCWSTR::null(), None, None, None, UI_FORBIDDEN, &mut output)
            .map_err(|_| anyhow::anyhow!("CurrentUser secret encryption failed"))?;
        let bytes = std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec();
        let _ = LocalFree(HLOCAL(output.pbData.cast()));
        Ok(bytes)
    }
}

pub fn unprotect(blob: &[u8]) -> Result<Vec<u8>> {
    ensure!(!blob.is_empty() && blob.len() as u64 <= MAX_BLOB, "Invalid protected secret size");
    let input = CRYPT_INTEGER_BLOB { cbData: blob.len() as u32, pbData: blob.as_ptr() as *mut u8 };
    let mut output = CRYPT_INTEGER_BLOB::default();
    unsafe {
        CryptUnprotectData(&input, None, None, None, None, UI_FORBIDDEN, &mut output)
            .map_err(|_| anyhow::anyhow!("CurrentUser secret decryption failed"))?;
        if output.cbData == 0 || output.pbData.is_null() {
            let _ = LocalFree(HLOCAL(output.pbData.cast()));
            bail!("Empty protected secret rejected");
        }
        let source = std::slice::from_raw_parts_mut(output.pbData, output.cbData as usize);
        let bytes = source.to_vec();
        erase(source);
        let _ = LocalFree(HLOCAL(output.pbData.cast()));
        Ok(bytes)
    }
}

fn secret_path(dir: &Path, name: &str) -> Result<PathBuf> {
    ensure!(valid_name(name), "Invalid secret filename");
    ensure_private_dir(dir)?;
    let path = dir.join(name);
    reject_reparse(&path)?;
    Ok(path)
}

pub fn save_secret(dir: &Path, name: &str, data: &[u8]) -> Result<()> {
    let path = secret_path(dir, name)?;
    let encrypted = protect(data)?;
    let mut random = [0u8; 16];
    unsafe { BCryptGenRandom(None, &mut random, BCRYPT_USE_SYSTEM_PREFERRED_RNG).ok()?; }
    let temporary = dir.join(format!("vault-{}.tmp", hex::encode(random)));
    let result = (|| {
        let mut file = OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        file.write_all(&encrypted)?;
        file.sync_all()?;
        drop(file);
        let from = wide(&temporary);
        let to = wide(&path);
        unsafe { MoveFileExW(PCWSTR(from.as_ptr()), PCWSTR(to.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)?; }
        Ok(())
    })();
    if result.is_err() { let _ = fs::remove_file(&temporary); }
    result
}

pub fn load_secret(dir: &Path, name: &str) -> Result<Vec<u8>> {
    let path = secret_path(dir, name)?;
    ensure_private_file(&path)?;
    let blob = read_limited_file(&path, MAX_BLOB)?;
    unprotect(&blob)
}

pub fn delete_secret(dir: &Path, name: &str) -> Result<()> {
    let path = secret_path(dir, name)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("Cannot delete protected secret"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_traversal_reserved_and_stream_names() {
        for name in ["", ".", "..", "../cred.blob", "a/irk", "a\\irk", "a:stream", "NUL", "COM1.dpapi", ".hidden", "a..b"] {
            assert!(!valid_name(name), "invalid filename accepted");
        }
        assert!(valid_name("device-test.irk.dpapi"));
    }

    #[test]
    fn fake_secret_roundtrip_replace_and_delete() {
        let mut random = [0u8; 16];
        unsafe { BCryptGenRandom(None, &mut random, BCRYPT_USE_SYSTEM_PREFERRED_RNG).ok().unwrap(); }
        let dir = std::env::temp_dir().join(format!("watch-unlock-vault-test-{}", hex::encode(random)));
        save_secret(&dir, "test.dpapi", b"fake-test-secret").unwrap();
        assert_eq!(load_secret(&dir, "test.dpapi").unwrap(), b"fake-test-secret");
        save_secret(&dir, "test.dpapi", b"replacement-test-secret").unwrap();
        assert_eq!(load_secret(&dir, "test.dpapi").unwrap(), b"replacement-test-secret");
        delete_secret(&dir, "test.dpapi").unwrap();
        assert!(load_secret(&dir, "test.dpapi").is_err());
        fs::remove_dir(&dir).unwrap();
    }

    #[test]
    fn bounded_files_accept_exact_limit_and_reject_oversize() {
        let mut random = [0u8; 16];
        unsafe { BCryptGenRandom(None, &mut random, BCRYPT_USE_SYSTEM_PREFERRED_RNG).ok().unwrap(); }
        let path = std::env::temp_dir().join(format!("watch-unlock-read-test-{}", hex::encode(random)));
        fs::write(&path, b"fixture").unwrap();
        assert_eq!(read_limited_file(&path, 7).unwrap(), b"fixture");
        assert!(read_limited_file(&path, 6).is_err());
        fs::remove_file(path).unwrap();
    }
}
