use std::io::Write;

use serde::{Deserialize, Serialize};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};

use windows::Win32::Security::{
    LogonUserW, LOGON32_LOGON_INTERACTIVE, LOGON32_LOGON_NETWORK, LOGON32_PROVIDER_DEFAULT,
};
use windows::Win32::Security::{
    EqualSid, GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::System::Console::{
    GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, STD_INPUT_HANDLE,
};



pub(crate) fn clear_secret(value: &mut String) {
    let ptr = value.as_mut_ptr();
    for index in 0..value.len() {
        unsafe { std::ptr::write_volatile(ptr.add(index), 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    value.clear();
}

pub(crate) fn clear_bytes(value: &mut Vec<u8>) {
    for byte in value.iter_mut() {
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    value.clear();
}

const MSA_DOMAIN: &str = "MicrosoftAccount";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasswordFailure {
    Wrong,
    LogonTypeDenied,
    AccountRestricted,
    PasswordExpired,
    PasswordMustChange,
    LockedOut,
    Other,
}

fn password_failure(code: u32) -> PasswordFailure {
    match code {
        1326 => PasswordFailure::Wrong,
        1327 => PasswordFailure::AccountRestricted,
        1330 => PasswordFailure::PasswordExpired,
        1385 => PasswordFailure::LogonTypeDenied,
        1314 => PasswordFailure::LogonTypeDenied,
        1907 => PasswordFailure::PasswordMustChange,
        1909 => PasswordFailure::LockedOut,
        _ => PasswordFailure::Other,
    }
}

fn failure_code(error: &windows::core::Error) -> u32 {
    (error.code().0 as u32) & 0xFFFF
}

fn matching_identity(password: &str) -> Result<(String, String), PasswordFailure> {
    // The session supplies its SID-filtered MicrosoftAccount identity first.
    // Stop after success instead of trying this password against other aliases.
    first_matching_identity(crate::session::identity_candidates(),
        |username, domain| validate_password(username, domain, password))
}

fn first_matching_identity(
    candidates: Vec<(String, String)>,
    mut validate: impl FnMut(&str, &str) -> Result<(), PasswordFailure>,
) -> Result<(String, String), PasswordFailure> {
    let mut last = PasswordFailure::Wrong;
    for (username, domain) in candidates {
        match validate(&username, &domain) {
            Ok(()) => return Ok((username, domain)),
            Err(failure) => last = failure,
        }
    }
    Err(last)
}

#[derive(Serialize, Deserialize)]
pub struct StoredCredential {
    version: u8,
    pub username: String,
    pub domain: String,
    pub password: String,
}

fn read_password(prompt: &str) -> anyhow::Result<String> {
    print!("{prompt}");
    let _ = std::io::stdout().flush();
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE)?;
        let mut mode = Default::default();
        GetConsoleMode(h, &mut mode)?;
        SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT)?;
        let mut line = String::new();
        let read = std::io::stdin().read_line(&mut line);
        let _ = SetConsoleMode(h, mode);
        println!();
        if let Err(error) = read {
            clear_secret(&mut line);
            return Err(error.into());
        }
        let length = line.trim_end_matches(['\r', '\n']).len();
        line.truncate(length);
        Ok(line)
    }
}

/// 用提交时完全相同的身份校验密码。
///
/// 微软账户必须用 UPN 邮箱 + NULL 域 + 交互式登录，让 LSA 走 CloudAP 的在线校验；
/// `LOGON32_LOGON_NETWORK` 只会校验本地缓存/SAM，微软账户密码必然失败。
fn validate_password(username: &str, domain: &str, password: &str) -> Result<(), PasswordFailure> {
    let msa = domain.eq_ignore_ascii_case(MSA_DOMAIN);
    let wu: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
    let wd: Vec<u16> = domain.encode_utf16().chain(std::iter::once(0)).collect();
    let mut wp: Vec<u16> = password.encode_utf16().chain(std::iter::once(0)).collect();
    let mut token = HANDLE::default();
    let result = unsafe {
        LogonUserW(
            PCWSTR(wu.as_ptr()),
            if msa { PCWSTR::null() } else { PCWSTR(wd.as_ptr()) },
            PCWSTR(wp.as_ptr()),
            if msa { LOGON32_LOGON_INTERACTIVE } else { LOGON32_LOGON_NETWORK },
            LOGON32_PROVIDER_DEFAULT,
            &mut token,
        )
    };
    for unit in &mut wp {
        std::ptr::write_volatile(unit, 0);
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    // LogonCache can contain another user's MSA. Valid credentials alone
    // do not prove this is the interactive user being enrolled.
    let outcome = match result {
        Err(error) => Err(password_failure(failure_code(&error))),
        Ok(()) if token_is_current_user(token) => Ok(()),
        Ok(()) => Err(PasswordFailure::Wrong),
    };
    if !token.is_invalid() {
        let _ = unsafe { CloseHandle(token) };
    }
    outcome
}

pub(crate) fn token_user_buffer(token: HANDLE) -> Option<Vec<usize>> {
    let mut required = 0u32;
    unsafe {
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut required);
        if required == 0 {
            return None;
        }
        // usize alignment is sufficient for TOKEN_USER and its trailing SID.
        let mut buffer = vec![0usize; (required as usize + std::mem::size_of::<usize>() - 1)
            / std::mem::size_of::<usize>()];
        GetTokenInformation(token, TokenUser, Some(buffer.as_mut_ptr().cast()), required, &mut required)
            .ok()?;
        Some(buffer)
    }
}

fn token_is_current_user(candidate: HANDLE) -> bool {
    unsafe {
        let mut current = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut current).is_err() {
            return false;
        }
        let candidate_user = token_user_buffer(candidate);
        let current_user = token_user_buffer(current);
        let _ = CloseHandle(current);
        match (candidate_user, current_user) {
            (Some(candidate), Some(current)) => {
                let candidate = &*(candidate.as_ptr().cast::<TOKEN_USER>());
                let current = &*(current.as_ptr().cast::<TOKEN_USER>());
                EqualSid(candidate.User.Sid, current.User.Sid).is_ok()
            }
            _ => false,
        }
    }
}

impl Drop for StoredCredential {
    fn drop(&mut self) { clear_secret(&mut self.password); }
}

fn save_credential(record: &StoredCredential) -> anyhow::Result<std::path::PathBuf> {
    let clear = crate::vault::SecretBytes(serde_json::to_vec(record)?);
    let dir = crate::config::app_dir().ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA unavailable"))?;
    crate::vault::save_secret(&dir, "cred.blob", &clear.0)?;
    Ok(dir.join("cred.blob"))
}

/// Only unit tests can inject fake credentials. Release and development binaries cannot.
pub fn load_credential() -> Option<StoredCredential> {
    #[cfg(test)]
    if let Ok(password) = std::env::var("WATCH_UNLOCK_TEST_PASSWORD") {
        return Some(StoredCredential {
            version: 1, username: "TestUser".into(), domain: "TestDomain".into(), password,
        });
    }
    let dir = crate::config::app_dir()?;
    let clear = crate::vault::SecretBytes(crate::vault::load_secret(&dir, "cred.blob").ok()?);
    let record = serde_json::from_slice::<StoredCredential>(&clear.0).ok()?;
    (record.version == 1).then_some(record)
}

const WRONG_PASSWORD: &str = "密码不对：Windows 没有接受这个密码。请填写当前 Windows 账户的登录密码（微软账户就填微软账户密码），不是 PIN 码，注意大小写。";
const LOGON_TYPE_DENIED: &str = "Windows 安全策略不允许使用该登录类型校验密码。请让管理员检查“拒绝从网络/本地登录”策略，或改用本地账户。";
const ACCOUNT_LOCKED: &str = "账户已被临时锁定。请等待 10 分钟后再试，不要继续尝试。";
const ACCOUNT_RESTRICTED: &str = "Windows 限制了这个账户的登录方式（例如登录时段或工作站限制），无法校验密码。";
const PASSWORD_EXPIRED: &str = "这个 Windows 账户的密码已过期，请先在 Windows 中更改密码。";
const PASSWORD_MUST_CHANGE: &str = "这个 Windows 账户要求先更改密码，请先在 Windows 中更改后再回来保存。";

fn shown(failure: PasswordFailure) -> &'static str {
    match failure {
        PasswordFailure::Wrong | PasswordFailure::Other => WRONG_PASSWORD,
        PasswordFailure::LogonTypeDenied => LOGON_TYPE_DENIED,
        PasswordFailure::AccountRestricted => ACCOUNT_RESTRICTED,
        PasswordFailure::PasswordExpired => PASSWORD_EXPIRED,
        PasswordFailure::PasswordMustChange => PASSWORD_MUST_CHANGE,
        PasswordFailure::LockedOut => ACCOUNT_LOCKED,
    }
}

/// Validate against Windows and require the returned token to have the current user's SID.
pub fn enroll_password(password: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!password.is_empty() && password.encode_utf16().count() <= 512
        && !password.contains('\0'), "Invalid Windows account password format");
    let (username, domain) = matching_identity(password)
        .map_err(|failure| crate::bridge::Shown(shown(failure)))?;
    let record = StoredCredential { version: 1, username, domain, password: password.to_owned() };
    save_credential(&record)?;
    Ok(())
}

pub fn clear_credential() -> anyhow::Result<()> {
    let dir = crate::config::app_dir().ok_or_else(|| anyhow::anyhow!("LOCALAPPDATA unavailable"))?;
    crate::vault::delete_secret(&dir, "cred.blob")
}

pub fn credential_configured() -> bool {
    load_credential().is_some()
}
/// CLI enrollment; no password is accepted through command-line arguments or environment.
pub fn enroll() -> anyhow::Result<()> {
    let mut first = read_password("Windows account password: ")?;
    let second_result = read_password("Confirm password: ");
    let result = match second_result {
        Ok(mut second) => {
            let matches = first == second;
            clear_secret(&mut second);
            if matches { enroll_password(&first) } else { Err(anyhow::anyhow!("Passwords do not match")) }
        },
        Err(error) => Err(error),
    };
    clear_secret(&mut first);
    result?;
    println!("Account credential saved with CurrentUser DPAPI");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{first_matching_identity, password_failure, shown, PasswordFailure};

    #[test]
    fn successful_current_identity_stops_before_another_password_attempt() {
        let candidates = vec![("current@example.test".into(), "MicrosoftAccount".into()),
            ("local-alias".into(), "DESKTOP".into())];
        let result = first_matching_identity(candidates, |username, domain| {
            assert_eq!(username, "current@example.test");
            assert_eq!(domain, "MicrosoftAccount");
            Ok(())
        });
        assert_eq!(result, Ok(("current@example.test".into(), "MicrosoftAccount".into())));
    }

    #[test]
    fn rejected_stale_alias_allows_the_next_current_user_candidate() {
        let candidates = vec![("stale@example.test".into(), "MicrosoftAccount".into()),
            ("current-local".into(), "DESKTOP".into())];
        let result = first_matching_identity(candidates, |username, _| {
            if username == "current-local" { Ok(()) } else { Err(PasswordFailure::Wrong) }
        });
        assert_eq!(result, Ok(("current-local".into(), "DESKTOP".into())));
        assert_eq!(first_matching_identity(Vec::new(), |_, _| panic!("no candidate to validate")),
            Err(PasswordFailure::Wrong));
    }

    #[test]
    fn win32_logon_errors_map_to_fixed_messages() {
        assert_eq!(password_failure(1326), PasswordFailure::Wrong);
        assert_eq!(password_failure(1327), PasswordFailure::AccountRestricted);
        assert_eq!(password_failure(1330), PasswordFailure::PasswordExpired);
        assert_eq!(password_failure(1385), PasswordFailure::LogonTypeDenied);
        assert_eq!(password_failure(1314), PasswordFailure::LogonTypeDenied);
        assert_eq!(password_failure(1907), PasswordFailure::PasswordMustChange);
        assert_eq!(password_failure(1909), PasswordFailure::LockedOut);
        assert_eq!(password_failure(0), PasswordFailure::Other);
        assert!(shown(PasswordFailure::LogonTypeDenied).contains("策略"));
        assert!(shown(PasswordFailure::LockedOut).contains("10 分钟"));
        assert!(shown(PasswordFailure::Wrong).contains("不是 PIN"));
    }
}
