//! Notifications are informational; delivery or opening a URL never authorizes unlock.

use std::io::Read;

use anyhow::{ensure, Result};
use serde::Deserialize;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::GetLastError;
use windows::Win32::Networking::WinHttp::{
    WinHttpCloseHandle, WinHttpConnect, WinHttpCrackUrl, WinHttpOpen, WinHttpOpenRequest,
    WinHttpQueryHeaders, WinHttpReadData, WinHttpReceiveResponse, WinHttpSendRequest,
    WinHttpSetOption, WinHttpSetTimeouts, SECURITY_FLAG_IGNORE_CERT_CN_INVALID,
    SECURITY_FLAG_IGNORE_CERT_DATE_INVALID, SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE,
    SECURITY_FLAG_IGNORE_UNKNOWN_CA, URL_COMPONENTS, WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
    WINHTTP_FLAG_SECURE, WINHTTP_INTERNET_SCHEME_HTTPS, WINHTTP_OPTION_REDIRECT_POLICY,
    WINHTTP_OPTION_REDIRECT_POLICY_NEVER, WINHTTP_OPTION_SECURITY_FLAGS, WINHTTP_QUERY_FLAG_NUMBER,
    WINHTTP_QUERY_STATUS_CODE,
};

const MAX_RESPONSE: usize = 4096;
const MAX_CONFIG: u64 = 16 * 1024;
const TIMEOUT_MS: i32 = 10_000;

/// Why a notification did not go out. Only these fixed categories leave this module: never the
/// key, the endpoint or a system error text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    NotSaved,
    Disabled,
    InvalidEndpoint,
    InvalidKey,
    Network,
    Rejected(u16),
}

impl Failure {
    pub fn code(self) -> String {
        match self {
            Self::NotSaved => "not_saved".into(),
            Self::Disabled => "disabled".into(),
            Self::InvalidEndpoint => "invalid_endpoint".into(),
            Self::InvalidKey => "invalid_key".into(),
            Self::Network => "network".into(),
            Self::Rejected(status) => format!("rejected_{status}"),
        }
    }
}

impl std::fmt::Display for Failure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotSaved => formatter.write_str("还没有保存 Bark 设置，请先填写设备密钥并保存。"),
            Self::Disabled => formatter.write_str("通知未启用。"),
            Self::InvalidEndpoint => formatter.write_str("推送地址无效，必须是 https:// 开头的完整地址。"),
            Self::InvalidKey => formatter.write_str("保存的 Bark 设备密钥格式不对，请重新填写并保存。"),
            Self::Network => formatter.write_str("连不上 Bark 服务器。请检查网络；公司网络需要在 Windows 中设置好代理。"),
            Self::Rejected(400) => formatter.write_str("Bark 拒绝了请求（400），通常是设备密钥不对。"),
            Self::Rejected(status) => write!(formatter, "Bark 服务器返回错误（{status}），请稍后重试或检查推送地址。"),
        }
    }
}

impl std::error::Error for Failure {}

#[derive(Deserialize)]
struct NotificationConfig {
    endpoint: String,
    enabled: bool,
    #[serde(default = "default_true")]
    notify_on_unlock: bool,
}

fn default_true() -> bool { true }

fn valid_key(key: &str) -> bool {
    (8..=256).contains(&key.len())
        && key.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Host, port and path+query of a URL that passed `valid_https_url`.
struct Target { host: Vec<u16>, port: u16, object: Vec<u16>, ip: bool }

fn crack(url: &str) -> Option<Target> {
    if url.len() > 2048 || !url.to_ascii_lowercase().starts_with("https://")
        || url.chars().any(|c| c.is_control() || c.is_whitespace() || matches!(c, '\\' | '#')) {
        return None;
    }
    let authority = url[8..].split(['/', '?']).next().unwrap_or("");
    if authority.is_empty() || authority.contains(['@', '%']) { return None; }
    let wide: Vec<u16> = url.encode_utf16().collect();
    let mut parts = URL_COMPONENTS {
        dwStructSize: std::mem::size_of::<URL_COMPONENTS>() as u32,
        dwHostNameLength: u32::MAX, dwUserNameLength: u32::MAX, dwPasswordLength: u32::MAX,
        dwUrlPathLength: u32::MAX, dwExtraInfoLength: u32::MAX, ..Default::default()
    };
    unsafe { WinHttpCrackUrl(&wide, 0, &mut parts) }.ok()?;
    if parts.nScheme != WINHTTP_INTERNET_SCHEME_HTTPS || parts.dwHostNameLength == 0
        || parts.dwUserNameLength != 0 || parts.dwPasswordLength != 0 {
        return None;
    }
    // The cracked fields point into `wide`, which is still alive here.
    let slice = |pointer: windows::core::PWSTR, length: u32| -> Vec<u16> {
        if pointer.is_null() || length == 0 { return Vec::new(); }
        unsafe { std::slice::from_raw_parts(pointer.0, length as usize).to_vec() }
    };
    let mut host = slice(parts.lpszHostName, parts.dwHostNameLength);
    let ip = ip_host(&String::from_utf16_lossy(&host));
    host.push(0);
    let mut object = slice(parts.lpszUrlPath, parts.dwUrlPathLength);
    if object.is_empty() { object.push(u16::from(b'/')); }
    object.extend(slice(parts.lpszExtraInfo, parts.dwExtraInfoLength));
    object.push(0);
    Some(Target { host, port: parts.nPort, object, ip })
}

/// A server addressed by IP cannot hold a publicly trusted certificate, which is how people
/// self-host Bark. Only such hosts skip certificate checks; a host name is always verified.
fn ip_host(host: &str) -> bool {
    host.trim_start_matches('[').trim_end_matches(']').parse::<std::net::IpAddr>().is_ok()
}

fn valid_https_url(url: &str) -> bool { crack(url).is_some() }

fn load_config() -> Result<NotificationConfig, Failure> {
    let dir = crate::config::app_dir().ok_or(Failure::NotSaved)?;
    crate::vault::ensure_private_dir(&dir).map_err(|_| Failure::NotSaved)?;
    let mut bytes = Vec::new();
    std::fs::File::open(dir.join("notifications.json")).map_err(|_| Failure::NotSaved)?
        .take(MAX_CONFIG + 1).read_to_end(&mut bytes).map_err(|_| Failure::NotSaved)?;
    if bytes.len() as u64 > MAX_CONFIG { return Err(Failure::NotSaved); }
    let config: NotificationConfig = serde_json::from_slice(&bytes).map_err(|_| Failure::NotSaved)?;
    if !valid_https_url(&config.endpoint) { return Err(Failure::InvalidEndpoint); }
    Ok(config)
}

pub fn validate_https_url(value: &str) -> Result<()> {
    ensure!(valid_https_url(value), "URL must use HTTPS without user information or fragments");
    Ok(())
}

/// Bark answers HTTP 200 with `{"code":200}`; anything else is a rejection with that status.
fn check_response(status: u32, body: &[u8]) -> Result<(), Failure> {
    let code = serde_json::from_slice::<serde_json::Value>(body).ok()
        .and_then(|value| value.get("code").and_then(|code| code.as_i64()));
    match (status, code) {
        (200, Some(200)) => Ok(()),
        (200, Some(code)) => Err(Failure::Rejected(u16::try_from(code).unwrap_or(0))),
        (200, None) => Err(Failure::Rejected(200)),
        (status, _) => Err(Failure::Rejected(u16::try_from(status).unwrap_or(0))),
    }
}

/// Closes a WinHTTP handle when dropped.
struct Handle(*mut core::ffi::c_void);
impl Drop for Handle {
    fn drop(&mut self) { if !self.0.is_null() { unsafe { let _ = WinHttpCloseHandle(self.0); } } }
}

/// One HTTPS POST through WinHTTP. AUTOMATIC_PROXY follows the Windows proxy settings, which
/// curl did not, so networks that require a proxy work too. Redirects are refused.
fn post(target: &Target, payload: &[u8]) -> Result<(), Failure> {
    let network = |_| Failure::Network;
    unsafe {
        let session = Handle(WinHttpOpen(w!("WatchUnlock"), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            PCWSTR::null(), PCWSTR::null(), 0));
        if session.0.is_null() { return Err(Failure::Network); }
        WinHttpSetTimeouts(session.0, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS, TIMEOUT_MS).map_err(network)?;
        let connection = Handle(WinHttpConnect(session.0, PCWSTR(target.host.as_ptr()), target.port, 0));
        if connection.0.is_null() { return Err(Failure::Network); }
        let request = Handle(WinHttpOpenRequest(connection.0, w!("POST"), PCWSTR(target.object.as_ptr()),
            PCWSTR::null(), PCWSTR::null(), std::ptr::null(), WINHTTP_FLAG_SECURE));
        if request.0.is_null() { return Err(Failure::Network); }
        let never = WINHTTP_OPTION_REDIRECT_POLICY_NEVER.to_ne_bytes();
        WinHttpSetOption(Some(request.0), WINHTTP_OPTION_REDIRECT_POLICY, Some(&never)).map_err(network)?;
        if target.ip {
            let ignore = (SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID
                | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID | SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE).to_ne_bytes();
            WinHttpSetOption(Some(request.0), WINHTTP_OPTION_SECURITY_FLAGS, Some(&ignore)).map_err(network)?;
        }
        let headers: Vec<u16> = "Content-Type: application/json\r\n".encode_utf16().collect();
        let length = u32::try_from(payload.len()).map_err(|_| Failure::Network)?;
        if WinHttpSendRequest(request.0, Some(&headers), Some(payload.as_ptr().cast()), length, length, 0).is_err()
            || WinHttpReceiveResponse(request.0, std::ptr::null_mut()).is_err() {
            tracing::warn!("[NOTIFY] transport error {}", GetLastError().0);
            return Err(Failure::Network);
        }
        let mut status = 0u32;
        let mut size = std::mem::size_of::<u32>() as u32;
        WinHttpQueryHeaders(request.0, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, PCWSTR::null(),
            Some((&mut status as *mut u32).cast()), &mut size, std::ptr::null_mut()).map_err(network)?;
        let mut body = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let mut read = 0u32;
            WinHttpReadData(request.0, chunk.as_mut_ptr().cast(), chunk.len() as u32, &mut read).map_err(network)?;
            if read == 0 { break; }
            body.extend_from_slice(&chunk[..read as usize]);
            if body.len() > MAX_RESPONSE { return Err(Failure::Rejected(u16::try_from(status).unwrap_or(0))); }
        }
        check_response(status, &body)
    }
}

/// Sends with the saved endpoint and key. `require_enabled` is false only for the explicit test,
/// so a test works before the user turns notifications on.
fn send(title: &str, body: &str, require_enabled: bool) -> Result<(), Failure> {
    let config = load_config()?;
    if require_enabled && !config.enabled { return Err(Failure::Disabled); }
    let target = crack(&config.endpoint).ok_or(Failure::InvalidEndpoint)?;
    let dir = crate::config::app_dir().ok_or(Failure::NotSaved)?;
    let key = crate::vault::SecretBytes(crate::vault::load_secret(&dir, "bark-key.dpapi").map_err(|_| Failure::NotSaved)?);
    let key_text = std::str::from_utf8(&key.0).unwrap_or("").trim();
    if !valid_key(key_text) { return Err(Failure::InvalidKey); }
    #[derive(serde::Serialize)]
    struct Payload<'a> {
        device_key: &'a str, title: &'a str, body: &'a str, group: &'static str,
        #[serde(rename = "isArchive")]
        is_archive: &'static str,
    }
    let payload = crate::vault::SecretBytes(serde_json::to_vec(&Payload {
        device_key: key_text, title, body, group: "watch-unlock-windows", is_archive: "0",
    }).map_err(|_| Failure::InvalidKey)?);
    post(&target, &payload.0)
}

fn record_failure(failure: Failure) {
    crate::audit::record("notification_failed", None, &format!("通知未发出：{failure}（{}）", failure.code()));
}

pub fn notify_unlock_async() {
    std::thread::spawn(|| {
        if !load_config().is_ok_and(|config| config.enabled && config.notify_on_unlock) { return; }
        if let Err(failure) = send("已靠近解锁 Windows", "你回到电脑旁，手表靠近后已解锁。", true) {
            record_failure(failure);
        }
    });
}

/// Sends a test with the saved settings, whether or not notifications are switched on.
pub fn notify_test() -> Result<(), Failure> {
    let result = send("Watch Unlock 测试通知", "这是一条测试通知，不会授予任何解锁权限。", false);
    if let Err(failure) = result { record_failure(failure); }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_validation_rejects_insecure_ambiguous_and_credential_urls() {
        for url in ["http://example.test/push", "https://user@example.test", "https://user:password@example.test",
            "https://example.test/#fragment", "https://example.test\\@host", "https://example.test\r\nHeader:x", "https://"] {
            assert!(!valid_https_url(url), "unsafe URL accepted");
        }
        assert!(valid_https_url("https://example.test:8443/push"));
        assert!(valid_https_url("https://api.day.app/push"));
    }

    #[test]
    fn cracked_target_keeps_host_port_path_and_query() {
        let target = crack("https://example.test:8443/push?group=a").unwrap();
        assert_eq!(String::from_utf16_lossy(&target.host), "example.test\0");
        assert_eq!(target.port, 8443);
        assert_eq!(String::from_utf16_lossy(&target.object), "/push?group=a\0");
        let bare = crack("https://api.day.app").unwrap();
        assert_eq!(bare.port, 443);
        assert_eq!(String::from_utf16_lossy(&bare.object), "/\0");
    }

    #[test]
    fn only_ip_addressed_servers_skip_certificate_checks() {
        assert!(!target_ip("https://api.day.app/push"));
        assert!(!target_ip("https://bark.example.com:8443/push"));
        assert!(!target_ip("https://192.168.1.10.example.com/push"));
        assert!(target_ip("https://192.168.1.10:8080/push"));
        assert!(target_ip("https://[fd00::1]:8443/push"));
    }

    fn target_ip(url: &str) -> bool { crack(url).unwrap().ip }

    #[test]
    fn provider_acceptance_requires_http_and_json_success() {
        assert_eq!(check_response(200, b"{\"code\":200}"), Ok(()));
        assert_eq!(check_response(302, b"{\"code\":200}"), Err(Failure::Rejected(302)));
        assert_eq!(check_response(200, b"{\"code\":400}"), Err(Failure::Rejected(400)));
        assert_eq!(check_response(400, b"{\"code\":400}"), Err(Failure::Rejected(400)));
        assert_eq!(check_response(200, b"{}"), Err(Failure::Rejected(200)));
    }

    #[test]
    fn failure_messages_name_the_cause_without_secrets() {
        assert_eq!(Failure::Rejected(400).code(), "rejected_400");
        assert!(Failure::Network.to_string().contains("代理"));
        assert!(Failure::NotSaved.to_string().contains("保存"));
        assert!(Failure::Rejected(500).to_string().contains("500"));
    }

    #[test]
    fn key_format_rejects_urls_and_whitespace() {
        assert!(valid_key("test_key-1234"));
        assert!(!valid_key("https://example.test/key"));
        assert!(!valid_key("has space"));
    }
}
