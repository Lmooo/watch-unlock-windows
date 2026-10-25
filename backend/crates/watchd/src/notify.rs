//! Notifications are informational; delivery or opening a URL never authorizes unlock.

use std::io::{Read, Write};
use std::os::windows::process::CommandExt;
use std::process::{Command, Stdio};

use anyhow::{ensure, Result};
use serde::Deserialize;
use windows::Win32::Networking::WinHttp::{
    WinHttpCrackUrl, URL_COMPONENTS, WINHTTP_INTERNET_SCHEME_HTTPS,
};
use windows::Win32::System::SystemInformation::GetSystemDirectoryW;
use windows::Win32::System::Threading::CREATE_NO_WINDOW;

const MAX_RESPONSE: usize = 4096;
const MAX_CONFIG: u64 = 16 * 1024;

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

fn valid_https_url(url: &str) -> bool {
    if url.len() > 2048 || !url.to_ascii_lowercase().starts_with("https://")
        || url.chars().any(|c| c.is_control() || c.is_whitespace() || matches!(c, '\\' | '#')) {
        return false;
    }
    let authority = url[8..].split(['/', '?']).next().unwrap_or("");
    if authority.is_empty() || authority.contains(['@', '%']) { return false; }
    let wide: Vec<u16> = url.encode_utf16().collect();
    let mut parts = URL_COMPONENTS {
        dwStructSize: std::mem::size_of::<URL_COMPONENTS>() as u32,
        dwHostNameLength: u32::MAX, dwUserNameLength: u32::MAX,
        dwPasswordLength: u32::MAX, ..Default::default()
    };
    unsafe { WinHttpCrackUrl(&wide, 0, &mut parts) }.is_ok()
        && parts.nScheme == WINHTTP_INTERNET_SCHEME_HTTPS && parts.dwHostNameLength > 0
        && parts.dwUserNameLength == 0 && parts.dwPasswordLength == 0
}

fn load_config() -> Result<NotificationConfig> {
    let dir = crate::config::app_dir().ok_or_else(|| anyhow::anyhow!("Notification configuration unavailable"))?;
    crate::vault::ensure_private_dir(&dir)?;
    let mut bytes = Vec::new();
    std::fs::File::open(dir.join("notifications.json"))?
        .take(MAX_CONFIG + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_CONFIG, "Notification configuration is too large");
    let config: NotificationConfig = serde_json::from_slice(&bytes)
        .map_err(|_| anyhow::anyhow!("Invalid notification configuration"))?;
    ensure!(valid_https_url(&config.endpoint), "Notification endpoint must use HTTPS without user information");
    Ok(config)
}

pub fn validate_https_url(value: &str) -> Result<()> {
    ensure!(valid_https_url(value), "URL must use HTTPS without user information or fragments");
    Ok(())
}

pub fn system_curl() -> Result<std::path::PathBuf> {
    let mut buffer = [0u16; 32768];
    let length = unsafe { GetSystemDirectoryW(Some(&mut buffer)) } as usize;
    ensure!(length > 0 && length < buffer.len(), "System directory is unavailable");
    Ok(std::path::PathBuf::from(String::from_utf16(&buffer[..length])?).join("curl.exe"))
}

fn accepted_response(response: &[u8]) -> bool {
    let Some(split) = response.iter().rposition(|b| *b == b'\n') else { return false; };
    if response.get(split + 1..) != Some(b"200") { return false; }
    serde_json::from_slice::<serde_json::Value>(&response[..split]).ok()
        .and_then(|value| value.get("code").and_then(|code| code.as_i64())) == Some(200)
}

pub fn send_notification(title: &str, body: &str) -> Result<()> {
    ensure!(title.len() <= 512 && body.len() <= 4096, "Notification content is too large");
    let config = load_config()?;
    ensure!(config.enabled, "Notifications are disabled");
    let dir = crate::config::app_dir().ok_or_else(|| anyhow::anyhow!("Notification configuration unavailable"))?;
    let key = crate::vault::SecretBytes(crate::vault::load_secret(&dir, "bark-key.dpapi")?);
    let key_text = std::str::from_utf8(&key.0).unwrap_or("").trim();
    ensure!(valid_key(key_text), "Invalid notification device key");
    #[derive(serde::Serialize)]
    struct Payload<'a> {
        device_key: &'a str, title: &'a str, body: &'a str, group: &'static str,
        #[serde(rename = "isArchive")]
        is_archive: &'static str,
    }
    let payload = crate::vault::SecretBytes(serde_json::to_vec(&Payload {
        device_key: key_text, title, body, group: "watch-unlock-windows", is_archive: "0",
    })?);
    let mut child = Command::new(system_curl()?)
        .args(["--disable", "--silent", "--show-error", "--globoff", "--proto", "=https",
            "--proto-redir", "=https", "--max-redirs", "0", "--connect-timeout", "5",
            "--max-time", "10", "--max-filesize", "4096", "--request", "POST",
            "--header", "Content-Type: application/json", "--data-binary", "@-",
            "--write-out", "\n%{http_code}", "--url", &config.endpoint])
        .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW.0).spawn()
        .map_err(|_| anyhow::anyhow!("Notification transport failed"))?;
    let sent = child.stdin.take().ok_or_else(|| anyhow::anyhow!("Notification transport failed"))
        .and_then(|mut input| input.write_all(&payload.0).map_err(|_| anyhow::anyhow!("Notification transport failed")));
    if sent.is_err() { let _ = child.kill(); let _ = child.wait(); return sent; }
    let mut response = Vec::new();
    let read = child.stdout.take().ok_or_else(|| anyhow::anyhow!("Notification transport failed"))
        .and_then(|output| output.take((MAX_RESPONSE + 1) as u64).read_to_end(&mut response)
            .map_err(|_| anyhow::anyhow!("Notification response failed")));
    if read.is_err() || response.len() > MAX_RESPONSE {
        let _ = child.kill(); let _ = child.wait();
        anyhow::bail!("Notification response rejected");
    }
    let status = child.wait().map_err(|_| anyhow::anyhow!("Notification transport failed"))?;
    ensure!(status.success() && accepted_response(&response), "Notification provider rejected the request");
    Ok(())
}

pub fn notify_unlock_async() {
    std::thread::spawn(|| {
        if !load_config().is_ok_and(|config| config.enabled && config.notify_on_unlock) { return; }
        let result = send_notification("已靠近解锁 Windows", "你回到电脑旁，手表靠近后已解锁。");
        match result {
            Ok(()) => tracing::info!("[NOTIFY] Notification accepted by provider"),
            Err(_) => tracing::warn!("[NOTIFY] Notification unavailable or rejected; details redacted"),
        }
    });
}

pub fn notify_test() -> Result<()> {
    send_notification("Watch Unlock 测试通知", "这是一条测试通知，不会授予任何解锁权限。")
        .map_err(|_| anyhow::anyhow!("Notification test unavailable or rejected; details redacted"))
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
    fn provider_acceptance_requires_http_and_json_success() {
        assert!(accepted_response(b"{\"code\":200}\n200"));
        assert!(!accepted_response(b"{\"code\":200}\n302"));
        assert!(!accepted_response(b"{\"code\":400}\n200"));
        assert!(!accepted_response(b"{}\n200"));
    }

    #[test]
    fn key_format_rejects_urls_and_whitespace() {
        assert!(valid_key("test_key-1234"));
        assert!(!valid_key("https://example.test/key"));
        assert!(!valid_key("has space"));
    }
}
