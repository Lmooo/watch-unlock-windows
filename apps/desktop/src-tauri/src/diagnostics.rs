//! "Export diagnostics": one text file in Downloads that a user can send for support, shown
//! selected in File Explorer. "Copy diagnostics" gives a short version for a chat message.
//! The backend part holds no secrets; see watchd's diagnostics.rs.

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::json;
use tauri::{AppHandle, Manager};

/// Events kept in the copied summary; enough to cover the last pairing or unlock attempt.
const BRIEF_EVENTS: usize = 30;

#[tauri::command]
pub async fn export_diagnostics(app: AppHandle) -> Result<String, String> {
    let version = app.package_info().version.to_string();
    let downloads = app.path().download_dir().map_err(|_| "downloads_unavailable")?;
    tauri::async_runtime::spawn_blocking(move || export(&version, &downloads))
        .await
        .map_err(|_| "diagnostics_task_failed")?
}

#[tauri::command]
pub async fn diagnostics_summary(app: AppHandle) -> Result<String, String> {
    let version = app.package_info().version.to_string();
    tauri::async_runtime::spawn_blocking(move || brief(&compose(&version).1))
        .await
        .map_err(|_| "diagnostics_task_failed".into())
}

fn export(version: &str, downloads: &Path) -> Result<String, String> {
    let (stamp, text) = compose(version);
    let path = target(downloads, &stamp);
    // A BOM keeps Chinese readable in editors that would otherwise guess a legacy code page.
    let mut bytes = "\u{feff}".as_bytes().to_vec();
    bytes.extend_from_slice(text.replace('\n', "\r\n").as_bytes());
    std::fs::write(&path, bytes).map_err(|_| "diagnostics_write_failed")?;
    reveal(&path);
    Ok(path.to_string_lossy().into_owned())
}

/// The full report and the stamp for its file name.
fn compose(version: &str) -> (String, String) {
    let (stamp, body) = match crate::backend::request(json!({"op":"diagnostics"})) {
        Ok(response) if response["ok"] == true => (
            response["data"]["stamp"].as_str().filter(|s| valid_stamp(s)).map(str::to_owned),
            response["data"]["text"].as_str().unwrap_or_default().to_owned(),
        ),
        // Both the request errors and the backend's error text are fixed strings.
        Ok(response) => (None, format!("\n后台诊断不可用：{}\n", response["error"].as_str().unwrap_or("未知错误"))),
        Err(code) => (None, format!("\n后台诊断不可用：{code}\n")),
    };
    let stamp = stamp.unwrap_or_else(fallback_stamp);
    let text = format!("Watch Unlock 诊断信息\n本文件不含密码、密钥、电脑名和设备名；设备按顺序记为「设备 1」「设备 2」。\n\n== 应用 ==\n版本：{version}\n{}{body}",
        crate::setup::report_lines());
    (stamp, text)
}

/// Drops the supervisor log and all but the last events, which is what makes the full report long.
fn brief(text: &str) -> String {
    let text = text.split("\n== 后台守护日志").next().unwrap_or(text);
    let Some(start) = text.find("\n== 最近事件") else { return text.trim_end().to_owned() };
    let (head, events) = text.split_at(start);
    let events: Vec<&str> = events.lines().skip(2).filter(|line| !line.trim().is_empty()).collect();
    let kept = &events[events.len().saturating_sub(BRIEF_EVENTS)..];
    format!("{}\n\n== 最近 {} 条事件（共 {} 条；完整内容请在「解锁记录」导出诊断信息） ==\n{}",
        head.trim_end(), kept.len(), events.len(), kept.join("\n"))
}

fn valid_stamp(stamp: &str) -> bool {
    stamp.len() == 15 && stamp.bytes().enumerate().all(|(i, b)| if i == 8 { b == b'-' } else { b.is_ascii_digit() })
}

fn fallback_stamp() -> String {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_secs()).to_string()
}

/// Never overwrites an earlier export made within the same second.
fn target(downloads: &Path, stamp: &str) -> PathBuf {
    let base = format!("WatchUnlock-诊断-{stamp}");
    let mut path = downloads.join(format!("{base}.txt"));
    let mut n = 2;
    while path.exists() {
        path = downloads.join(format!("{base}-{n}.txt"));
        n += 1;
    }
    path
}

/// Opens File Explorer with the file selected; explorer.exe wants `/select,"path"` verbatim.
fn reveal(path: &Path) {
    let root = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    let mut command = Command::new(root.join("explorer.exe"));
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.raw_arg(format!("/select,\"{}\"", path.display()));
    }
    let _ = command.spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_from_the_backend_must_be_plain_dates() {
        assert!(valid_stamp("20261026-172223"));
        assert!(!valid_stamp("2026102617222"));
        assert!(!valid_stamp("..\\..\\x-172223"));
    }

    #[test]
    fn summary_keeps_status_and_only_recent_events() {
        let events: String = (1..=40).map(|n| format!("2026-10-26 10:00:{n:02}  e{n}  —  x\n")).collect();
        let text = format!("头\n\n== 蓝牙 ==\n外设模式：是\n\n== 最近事件（最多 500 条，按时间顺序） ==\n{events}\n== 后台守护日志（最后 200 行） ==\nsupervisor_started\n");
        let summary = brief(&text);
        assert!(summary.contains("外设模式：是"));
        assert!(summary.contains("最近 30 条事件（共 40 条"));
        assert!(summary.contains("  e40  ") && summary.contains("  e11  ") && !summary.contains("  e10  "));
        assert!(!summary.contains("supervisor_started") && !summary.contains("最多 500 条"));
    }

    #[test]
    fn repeated_exports_get_new_names() {
        let dir = std::env::temp_dir().join(format!("wu-diag-{}", fallback_stamp()));
        std::fs::create_dir_all(&dir).unwrap();
        let first = target(&dir, "20261026-172223");
        std::fs::write(&first, b"x").unwrap();
        let second = target(&dir, "20261026-172223");
        assert_ne!(first, second);
        assert!(second.to_string_lossy().ends_with("-2.txt"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
