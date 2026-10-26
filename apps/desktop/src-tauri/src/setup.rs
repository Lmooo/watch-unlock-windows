//! Install state shown in the window, and the per-user Run entry that starts the background at
//! logon. Installation itself is done by the setup.exe produced by `tauri build`.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Serialize;

/// Per-user autostart; needs no administrator rights. The installer writes it once.
const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "WatchUnlockWindows";
/// Earlier script-based installs started the background from this scheduled task.
const LEGACY_TASK: &str = "WatchUnlockWindows";
const PROVIDER_KEY: &str = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{A8CA66E1-5FCA-45DD-8D79-44FC9701B739}";

#[derive(Serialize)]
pub struct SetupStatus {
    /// This window runs from an installed copy, the only one whose background can unlock.
    running_installed: bool,
    /// The Credential Provider is registered, so the lock screen can be unlocked.
    provider_registered: bool,
    autostart: bool,
}

fn system_tool(name: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    root.join("System32").join(name)
}

fn hidden(mut command: Command) -> Command {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    command
}

fn run(tool: &str, args: &[&str]) -> bool {
    let mut command = Command::new(system_tool(tool));
    command.args(args);
    hidden(command).status().is_ok_and(|status| status.success())
}

fn current_dir() -> Option<PathBuf> {
    std::env::current_exe().ok()?.parent().map(Path::to_path_buf)
}

/// The installer puts the window, the background and the login component together under
/// Program Files; the login component only trusts a background found there.
pub fn running_installed() -> bool {
    let Some(dir) = current_dir() else { return false };
    let Some(root) = std::env::var_os("ProgramW6432").or_else(|| std::env::var_os("ProgramFiles")) else { return false };
    let inside = match (dir.canonicalize(), PathBuf::from(root).canonicalize()) {
        (Ok(dir), Ok(root)) => dir.starts_with(&root) && dir != root,
        _ => false,
    };
    inside && dir.join("watch_unlock_provider.dll").is_file() && dir.join("watchd-supervisor.exe").is_file()
}

/// True when this is a stray copy on a machine that has an installation: a background started
/// from here would replace the installed one with a copy the login component does not trust.
pub fn other_copy_installed() -> bool {
    std::env::var_os("WATCH_UNLOCK_BACKEND").is_none() && !running_installed() && run("reg.exe", &["query", PROVIDER_KEY])
}

fn autostart_enabled() -> bool {
    run("reg.exe", &["query", RUN_KEY, "/v", RUN_VALUE]) || run("schtasks.exe", &["/Query", "/TN", LEGACY_TASK])
}

fn current_status() -> SetupStatus {
    let running_installed = running_installed();
    SetupStatus {
        running_installed,
        provider_registered: run("reg.exe", &["query", PROVIDER_KEY]),
        autostart: running_installed && autostart_enabled(),
    }
}

/// The install facts for the diagnostics file, one "name：value" line each.
pub fn report_lines() -> String {
    let status = current_status();
    let yes = |value: bool| if value { "是" } else { "否" };
    format!("从安装目录运行：{}\n登录组件已注册：{}\n开机自启：{}\n",
        yes(status.running_installed), yes(status.provider_registered), yes(status.autostart))
}

/// Async so the reg.exe and schtasks.exe queries never block the window's main thread.
#[tauri::command]
pub async fn setup_status() -> Result<SetupStatus, String> {
    tauri::async_runtime::spawn_blocking(current_status).await.map_err(|_| "setup_task_failed".into())
}

#[tauri::command]
pub async fn set_autostart(enabled: bool) -> Result<SetupStatus, String> {
    tauri::async_runtime::spawn_blocking(move || {
        if !running_installed() { return Err("not_installed".into()); }
        let supervisor = current_dir().ok_or("not_installed")?.join("watchd-supervisor.exe");
        // Either way the legacy task goes, so it can neither duplicate nor override this switch.
        if run("schtasks.exe", &["/Query", "/TN", LEGACY_TASK]) {
            let _ = run("schtasks.exe", &["/Delete", "/TN", LEGACY_TASK, "/F"]);
        }
        let quoted = format!("\"{}\"", supervisor.display());
        let changed = if enabled {
            run("reg.exe", &["add", RUN_KEY, "/v", RUN_VALUE, "/t", "REG_SZ", "/d", &quoted, "/f"])
        } else {
            !run("reg.exe", &["query", RUN_KEY, "/v", RUN_VALUE])
                || run("reg.exe", &["delete", RUN_KEY, "/v", RUN_VALUE, "/f"])
        };
        if !changed { return Err("autostart_failed".into()); }
        Ok(current_status())
    }).await.map_err(|_| "setup_task_failed")?
}

