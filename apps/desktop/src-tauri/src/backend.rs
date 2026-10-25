use std::io::{BufRead, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::mpsc;

use serde_json::Value;

use crate::request::Request;

const MAX_RESPONSE: usize = 256 * 1024;

pub fn backend_path() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("WATCH_UNLOCK_BACKEND") {
        let path = PathBuf::from(path);
        return (path.is_absolute() && path.is_file()).then_some(path);
    }
    let executable_dir = std::env::current_exe().ok()?.parent()?.to_path_buf();
    let path = executable_dir.join("watchd.exe");
    path.is_file().then_some(path)
}

pub fn command() -> Result<Command, String> {
    let path = backend_path().ok_or("backend_not_found")?;
    let mut command = Command::new(path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    command.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
    Ok(command)
}

pub fn read_line<R: Read>(reader: R, limit: usize) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    BufReader::new(reader)
        .take((limit + 1) as u64)
        .read_until(b'\n', &mut bytes)
        .map_err(|_| "backend_read_failed")?;
    if bytes.is_empty() || bytes.len() > limit || bytes.last() != Some(&b'\n') {
        return Err("backend_invalid_response".into());
    }
    Ok(bytes)
}

pub fn request(value: Value) -> Result<Value, String> {
    let request: Request = serde_json::from_value(value).map_err(|_| "invalid_request")?;
    if !request.valid() { return Err("invalid_request".into()); }
    let timeout = request.timeout();
    let mut input = serde_json::to_vec(&request).map_err(|_| "invalid_request")?;
    if input.len() > 16 * 1024 { return Err("request_too_large".into()); }
    input.push(b'\n');
    let mut child = command()?
        .arg("ui")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|_| "backend_start_failed")?;
    let mut stdin = child.stdin.take().ok_or("backend_input_unavailable")?;
    let stdout = child.stdout.take().ok_or("backend_output_unavailable")?;
    std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
        input.fill(0);
    });
    let (tx, rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || { let _ = tx.send(read_line(stdout, MAX_RESPONSE)); });
    let response = rx.recv_timeout(timeout);
    let _ = child.kill();
    let _ = child.wait();
    let bytes = response.map_err(|_| "backend_timeout")??;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| "backend_invalid_json")?;
    if !value.get("ok").is_some_and(Value::is_boolean) {
        return Err("backend_invalid_response".into());
    }
    Ok(value)
}
