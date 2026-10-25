/// Fixed destinations only: the frontend names a link, it never supplies a URL.
fn url_for(link: &str) -> Option<&'static str> {
    match link {
        "repo" => Some("https://github.com/whyy1/watch-unlock-windows"),
        "bark" => Some("https://apps.apple.com/app/id1403753865"),
        _ => None,
    }
}

#[tauri::command]
pub fn open_link(link: &str) -> Result<(), String> {
    open_url(url_for(link).ok_or("invalid_link")?)
}

#[cfg(windows)]
fn open_url(url: &str) -> Result<(), String> {
    use std::ffi::c_void;
    #[link(name = "shell32")]
    extern "system" {
        fn ShellExecuteW(window: *mut c_void, operation: *const u16, file: *const u16,
            parameters: *const u16, directory: *const u16, show: i32) -> isize;
    }
    let operation: Vec<u16> = "open\0".encode_utf16().collect();
    let url: Vec<u16> = url.encode_utf16().chain(std::iter::once(0)).collect();
    let result = unsafe { ShellExecuteW(std::ptr::null_mut(), operation.as_ptr(), url.as_ptr(),
        std::ptr::null(), std::ptr::null(), 1) };
    if result > 32 { Ok(()) } else { Err("browser_open_failed".into()) }
}

#[cfg(not(windows))]
fn open_url(_: &str) -> Result<(), String> { Err("unsupported_platform".into()) }

#[cfg(test)]
mod tests {
    use super::url_for;

    #[test]
    fn only_named_fixed_links_open() {
        assert_eq!(url_for("repo"), Some("https://github.com/whyy1/watch-unlock-windows"));
        assert_eq!(url_for("bark"), Some("https://apps.apple.com/app/id1403753865"));
        for link in ["", "license", "https://example.invalid", "repo "] {
            assert!(url_for(link).is_none());
        }
    }
}
