//! Resolve application data through the Windows known-folder API.

use std::path::PathBuf;
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{SHGetKnownFolderPath, FOLDERID_LocalAppData, KF_FLAG_DEFAULT};

const DIRECTORY_NAME: &str = "WatchUnlockWindows";

/// Current-user application data. Release builds never trust an environment path.
/// The caller must apply the vault's private ACL before creating or opening files.
pub fn app_dir() -> Option<PathBuf> {
    #[cfg(any(test, debug_assertions))]
    if let Some(value) = std::env::var_os("WATCH_UNLOCK_DIR") {
        return isolated_directory(&value);
    }
    unsafe {
        let allocated = SHGetKnownFolderPath(&FOLDERID_LocalAppData, KF_FLAG_DEFAULT, None).ok()?;
        let value = allocated.to_string();
        CoTaskMemFree(Some(allocated.0.cast()));
        let base = PathBuf::from(value.ok()?);
        base.is_absolute().then(|| base.join(DIRECTORY_NAME))
    }
}

#[cfg(any(test, debug_assertions))]
fn isolated_directory(value: &std::ffi::OsStr) -> Option<PathBuf> {
    let path = PathBuf::from(value);
    let valid_name = path.file_name().is_some_and(|name| {
        name.to_str().is_some_and(|name| name.eq_ignore_ascii_case(DIRECTORY_NAME))
    });
    let no_parent = !path.components().any(|component| component == std::path::Component::ParentDir);
    (path.is_absolute() && valid_name && no_parent).then_some(path)
}

#[cfg(test)]
mod tests {
    use super::isolated_directory;
    use std::ffi::OsStr;

    #[test]
    fn override_requires_an_absolute_dedicated_directory() {
        for invalid in ["", "WatchUnlockWindows", "C:WatchUnlockWindows", "C:\\", "C:\\Windows",
            "C:\\isolated\\..\\WatchUnlockWindows", "C:\\isolated\\WatchUnlockWindows\\other"] {
            assert!(isolated_directory(OsStr::new(invalid)).is_none());
        }
        assert!(isolated_directory(OsStr::new("C:\\isolated\\WatchUnlockWindows")).is_some());
    }
}
