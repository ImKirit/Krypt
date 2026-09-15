//! Copying secrets: kept out of the Windows clipboard history and the cloud clipboard, and
//! removed again after a while unless something else was copied in the meantime.

use std::time::Duration;

#[cfg(windows)]
pub fn copy_secret(text: &str, clear_after: Duration) -> Result<(), String> {
    use clipboard_win::{Clipboard, options::NoClear, raw};

    // Formats Windows checks before it records clipboard content anywhere.
    const PRIVATE_FORMATS: [&str; 3] = [
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
        "CanUploadToCloudClipboard",
    ];

    {
        let _open = Clipboard::new_attempts(10).map_err(|e| e.to_string())?;
        raw::empty().map_err(|e| e.to_string())?;
        raw::set_string_with(text, NoClear).map_err(|e| e.to_string())?;
        for name in PRIVATE_FORMATS {
            if let Some(format) = raw::register_format(name) {
                raw::set_without_clear(format.get(), &0u32.to_le_bytes())
                    .map_err(|e| e.to_string())?;
            }
        }
    }
    // Read after closing: Windows adds synthesized formats on close, which counts as a change.
    let sequence = raw::seq_num();

    std::thread::spawn(move || {
        std::thread::sleep(clear_after);
        if let Ok(_open) = Clipboard::new_attempts(10) {
            // Only clear what we put there; a later copy by the user stays.
            if raw::seq_num() == sequence {
                let _ = raw::empty();
            }
        }
    });
    Ok(())
}

#[cfg(not(windows))]
pub fn copy_secret(_text: &str, _clear_after: Duration) -> Result<(), String> {
    Err("copying is only implemented on Windows so far".into())
}

#[cfg(all(test, windows))]
mod tests {
    use clipboard_win::{get_clipboard_string, set_clipboard_string};

    use super::*;

    /// Uses the real clipboard of whoever runs it, so it only runs on request:
    /// `cargo test -p krypt -- --ignored`
    #[test]
    #[ignore]
    fn clears_its_own_copy_and_leaves_a_later_one_alone() {
        let empty = || {
            get_clipboard_string()
                .map(|text| text.is_empty())
                .unwrap_or(true)
        };

        copy_secret("krypt clipboard test", Duration::from_secs(1)).unwrap();
        assert_eq!(get_clipboard_string().unwrap(), "krypt clipboard test");
        std::thread::sleep(Duration::from_millis(2500));
        assert!(empty(), "the copy was not cleared");

        copy_secret("krypt clipboard test", Duration::from_secs(1)).unwrap();
        set_clipboard_string("copied by someone else").unwrap();
        std::thread::sleep(Duration::from_millis(2500));
        assert_eq!(get_clipboard_string().unwrap(), "copied by someone else");
        set_clipboard_string("").unwrap();
    }
}
