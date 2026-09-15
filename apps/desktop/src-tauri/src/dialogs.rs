//! Native file dialogs. They are opened from Rust and hand back only the chosen path, so the
//! web view never gets access to the file system.

use std::path::PathBuf;

use tauri::{AppHandle, WebviewWindow};
use tauri_plugin_dialog::DialogExt;

/// Blocks until the user picks a place. Never call it on the main thread.
pub fn save_path(
    app: &AppHandle,
    window: &WebviewWindow,
    title: &str,
    file_name: &str,
) -> Option<PathBuf> {
    // Test runs of debug builds cannot click through a native dialog.
    #[cfg(debug_assertions)]
    {
        if let Some(path) = std::env::var_os("KRYPT_TEST_SAVE_PATH") {
            return Some(PathBuf::from(path));
        }
    }
    app.dialog()
        .file()
        .set_parent(window)
        .set_title(title)
        .set_file_name(file_name)
        .add_filter("JSON", &["json"])
        .blocking_save_file()
        .and_then(|path| path.into_path().ok())
}

/// Blocks until the user picks a file. Never call it on the main thread.
pub fn open_path(app: &AppHandle, window: &WebviewWindow, title: &str) -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    {
        if let Some(path) = std::env::var_os("KRYPT_TEST_OPEN_PATH") {
            return Some(PathBuf::from(path));
        }
    }
    app.dialog()
        .file()
        .set_parent(window)
        .set_title(title)
        .add_filter("CSV, JSON, XML", &["csv", "json", "xml"])
        .add_filter("*", &["*"])
        .blocking_pick_file()
        .and_then(|path| path.into_path().ok())
}
