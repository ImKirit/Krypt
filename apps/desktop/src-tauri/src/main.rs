// No extra console window next to the app in release builds.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(not(debug_assertions))]
    strip_webview_overrides();
    krypt_desktop::run();
}

/// WebView2 reads `WEBVIEW2_*` variables that can open a remote debugging port or load a
/// different browser runtime. A user never needs them, so release builds drop them before
/// the web view starts. Debug builds keep them for the test driver.
#[cfg(not(debug_assertions))]
fn strip_webview_overrides() {
    let names: Vec<std::ffi::OsString> = std::env::vars_os()
        .map(|(name, _)| name)
        .filter(|name| {
            name.to_str()
                .is_some_and(|name| name.to_ascii_uppercase().starts_with("WEBVIEW2_"))
        })
        .collect();
    for name in names {
        // SAFETY: this is the first thing main does; no other thread exists yet.
        unsafe { std::env::remove_var(name) };
    }
}
