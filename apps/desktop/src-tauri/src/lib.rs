//! Krypt desktop app: the Tauri shell around `krypt-store`.
//!
//! The window never holds keys. It asks for lists without secrets, and for a single secret
//! only when the user reveals or copies it; copying happens here, not in the web view.

mod backend;
mod clipboard;
mod dialogs;
mod error;
mod session;
mod settings;

use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::thread;
use std::time::{Duration, Instant, SystemTime};

use krypt_core::crypto::KdfParams;
use krypt_core::generator::GeneratorOptions;
use krypt_core::model::{Item, ItemType, Service};
use serde_json::Value;
use tauri::{AppHandle, Emitter, Manager, State, WebviewWindow};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::backend::{
    Backend, GeneratedPassword, ImportPreview, ImportResult, ItemSummary, ServiceSummary, Status,
    TotpNow,
};
use crate::error::{AppError, AppResult};
use crate::settings::Settings;

type AppState = Mutex<Backend>;

fn backend<'a>(state: &'a State<'_, AppState>) -> MutexGuard<'a, Backend> {
    state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[tauri::command]
fn status(state: State<'_, AppState>) -> Status {
    backend(&state).status()
}

#[tauri::command]
async fn create_vault(state: State<'_, AppState>, password: String) -> AppResult<String> {
    let password = Zeroizing::new(password);
    backend(&state)
        .create_vault(&password)
        .map(|shown| shown.to_string())
}

#[tauri::command]
async fn unlock(state: State<'_, AppState>, password: String) -> AppResult<()> {
    let password = Zeroizing::new(password);
    backend(&state).unlock(&password)
}

#[tauri::command]
async fn recover(
    state: State<'_, AppState>,
    recovery_key: String,
    new_password: String,
) -> AppResult<()> {
    let recovery_key = Zeroizing::new(recovery_key);
    let new_password = Zeroizing::new(new_password);
    backend(&state).recover(&recovery_key, &new_password)
}

#[tauri::command]
fn lock(state: State<'_, AppState>) {
    backend(&state).lock();
}

#[tauri::command]
fn touch(state: State<'_, AppState>) {
    backend(&state).touch();
}

#[tauri::command]
async fn change_password(
    state: State<'_, AppState>,
    current: String,
    new_password: String,
) -> AppResult<()> {
    let current = Zeroizing::new(current);
    let new_password = Zeroizing::new(new_password);
    backend(&state).change_password(&current, &new_password)
}

#[tauri::command]
fn new_recovery_key(state: State<'_, AppState>) -> AppResult<String> {
    backend(&state)
        .new_recovery_key()
        .map(|shown| shown.to_string())
}

#[tauri::command]
fn list_services(state: State<'_, AppState>) -> AppResult<Vec<ServiceSummary>> {
    backend(&state).services()
}

#[tauri::command]
fn get_service(state: State<'_, AppState>, id: Uuid) -> AppResult<Service> {
    backend(&state).service(id)
}

#[tauri::command]
fn list_items(state: State<'_, AppState>) -> AppResult<Vec<ItemSummary>> {
    backend(&state).items()
}

#[tauri::command]
fn list_trash(state: State<'_, AppState>) -> AppResult<Vec<ItemSummary>> {
    backend(&state).trash()
}

#[tauri::command]
fn get_item(state: State<'_, AppState>, id: Uuid) -> AppResult<Value> {
    backend(&state).item_view(id)
}

#[tauri::command]
fn get_item_for_edit(state: State<'_, AppState>, id: Uuid) -> AppResult<Item> {
    backend(&state).item_for_edit(id)
}

#[tauri::command]
fn empty_item(item_type: ItemType) -> Item {
    Backend::empty_item(item_type)
}

#[tauri::command]
fn empty_service(name: String) -> Service {
    Backend::empty_service(&name)
}

#[tauri::command]
fn save_item(state: State<'_, AppState>, item: Item) -> AppResult<Uuid> {
    backend(&state).save_item(item)
}

#[tauri::command]
fn save_service(state: State<'_, AppState>, service: Service) -> AppResult<Uuid> {
    backend(&state).save_service(service)
}

#[tauri::command]
fn trash_item(state: State<'_, AppState>, id: Uuid) -> AppResult<()> {
    backend(&state).trash_item(id)
}

#[tauri::command]
fn restore_item(state: State<'_, AppState>, id: Uuid) -> AppResult<()> {
    backend(&state).restore_item(id)
}

#[tauri::command]
fn purge_item(state: State<'_, AppState>, id: Uuid) -> AppResult<()> {
    backend(&state).purge_item(id)
}

#[tauri::command]
fn empty_trash(state: State<'_, AppState>) -> AppResult<usize> {
    backend(&state).empty_trash()
}

#[tauri::command]
fn trash_service(state: State<'_, AppState>, id: Uuid) -> AppResult<()> {
    backend(&state).trash_service(id)
}

#[tauri::command]
fn reveal_field(state: State<'_, AppState>, id: Uuid, pointer: String) -> AppResult<String> {
    backend(&state)
        .field(id, &pointer)
        .map(|value| value.to_string())
}

/// Returns the seconds until the clipboard is cleared.
#[tauri::command]
fn copy_field(state: State<'_, AppState>, id: Uuid, pointer: String) -> AppResult<u64> {
    let (value, clear_after) = {
        let mut backend = backend(&state);
        (
            backend.field(id, &pointer)?,
            backend.clipboard_clear_after(),
        )
    };
    copy(&value, clear_after)
}

/// For text the window already shows, like the recovery key right after setup.
#[tauri::command]
fn copy_text(state: State<'_, AppState>, text: String) -> AppResult<u64> {
    let text = Zeroizing::new(text);
    let clear_after = backend(&state).clipboard_clear_after();
    copy(&text, clear_after)
}

#[tauri::command]
fn totp_now(state: State<'_, AppState>, id: Uuid) -> AppResult<TotpNow> {
    backend(&state).totp_now(id)
}

#[tauri::command]
fn save_settings(state: State<'_, AppState>, settings: Settings) -> AppResult<Settings> {
    backend(&state).save_settings(settings)
}

#[tauri::command]
fn generate_password(options: GeneratorOptions) -> AppResult<GeneratedPassword> {
    Backend::generate(&options)
}

/// Asks where to save, then writes the encrypted export. Resolves to the file name, or to
/// null when the dialog was cancelled.
#[tauri::command]
async fn export_vault(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    password: String,
    title: String,
) -> AppResult<Option<String>> {
    let password = Zeroizing::new(password);
    backend(&state).check_export(&password)?;
    let suggested = format!("krypt-export-{}.json", backend::today());
    let Some(path) = dialogs::save_path(&app, &window, &title, &suggested) else {
        return Ok(None);
    };
    backend(&state).export_to(&path, &password)?;
    Ok(Some(
        path.file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default(),
    ))
}

/// Asks for a file and prepares its import. Resolves to null when the dialog was cancelled.
#[tauri::command]
async fn import_pick(
    app: AppHandle,
    window: WebviewWindow,
    state: State<'_, AppState>,
    title: String,
) -> AppResult<Option<ImportPreview>> {
    backend(&state).ensure_unlocked()?;
    let Some(path) = dialogs::open_path(&app, &window, &title) else {
        return Ok(None);
    };
    backend(&state).import_open(path).map(Some)
}

#[tauri::command]
async fn import_unlock(state: State<'_, AppState>, password: String) -> AppResult<ImportPreview> {
    let password = Zeroizing::new(password);
    backend(&state).import_unlock(&password)
}

#[tauri::command]
async fn import_commit(state: State<'_, AppState>, delete_source: bool) -> AppResult<ImportResult> {
    backend(&state).import_commit(delete_source)
}

#[tauri::command]
fn import_cancel(state: State<'_, AppState>) {
    backend(&state).import_cancel();
}

fn copy(text: &str, clear_after: Duration) -> AppResult<u64> {
    clipboard::copy_secret(text, clear_after).map_err(|_| AppError::new("clipboard"))?;
    Ok(clear_after.as_secs())
}

fn data_dir(app: &AppHandle) -> tauri::Result<PathBuf> {
    // Debug builds can be pointed at a throwaway folder, so test runs never touch a real vault.
    #[cfg(debug_assertions)]
    {
        if let Some(dir) = std::env::var_os("KRYPT_DATA_DIR") {
            return Ok(PathBuf::from(dir));
        }
    }
    app.path().app_data_dir()
}

/// Locks after the idle time, when Windows locks the session, and after standby.
fn start_auto_lock(app: AppHandle) {
    // Debug test runs may keep going while the screen of the machine is locked.
    let follow_windows =
        !cfg!(debug_assertions) || std::env::var_os("KRYPT_IGNORE_SESSION_LOCK").is_none();
    thread::spawn(move || {
        let mut previous_tick = SystemTime::now();
        loop {
            thread::sleep(Duration::from_secs(5));
            let now = SystemTime::now();
            let woke = session::woke_from_standby(previous_tick, now);
            previous_tick = now;
            let state = app.state::<AppState>();
            let locked = {
                let mut backend = backend(&state);
                let away = follow_windows
                    && backend.lock_with_windows()
                    && (woke || session::session_locked());
                if away {
                    backend.lock()
                } else {
                    backend.lock_if_idle(Instant::now())
                }
            };
            if locked {
                let _ = app.emit("vault-locked", ());
            }
        }
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // Registered for the native dialogs Rust opens. The window's capabilities do not
        // include the plugin, so the web view cannot open dialogs or see paths itself.
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let data_dir = data_dir(app.handle())?;
            app.manage(Mutex::new(Backend::open(data_dir, KdfParams::DEFAULT)));
            start_auto_lock(app.handle().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            status,
            create_vault,
            unlock,
            recover,
            lock,
            touch,
            change_password,
            new_recovery_key,
            list_services,
            get_service,
            list_items,
            list_trash,
            get_item,
            get_item_for_edit,
            empty_item,
            empty_service,
            save_item,
            save_service,
            trash_item,
            restore_item,
            purge_item,
            empty_trash,
            trash_service,
            reveal_field,
            copy_field,
            copy_text,
            totp_now,
            save_settings,
            generate_password,
            export_vault,
            import_pick,
            import_unlock,
            import_commit,
            import_cancel,
        ])
        .run(tauri::generate_context!())
        .expect("error while running Krypt");
}
