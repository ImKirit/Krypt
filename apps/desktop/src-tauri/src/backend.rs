//! Everything the window can ask for, kept free of Tauri so it can be tested directly.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use krypt_core::crypto::{self, KdfParams};
use krypt_core::export::{self, ExportPayload};
use krypt_core::generator::{self, GeneratorOptions};
use krypt_core::keyslot::{self, SlotKind};
use krypt_core::model::{Item, ItemData, ItemType, PasswordChange, Service};
use krypt_core::password::{MIN_CHARS as MIN_PASSWORD_CHARS, PasswordRules};
use krypt_core::recovery::RecoveryKey;
use krypt_core::secret::{self, MASKED, Secret};
use krypt_core::totp::TotpConfig;
use krypt_import::{Plan, Source};
use krypt_store::{BackupRetention, LockedVault, Record, Vault};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::device::{CHALLENGE_LEN, DeviceRecord};
use crate::error::{AppError, AppResult};
use crate::settings::Settings;

const PASSWORD_HISTORY_KEPT: usize = 20;
/// The ten newest copies, plus the newest copy of each of the last eight weeks.
const BACKUPS: BackupRetention = BackupRetention {
    recent: 10,
    weeks: 8,
};
/// Anything larger is no export.
const MAX_IMPORT_BYTES: u64 = 64 * 1024 * 1024;

enum VaultSlot {
    Missing,
    Locked(LockedVault),
    Unlocked(Vault),
    /// Only seen while a lock or unlock is in progress.
    Busy,
}

pub struct Backend {
    data_dir: PathBuf,
    kdf: KdfParams,
    slot: VaultSlot,
    problem: Option<AppError>,
    settings: Settings,
    last_activity: Instant,
    backed_up: bool,
    backup_failed: bool,
    pending_import: Option<PendingImport>,
    /// Whether Windows Hello is set up on this PC; checked once in the background at start.
    hello_supported: bool,
    /// When the master password last opened the vault while the app runs.
    password_unlocked_at: Option<i64>,
    /// Offer Windows Hello after this unlock with the master password.
    hello_offer_due: bool,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub vault_exists: bool,
    pub unlocked: bool,
    /// Why an existing vault could not be opened, e.g. a newer format.
    pub problem: Option<AppError>,
    pub backup_failed: bool,
    pub settings: Settings,
    pub min_password_chars: usize,
    pub hello: HelloStatus,
}

#[derive(Debug, Serialize)]
pub struct HelloStatus {
    /// Windows Hello is set up on this PC.
    pub supported: bool,
    /// This PC opens this vault with Windows Hello.
    pub enrolled: bool,
    /// The reminder interval has passed, so the master password comes first.
    pub password_due: bool,
    /// Ask now whether to use Windows Hello.
    pub offer: bool,
}

/// What Windows Hello has to sign. Nothing in it is secret.
#[derive(Debug)]
pub struct HelloRequest {
    pub key_name: String,
    pub challenge: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct ServiceSummary {
    pub id: Uuid,
    pub name: String,
    pub domains: Vec<String>,
    pub favorite: bool,
    pub item_count: usize,
}

/// A list row. Never contains a secret.
#[derive(Debug, Serialize)]
pub struct ItemSummary {
    pub id: Uuid,
    pub service_id: Option<Uuid>,
    pub service_name: Option<String>,
    pub label: String,
    pub item_type: ItemType,
    pub subtitle: Option<String>,
    pub favorite: bool,
    pub has_totp: bool,
    pub tags: Vec<String>,
    pub updated: i64,
    pub deleted_at: Option<i64>,
}

#[derive(Debug, Serialize)]
pub struct TotpNow {
    pub code: String,
    pub remaining: u32,
    pub period: u32,
}

#[derive(Debug, Serialize)]
pub struct GeneratedPassword {
    pub value: Secret,
    pub bits: u32,
}

/// What an import is about to do. Names and counts only, never a secret.
#[derive(Debug, Default, Serialize)]
pub struct ImportPreview {
    pub file_name: String,
    /// A Krypt export that waits for its password; nothing else is filled in yet.
    pub needs_password: bool,
    pub source: Option<Source>,
    pub counts: Vec<TypeCount>,
    pub total: usize,
    pub new_services: Vec<String>,
    pub existing_services: Vec<String>,
    pub duplicates: usize,
    pub skipped: usize,
    /// Exports of other apps hold every password unencrypted.
    pub plaintext: bool,
}

#[derive(Debug, Serialize)]
pub struct TypeCount {
    pub item_type: ItemType,
    pub count: usize,
}

#[derive(Debug, Serialize)]
pub struct ImportResult {
    pub items: usize,
    pub services: usize,
    pub source_deleted: bool,
}

struct PendingImport {
    path: PathBuf,
    file_name: String,
    /// Empty until the password of a Krypt export is known.
    plan: Option<(Source, Plan)>,
}

impl Backend {
    pub fn open(data_dir: PathBuf, kdf: KdfParams) -> Self {
        let settings = Settings::load(&data_dir);
        let path = vault_path(&data_dir);
        let (slot, problem) = if path.exists() {
            match LockedVault::open(&path) {
                Ok(locked) => (VaultSlot::Locked(locked), None),
                Err(error) => (VaultSlot::Missing, Some(AppError::from(error))),
            }
        } else {
            (VaultSlot::Missing, None)
        };
        Self {
            data_dir,
            kdf,
            slot,
            problem,
            settings,
            last_activity: Instant::now(),
            backed_up: false,
            backup_failed: false,
            pending_import: None,
            hello_supported: false,
            password_unlocked_at: None,
            hello_offer_due: false,
        }
    }

    pub fn status(&self) -> Status {
        let unlocked = matches!(self.slot, VaultSlot::Unlocked(_));
        Status {
            vault_exists: vault_path(&self.data_dir).exists(),
            unlocked,
            problem: self.problem.clone(),
            backup_failed: self.backup_failed,
            settings: self.settings.clone(),
            min_password_chars: MIN_PASSWORD_CHARS,
            hello: self.hello_status(unlocked),
        }
    }

    /// Creates the vault and returns the recovery key, formatted to be shown once.
    pub fn create_vault(&mut self, password: &str) -> AppResult<Zeroizing<String>> {
        check_password_rules(password)?;
        if !matches!(self.slot, VaultSlot::Missing) || self.problem.is_some() {
            return Err(AppError::new("vault_exists"));
        }
        let created = Vault::create(vault_path(&self.data_dir), password, self.kdf)?;
        let shown = created.recovery_key.to_display_string();
        // A brand-new vault has nothing worth a backup yet.
        self.backed_up = true;
        self.slot = VaultSlot::Unlocked(created.vault);
        self.touch();
        self.password_unlocked();
        Ok(shown)
    }

    pub fn unlock(&mut self, password: &str) -> AppResult<()> {
        let locked = self.take_locked()?;
        match locked.unlock_with_password(password) {
            Ok(mut vault) => {
                self.strengthen(&mut vault, password);
                self.finish_unlock(vault);
                self.password_unlocked();
                Ok(())
            }
            Err(failed) => {
                let failed = *failed;
                self.slot = VaultSlot::Locked(failed.vault);
                Err(failed.error.into())
            }
        }
    }

    /// Opens the vault with the recovery key and sets a new master password.
    pub fn recover(&mut self, recovery_key: &str, new_password: &str) -> AppResult<()> {
        check_password_rules(new_password)?;
        let key = RecoveryKey::parse(recovery_key)?;
        let locked = self.take_locked()?;
        match locked.unlock_with_recovery_key(&key) {
            Ok(mut vault) => {
                let changed = vault.change_password(new_password, self.kdf);
                self.finish_unlock(vault);
                if changed.is_ok() {
                    self.password_unlocked();
                }
                changed.map_err(AppError::from)
            }
            Err(failed) => {
                let failed = *failed;
                self.slot = VaultSlot::Locked(failed.vault);
                Err(failed.error.into())
            }
        }
    }

    /// Returns true if the vault was unlocked and is locked now.
    pub fn lock(&mut self) -> bool {
        // A prepared import holds decrypted entries.
        self.pending_import = None;
        self.hello_offer_due = false;
        match std::mem::replace(&mut self.slot, VaultSlot::Busy) {
            VaultSlot::Unlocked(vault) => {
                self.slot = VaultSlot::Locked(vault.lock());
                true
            }
            other => {
                self.slot = other;
                false
            }
        }
    }

    pub fn touch(&mut self) {
        self.last_activity = Instant::now();
    }

    /// Locks once the configured idle time has passed. Returns true if it locked just now.
    pub fn lock_if_idle(&mut self, now: Instant) -> bool {
        let minutes = self.settings.auto_lock_minutes;
        if minutes == 0 || !matches!(self.slot, VaultSlot::Unlocked(_)) {
            return false;
        }
        let idle = now.saturating_duration_since(self.last_activity);
        idle >= Duration::from_secs(u64::from(minutes) * 60) && self.lock()
    }

    pub fn change_password(&mut self, current: &str, new_password: &str) -> AppResult<()> {
        check_password_rules(new_password)?;
        self.touch();
        let kdf = self.kdf;
        let vault = self.vault_mut()?;
        if !vault.check_password(current)? {
            return Err(AppError::new("wrong_password"));
        }
        vault.change_password(new_password, kdf)?;
        Ok(())
    }

    pub fn new_recovery_key(&mut self) -> AppResult<Zeroizing<String>> {
        self.touch();
        Ok(self
            .vault_mut()?
            .replace_recovery_key()?
            .to_display_string())
    }

    pub fn ensure_unlocked(&self) -> AppResult<()> {
        self.vault().map(|_| ())
    }

    pub fn services(&self) -> AppResult<Vec<ServiceSummary>> {
        let vault = self.vault()?;
        let items = vault.items()?;
        Ok(vault
            .services()?
            .into_iter()
            .map(|record| {
                let service = record.value;
                let item_count = items
                    .iter()
                    .filter(|item| item.value.service_id == Some(service.id))
                    .count();
                ServiceSummary {
                    id: service.id,
                    domains: service.domains.iter().map(|d| d.host.clone()).collect(),
                    favorite: service.favorite,
                    name: service.name,
                    item_count,
                }
            })
            .collect::<Vec<_>>())
        .map(|mut summaries| {
            summaries.sort_by_key(|summary| summary.name.to_lowercase());
            summaries
        })
    }

    pub fn service(&self, id: Uuid) -> AppResult<Service> {
        self.vault()?
            .service(id)?
            .map(|record| record.value)
            .ok_or_else(|| AppError::new("not_found"))
    }

    pub fn items(&self) -> AppResult<Vec<ItemSummary>> {
        let names = self.service_names()?;
        Ok(self
            .vault()?
            .items()?
            .iter()
            .map(|record| summarize(record, &names))
            .collect())
    }

    pub fn trash(&self) -> AppResult<Vec<ItemSummary>> {
        let names = self.service_names()?;
        Ok(self
            .vault()?
            .trashed_items()?
            .iter()
            .map(|record| summarize(record, &names))
            .collect())
    }

    /// The item with every non-empty secret replaced by a placeholder.
    pub fn item_view(&self, id: Uuid) -> AppResult<Value> {
        let record = self.record(id)?;
        let mut view = secret::masked(|| serde_json::to_value(&record.value))
            .map_err(|_| AppError::new("internal"))?;
        if let Value::Object(map) = &mut view {
            map.insert("revision".into(), record.revision.into());
            map.insert("updated".into(), record.updated.into());
            map.insert("deleted_at".into(), record.deleted_at.into());
        }
        Ok(view)
    }

    /// The complete item, secrets included. Only for the editor, opened on purpose.
    pub fn item_for_edit(&mut self, id: Uuid) -> AppResult<Item> {
        self.touch();
        Ok(self.record(id)?.value)
    }

    /// One field of an item, addressed by a JSON pointer such as `/data/password`.
    pub fn field(&mut self, id: Uuid, pointer: &str) -> AppResult<Zeroizing<String>> {
        self.touch();
        let item = self.record(id)?.value;
        let value =
            Zeroizing::new(serde_json::to_string(&item).map_err(|_| AppError::new("internal"))?);
        let value: Value = serde_json::from_str(&value).map_err(|_| AppError::new("internal"))?;
        match value.pointer(pointer) {
            Some(Value::String(text)) if !text.is_empty() => Ok(Zeroizing::new(text.clone())),
            Some(Value::Number(number)) => Ok(Zeroizing::new(number.to_string())),
            _ => Err(AppError::new("not_found")),
        }
    }

    pub fn empty_item(item_type: ItemType) -> Item {
        Item::new(item_type.empty_data(), now_ms())
    }

    pub fn empty_service(name: &str) -> Service {
        Service::new(name.trim())
    }

    pub fn save_item(&mut self, mut item: Item) -> AppResult<Uuid> {
        self.touch();
        if contains_placeholder(&item)? {
            return Err(AppError::new("masked_value"));
        }
        item.label = item.label.trim().to_owned();
        let vault = self.vault_mut()?;
        if let Some(service_id) = item.service_id
            && vault.service(service_id)?.is_none()
        {
            return Err(AppError::new("not_found"));
        }
        if let (ItemData::Login(new), Some(old)) = (&mut item.data, vault.item(item.id)?)
            && let ItemData::Login(old) = &old.value.data
            && !old.password.is_empty()
            && old.password != new.password
        {
            new.password_history.insert(
                0,
                PasswordChange {
                    password: old.password.clone(),
                    replaced_at: now_ms(),
                },
            );
            new.password_history.truncate(PASSWORD_HISTORY_KEPT);
        }
        vault.put_item(&item)?;
        Ok(item.id)
    }

    pub fn save_service(&mut self, mut service: Service) -> AppResult<Uuid> {
        self.touch();
        service.name = service.name.trim().to_owned();
        if service.name.is_empty() {
            return Err(AppError::new("empty_name"));
        }
        for domain in &mut service.domains {
            domain.host = normalize_host(&domain.host);
        }
        service.domains.retain(|domain| !domain.host.is_empty());
        self.vault_mut()?.put_service(&service)?;
        Ok(service.id)
    }

    pub fn trash_item(&mut self, id: Uuid) -> AppResult<()> {
        self.touch();
        found(self.vault_mut()?.trash_item(id)?)
    }

    pub fn restore_item(&mut self, id: Uuid) -> AppResult<()> {
        self.touch();
        found(self.vault_mut()?.restore_item(id)?)
    }

    pub fn purge_item(&mut self, id: Uuid) -> AppResult<()> {
        self.touch();
        found(self.vault_mut()?.purge_item(id)?)
    }

    pub fn empty_trash(&mut self) -> AppResult<usize> {
        self.touch();
        Ok(self.vault_mut()?.empty_trash(i64::MAX)?)
    }

    /// Only services without entries can go, so nothing ends up without its service.
    pub fn trash_service(&mut self, id: Uuid) -> AppResult<()> {
        self.touch();
        let vault = self.vault_mut()?;
        if vault
            .items()?
            .iter()
            .any(|item| item.value.service_id == Some(id))
        {
            return Err(AppError::new("service_not_empty"));
        }
        found(vault.trash_service(id)?)
    }

    pub fn totp_now(&self, id: Uuid) -> AppResult<TotpNow> {
        let item = self.record(id)?.value;
        let config: &TotpConfig = match &item.data {
            ItemData::Totp(config) => config,
            ItemData::Login(login) => login
                .totp
                .as_ref()
                .ok_or_else(|| AppError::new("no_totp"))?,
            _ => return Err(AppError::new("no_totp")),
        };
        let now = unix_seconds();
        Ok(TotpNow {
            code: config.code_at(now)?.to_string(),
            remaining: config.seconds_remaining(now)?,
            period: config.period,
        })
    }

    /// A random password or passphrase. Needs no vault.
    pub fn generate(options: &GeneratorOptions) -> AppResult<GeneratedPassword> {
        let generated = generator::generate(options)?;
        Ok(GeneratedPassword {
            value: generated.value,
            bits: generated.bits,
        })
    }

    /// Checks what an export needs before the save dialog opens, so a weak password is
    /// reported first.
    pub fn check_export(&self, password: &str) -> AppResult<()> {
        self.vault()?;
        check_password_rules(password)
    }

    /// Writes every service and every entry outside the trash into an encrypted export.
    pub fn export_to(&mut self, path: &Path, password: &str) -> AppResult<()> {
        check_password_rules(password)?;
        self.touch();
        let vault = self.vault()?;
        let payload = ExportPayload {
            exported_at: now_ms(),
            services: vault
                .services()?
                .into_iter()
                .map(|record| record.value)
                .collect(),
            items: vault
                .items()?
                .into_iter()
                .map(|record| record.value)
                .collect(),
        };
        let sealed = export::seal(&payload, password, self.kdf)?;
        write_replacing(path, &sealed)
    }

    /// Reads a file chosen for import and works out what it would add. A Krypt export waits
    /// for its password in [`Backend::import_unlock`].
    pub fn import_open(&mut self, path: PathBuf) -> AppResult<ImportPreview> {
        self.touch();
        self.pending_import = None;
        self.vault()?;
        let bytes = read_import(&path)?;
        let plan = if krypt_import::needs_password(&bytes) {
            None
        } else {
            Some(self.plan_import(&bytes, None)?)
        };
        let pending = PendingImport {
            file_name: path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default(),
            path,
            plan,
        };
        let preview = pending.preview();
        self.pending_import = Some(pending);
        Ok(preview)
    }

    pub fn import_unlock(&mut self, password: &str) -> AppResult<ImportPreview> {
        self.touch();
        let path = match &self.pending_import {
            Some(pending) => pending.path.clone(),
            None => return Err(AppError::new("no_import")),
        };
        let bytes = read_import(&path)?;
        let plan = self.plan_import(&bytes, Some(password))?;
        let pending = self
            .pending_import
            .as_mut()
            .ok_or_else(|| AppError::new("no_import"))?;
        pending.plan = Some(plan);
        Ok(pending.preview())
    }

    /// Writes the prepared import in one transaction, after a backup of the vault.
    pub fn import_commit(&mut self, delete_source: bool) -> AppResult<ImportResult> {
        self.touch();
        let Some(PendingImport {
            path,
            plan: Some((source, plan)),
            ..
        }) = self.pending_import.take()
        else {
            return Err(AppError::new("no_import"));
        };
        let vault = self.vault_mut()?;
        // Hundreds of new entries are easier to undo from a copy than one by one.
        let _ = vault.create_backup(BACKUPS);
        vault.put_all(&plan.new_services, &plan.items)?;
        let source_deleted =
            delete_source && source != Source::Krypt && fs::remove_file(&path).is_ok();
        Ok(ImportResult {
            items: plan.items.len(),
            services: plan.new_services.len(),
            source_deleted,
        })
    }

    pub fn import_cancel(&mut self) {
        self.pending_import = None;
    }

    pub fn clipboard_clear_after(&self) -> Duration {
        Duration::from_secs(u64::from(self.settings.clipboard_clear_seconds))
    }

    pub fn save_settings(&mut self, settings: Settings) -> AppResult<Settings> {
        let mut settings = settings.sanitized();
        // Only the backend decides whether Windows Hello has been offered.
        settings.hello_offered = self.settings.hello_offered;
        settings.save(&self.data_dir)?;
        self.settings = settings.clone();
        Ok(settings)
    }

    /// Whether the auto-lock also follows the Windows session lock and standby.
    pub fn lock_with_windows(&self) -> bool {
        self.settings.lock_with_windows
    }

    /// Rewrites the password slot with the current Argon2id costs if the vault still uses
    /// weaker ones. Needs the password, so it runs right after a password unlock. If it fails,
    /// the old slot stays in place and keeps working.
    fn strengthen(&self, vault: &mut Vault, password: &str) {
        if let Ok(Some(current)) = vault.password_kdf_params()
            && is_weaker(current, self.kdf)
        {
            let _ = vault.change_password(password, self.kdf);
        }
    }

    fn plan_import(&self, bytes: &[u8], password: Option<&str>) -> AppResult<(Source, Plan)> {
        let parsed = krypt_import::parse(bytes, password)?;
        let source = parsed.source;
        let vault = self.vault()?;
        let services: Vec<Service> = vault
            .services()?
            .into_iter()
            .map(|record| record.value)
            .collect();
        let items: Vec<Item> = vault
            .items()?
            .into_iter()
            .map(|record| record.value)
            .collect();
        let plan = krypt_import::plan(parsed, &services, &items);
        if plan.items.is_empty() && plan.duplicates == 0 {
            return Err(AppError::new("import_empty"));
        }
        Ok((source, plan))
    }

    fn take_locked(&mut self) -> AppResult<LockedVault> {
        match std::mem::replace(&mut self.slot, VaultSlot::Busy) {
            VaultSlot::Locked(locked) => Ok(locked),
            other => {
                let code = if matches!(other, VaultSlot::Unlocked(_)) {
                    "already_unlocked"
                } else {
                    "no_vault"
                };
                self.slot = other;
                Err(AppError::new(code))
            }
        }
    }

    fn finish_unlock(&mut self, vault: Vault) {
        if !self.backed_up {
            // One copy per app start. A failed copy must not keep anyone out of their vault,
            // so it only raises a warning in the status.
            match vault.create_backup(BACKUPS) {
                Ok(_) => self.backed_up = true,
                Err(_) => self.backup_failed = true,
            }
        }
        self.slot = VaultSlot::Unlocked(vault);
        self.touch();
    }

    fn vault(&self) -> AppResult<&Vault> {
        match &self.slot {
            VaultSlot::Unlocked(vault) => Ok(vault),
            _ => Err(AppError::new("locked")),
        }
    }

    fn vault_mut(&mut self) -> AppResult<&mut Vault> {
        match &mut self.slot {
            VaultSlot::Unlocked(vault) => Ok(vault),
            _ => Err(AppError::new("locked")),
        }
    }

    fn record(&self, id: Uuid) -> AppResult<Record<Item>> {
        self.vault()?
            .item(id)?
            .ok_or_else(|| AppError::new("not_found"))
    }

    fn service_names(&self) -> AppResult<HashMap<Uuid, String>> {
        let vault = self.vault()?;
        Ok(vault
            .services()?
            .into_iter()
            .chain(vault.trashed_services()?)
            .map(|record| (record.value.id, record.value.name))
            .collect())
    }
}

/// Windows Hello (Weg B). The prompts themselves happen outside, in `lib.rs`, so the backend is
/// never locked while Windows waits for a PIN or a finger.
impl Backend {
    pub fn set_hello_supported(&mut self, supported: bool) {
        self.hello_supported = supported;
    }

    /// What Windows Hello has to sign to open the locked vault.
    pub fn hello_unlock_request(&self) -> AppResult<HelloRequest> {
        match self.slot {
            VaultSlot::Locked(_) => {}
            VaultSlot::Unlocked(_) => return Err(AppError::new("already_unlocked")),
            VaultSlot::Missing | VaultSlot::Busy => return Err(AppError::new("no_vault")),
        }
        let device = self.usable_device()?;
        Ok(HelloRequest {
            key_name: device.key_name,
            challenge: device.challenge,
        })
    }

    /// Opens the vault with the signature Windows Hello made for the unlock request.
    pub fn unlock_with_hello(&mut self, signature: &[u8]) -> AppResult<()> {
        let device = self.usable_device()?;
        let kek = keyslot::device_kek(signature)?;
        let locked = self.take_locked()?;
        match locked.unlock_with_external_key(device.slot_id, &kek) {
            Ok(vault) => {
                self.finish_unlock(vault);
                Ok(())
            }
            Err(failed) => {
                let failed = *failed;
                self.slot = VaultSlot::Locked(failed.vault);
                Err(failed.error.into())
            }
        }
    }

    /// A fresh key name and challenge for turning Windows Hello on. Needs the open vault.
    pub fn hello_enroll_request(&self) -> AppResult<HelloRequest> {
        self.vault()?;
        if !self.hello_supported {
            return Err(AppError::new("hello_unavailable"));
        }
        let mut challenge = vec![0u8; CHALLENGE_LEN];
        crypto::random_bytes(&mut challenge)?;
        Ok(HelloRequest {
            key_name: format!("dev.imkirit.krypt.{}", Uuid::new_v4()),
            challenge,
        })
    }

    /// Adds the device slot for the signature over the request's challenge and writes
    /// `device.json`. Returns the key name of the device it replaced, which Windows should
    /// delete.
    pub fn hello_enroll(
        &mut self,
        request: &HelloRequest,
        signature: &[u8],
    ) -> AppResult<Option<String>> {
        self.touch();
        if request.challenge.len() != CHALLENGE_LEN {
            return Err(AppError::new("internal"));
        }
        let kek = keyslot::device_kek(signature)?;
        let previous = self.device();
        let now = now_ms();
        let last_password_unlock = self
            .password_unlocked_at
            .or(previous.as_ref().map(|device| device.last_password_unlock))
            .unwrap_or(now);
        let data_dir = self.data_dir.clone();

        let vault = self.vault_mut()?;
        let slot_id = vault.add_external_slot(SlotKind::Device, &kek)?;
        let record = DeviceRecord::new(
            vault.vault_id(),
            slot_id,
            request.key_name.clone(),
            request.challenge.clone(),
            now,
            last_password_unlock,
        );
        if let Err(error) = record.save(&data_dir) {
            let _ = vault.remove_external_slot(slot_id);
            return Err(error);
        }
        if let Some(previous) = &previous {
            let _ = vault.remove_external_slot(previous.slot_id);
        }

        self.hello_offer_due = false;
        let _ = self.remember_hello_offered();
        Ok(previous.map(|device| device.key_name))
    }

    /// The user does not want Windows Hello now. Krypt does not ask again; the settings still
    /// offer it.
    pub fn hello_dismiss(&mut self) -> AppResult<()> {
        self.hello_offer_due = false;
        self.remember_hello_offered()
    }

    /// Removes the device slot and `device.json`. Returns the key name Windows should delete.
    pub fn hello_forget(&mut self) -> AppResult<Option<String>> {
        self.touch();
        let record = DeviceRecord::load(&self.data_dir);
        let vault = self.vault_mut()?;
        if let Some(record) = &record
            && vault.vault_id() == record.vault_id
        {
            vault.remove_external_slot(record.slot_id)?;
        }
        DeviceRecord::remove(&self.data_dir)?;
        Ok(record.map(|record| record.key_name))
    }

    fn hello_status(&self, unlocked: bool) -> HelloStatus {
        let device = self.device();
        let enrolled = device.is_some();
        HelloStatus {
            supported: self.hello_supported,
            enrolled,
            password_due: device.is_some_and(|device| {
                device.password_due(self.settings.password_reminder_days, now_ms())
            }),
            offer: unlocked
                && self.hello_offer_due
                && self.hello_supported
                && !enrolled
                && !self.settings.hello_offered,
        }
    }

    /// The Windows Hello record of this PC, if it belongs to the vault that is open.
    fn device(&self) -> Option<DeviceRecord> {
        let record = DeviceRecord::load(&self.data_dir)?;
        let belongs = match &self.slot {
            VaultSlot::Locked(vault) => {
                vault.vault_id().is_ok_and(|id| id == record.vault_id)
                    && vault.has_slot(record.slot_id).unwrap_or(false)
            }
            VaultSlot::Unlocked(vault) => {
                vault.vault_id() == record.vault_id
                    && vault.has_slot(record.slot_id).unwrap_or(false)
            }
            VaultSlot::Missing | VaultSlot::Busy => false,
        };
        belongs.then_some(record)
    }

    /// The device record, unless there is none or the master password is due.
    fn usable_device(&self) -> AppResult<DeviceRecord> {
        let device = self.device().ok_or_else(|| AppError::new("no_device"))?;
        if device.password_due(self.settings.password_reminder_days, now_ms()) {
            return Err(AppError::new("password_due"));
        }
        Ok(device)
    }

    /// An unlock with the master password resets the Windows Hello reminder and lets Krypt
    /// offer Windows Hello once.
    fn password_unlocked(&mut self) {
        let now = now_ms();
        self.password_unlocked_at = Some(now);
        self.hello_offer_due = true;
        if let Some(mut device) = self.device() {
            device.last_password_unlock = now;
            // Only the reminder depends on it; if the write fails, the password comes back early.
            let _ = device.save(&self.data_dir);
        }
    }

    fn remember_hello_offered(&mut self) -> AppResult<()> {
        if self.settings.hello_offered {
            return Ok(());
        }
        let mut settings = self.settings.clone();
        settings.hello_offered = true;
        settings.save(&self.data_dir)?;
        self.settings = settings;
        Ok(())
    }
}

impl PendingImport {
    fn preview(&self) -> ImportPreview {
        let Some((source, plan)) = &self.plan else {
            return ImportPreview {
                file_name: self.file_name.clone(),
                needs_password: true,
                ..ImportPreview::default()
            };
        };
        let mut new_services: Vec<String> = plan
            .new_services
            .iter()
            .map(|service| service.name.clone())
            .collect();
        new_services.sort_by_key(|name| name.to_lowercase());
        ImportPreview {
            file_name: self.file_name.clone(),
            needs_password: false,
            source: Some(*source),
            counts: ItemType::ALL
                .iter()
                .filter_map(|&item_type| {
                    let count = plan
                        .items
                        .iter()
                        .filter(|item| item.item_type() == item_type)
                        .count();
                    (count > 0).then_some(TypeCount { item_type, count })
                })
                .collect(),
            total: plan.items.len(),
            new_services,
            existing_services: plan.existing_services.clone(),
            duplicates: plan.duplicates,
            skipped: plan.skipped,
            plaintext: *source != Source::Krypt,
        }
    }
}

pub fn vault_path(data_dir: &Path) -> PathBuf {
    data_dir.join("vault.db")
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Today in UTC as `YYYY-MM-DD`, for file names.
pub fn today() -> String {
    date_from_days(now_ms().div_euclid(86_400_000))
}

/// Howard Hinnant's `civil_from_days`: days since 1970-01-01 to a calendar date.
fn date_from_days(days: i64) -> String {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02}")
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// True if `target` costs at least as much memory and time as `current` and more of one.
/// Mixed changes never count, so a build with other defaults cannot lower a vault's costs.
fn is_weaker(current: KdfParams, target: KdfParams) -> bool {
    current.m_cost_kib <= target.m_cost_kib
        && current.t_cost <= target.t_cost
        && (current.m_cost_kib, current.t_cost) != (target.m_cost_kib, target.t_cost)
}

/// New master and export passwords must meet every rule. Passwords set before the rules
/// existed keep working.
fn check_password_rules(password: &str) -> AppResult<()> {
    if PasswordRules::check(password).all_met() {
        Ok(())
    } else {
        Err(AppError::new("password_rules"))
    }
}

fn read_import(path: &Path) -> AppResult<Zeroizing<Vec<u8>>> {
    let size = fs::metadata(path).map_err(|_| AppError::new("io"))?.len();
    if size > MAX_IMPORT_BYTES {
        return Err(AppError::new("import_too_large"));
    }
    fs::read(path)
        .map(Zeroizing::new)
        .map_err(|_| AppError::new("io"))
}

/// Writes next to `path` first and then moves the file into place, so an interrupted write
/// never leaves half a file under the chosen name.
fn write_replacing(path: &Path, bytes: &[u8]) -> AppResult<()> {
    let mut partial_name = path
        .file_name()
        .ok_or_else(|| AppError::new("io"))?
        .to_owned();
    partial_name.push(".partial");
    let partial = path.with_file_name(partial_name);
    let written = (|| {
        let mut file = fs::File::create(&partial)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&partial, path)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&partial);
    }
    written.map_err(|_| AppError::new("io"))
}

fn found(changed: bool) -> AppResult<()> {
    if changed {
        Ok(())
    } else {
        Err(AppError::new("not_found"))
    }
}

/// True if any secret in the item is the placeholder from a masked view. Saving that would
/// overwrite the real value.
fn contains_placeholder(item: &Item) -> AppResult<bool> {
    let json = Zeroizing::new(serde_json::to_string(item).map_err(|_| AppError::new("internal"))?);
    Ok(json.contains(&format!("\"{MASKED}\"")))
}

/// `https://Console.Anthropic.com/settings` becomes `console.anthropic.com`.
fn normalize_host(input: &str) -> String {
    let lower = input.trim().to_lowercase();
    let without_scheme = lower
        .split_once("://")
        .map_or(lower.as_str(), |(_, rest)| rest);
    without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim_end_matches('.')
        .to_owned()
}

fn summarize(record: &Record<Item>, names: &HashMap<Uuid, String>) -> ItemSummary {
    let item = &record.value;
    ItemSummary {
        id: item.id,
        service_id: item.service_id,
        service_name: item.service_id.and_then(|id| names.get(&id).cloned()),
        label: item.label.clone(),
        item_type: item.item_type(),
        subtitle: subtitle(&item.data),
        favorite: item.favorite,
        has_totp: matches!(&item.data, ItemData::Totp(_))
            || matches!(&item.data, ItemData::Login(login) if login.totp.is_some()),
        tags: item.tags.clone(),
        updated: record.updated,
        deleted_at: record.deleted_at,
    }
}

/// The plain-text detail shown under a list row. Only fields that are not secret.
fn subtitle(data: &ItemData) -> Option<String> {
    let text = match data {
        ItemData::Login(login) => login.username.clone().or_else(|| login.email.clone()),
        ItemData::ApiKey(key) => key.key_id.clone().or_else(|| key.organization.clone()),
        ItemData::Passkey(passkey) => passkey
            .username
            .clone()
            .or_else(|| Some(passkey.rp_id.clone())),
        ItemData::Totp(totp) => totp.account.clone().or_else(|| totp.issuer.clone()),
        ItemData::Card(card) => card.holder.clone().or_else(|| card.brand.clone()),
        ItemData::Identity(identity) => Some(identity.full_name.clone()),
        ItemData::SshKey(key) => key.comment.clone().or_else(|| key.fingerprint.clone()),
        ItemData::EnvFile(env) => env.file_name.clone().or_else(|| env.project.clone()),
        ItemData::Database(db) => Some(match db.port {
            Some(port) => format!("{}:{port}", db.host),
            None => db.host.clone(),
        }),
        ItemData::Note(_) | ItemData::RecoveryCodes(_) => None,
    };
    text.filter(|t| !t.trim().is_empty())
}

#[cfg(test)]
mod tests {
    use krypt_core::model::{ApiKey, DomainRule, Login};

    use super::*;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    const PASSWORD: &str = "Correct-horse-battery-1";
    const NEW_PASSWORD: &str = "A-brand-new-password-2";
    const OTHER_PASSWORD: &str = "Another-good-password-3";
    const EXPORT_PASSWORD: &str = "Export-password-4";
    /// Stands in for the key Windows Hello keeps.
    const HELLO_SECRET: &[u8] = b"only windows hello knows this key";
    const DAY_MS: i64 = 86_400_000;

    fn unlocked() -> (tempfile::TempDir, Backend) {
        let dir = tempfile::tempdir().unwrap();
        let mut backend = Backend::open(dir.path().to_owned(), FAST);
        backend.create_vault(PASSWORD).unwrap();
        (dir, backend)
    }

    fn login(password: &str) -> Item {
        let mut item = Backend::empty_item(ItemType::Login);
        item.label = "personal".into();
        if let ItemData::Login(login) = &mut item.data {
            login.email = Some("you@example.com".into());
            login.password = Secret::new(password);
        }
        item
    }

    fn csv_file(dir: &Path, text: &str) -> PathBuf {
        let path = dir.join("passwords.csv");
        fs::write(&path, text).unwrap();
        path
    }

    /// A deterministic signature, like Windows Hello's, without the prompt.
    fn sign(secret: &[u8], request: &HelloRequest) -> Vec<u8> {
        let mut signature = vec![0u8; 256];
        crypto::hkdf_sha256(Some(&request.challenge), secret, b"test", &mut signature).unwrap();
        signature
    }

    fn with_hello() -> (tempfile::TempDir, Backend) {
        let (dir, mut backend) = unlocked();
        backend.set_hello_supported(true);
        (dir, backend)
    }

    fn enroll(backend: &mut Backend) -> HelloRequest {
        let request = backend.hello_enroll_request().unwrap();
        let replaced = backend
            .hello_enroll(&request, &sign(HELLO_SECRET, &request))
            .unwrap();
        assert_eq!(replaced, None);
        request
    }

    fn age_password_unlock(dir: &Path, days: i64) {
        let mut record = DeviceRecord::load(dir).unwrap();
        record.last_password_unlock = now_ms() - days * DAY_MS;
        record.save(dir).unwrap();
    }

    #[test]
    fn unlocking_raises_weaker_argon2_costs_and_never_lowers_them() {
        let dir = tempfile::tempdir().unwrap();
        let reopen = || {
            LockedVault::open(vault_path(dir.path()))
                .unwrap()
                .unlock_with_password(PASSWORD)
                .unwrap()
        };
        let mut first = Backend::open(dir.path().to_owned(), FAST);
        first.create_vault(PASSWORD).unwrap();
        drop(first);

        let stronger = KdfParams {
            m_cost_kib: 128,
            t_cost: 2,
            p_cost: 1,
        };
        let mut newer_build = Backend::open(dir.path().to_owned(), stronger);
        newer_build.unlock(PASSWORD).unwrap();
        drop(newer_build);
        assert_eq!(reopen().password_kdf_params().unwrap(), Some(stronger));

        let mut older_build = Backend::open(dir.path().to_owned(), FAST);
        older_build.unlock(PASSWORD).unwrap();
        drop(older_build);
        assert_eq!(reopen().password_kdf_params().unwrap(), Some(stronger));
    }

    #[test]
    fn only_strictly_stronger_costs_count() {
        let base = KdfParams {
            m_cost_kib: 1024,
            t_cost: 2,
            p_cost: 1,
        };
        assert!(is_weaker(base, KdfParams { t_cost: 3, ..base }));
        assert!(is_weaker(
            base,
            KdfParams {
                m_cost_kib: 2048,
                ..base
            }
        ));
        assert!(!is_weaker(base, base));
        assert!(!is_weaker(
            base,
            KdfParams {
                m_cost_kib: 2048,
                t_cost: 1,
                ..base
            }
        ));
        assert!(!is_weaker(base, KdfParams { p_cost: 4, ..base }));
    }

    #[test]
    fn creates_locks_and_unlocks() {
        let dir = tempfile::tempdir().unwrap();
        let mut backend = Backend::open(dir.path().to_owned(), FAST);
        assert!(!backend.status().vault_exists);
        for weak in [
            "short",
            "long but no rules",
            "Nodigits-here",
            "n0-upper-case",
        ] {
            assert_eq!(
                backend.create_vault(weak).unwrap_err().code,
                "password_rules",
                "{weak}"
            );
        }

        let recovery_key = backend.create_vault(PASSWORD).unwrap();
        assert_eq!(recovery_key.len(), 39);
        assert!(backend.status().unlocked);
        assert!(backend.lock());
        assert_eq!(backend.items().unwrap_err().code, "locked");
        assert_eq!(
            backend.unlock("wrong password!").unwrap_err().code,
            "wrong_password"
        );
        backend.unlock(PASSWORD).unwrap();
        assert!(backend.status().unlocked);
        assert_eq!(
            backend.unlock(PASSWORD).unwrap_err().code,
            "already_unlocked"
        );

        // A second start finds the vault locked.
        drop(backend);
        let reopened = Backend::open(dir.path().to_owned(), FAST);
        assert!(reopened.status().vault_exists);
        assert!(!reopened.status().unlocked);
    }

    #[test]
    fn the_first_unlock_of_a_start_writes_a_backup() {
        let (dir, mut backend) = unlocked();
        backend.lock();
        backend.unlock(PASSWORD).unwrap();
        assert!(
            !dir.path().join("backups").exists(),
            "new vaults need no backup"
        );

        drop(backend);
        let mut next_start = Backend::open(dir.path().to_owned(), FAST);
        next_start.unlock(PASSWORD).unwrap();
        next_start.lock();
        next_start.unlock(PASSWORD).unwrap();
        assert_eq!(fs::read_dir(dir.path().join("backups")).unwrap().count(), 1);
        assert!(!next_start.status().backup_failed);
    }

    #[test]
    fn the_recovery_key_sets_a_new_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut backend = Backend::open(dir.path().to_owned(), FAST);
        let recovery_key = backend.create_vault(PASSWORD).unwrap();
        backend.lock();

        assert_eq!(
            backend.recover(&recovery_key, "weak").unwrap_err().code,
            "password_rules"
        );
        assert_eq!(
            backend.recover("not a key", NEW_PASSWORD).unwrap_err().code,
            "invalid_recovery_key"
        );
        backend
            .recover(&recovery_key.to_lowercase(), NEW_PASSWORD)
            .unwrap();
        backend.lock();
        assert_eq!(backend.unlock(PASSWORD).unwrap_err().code, "wrong_password");
        backend.unlock(NEW_PASSWORD).unwrap();
    }

    #[test]
    fn changing_the_password_needs_the_current_one_and_the_rules() {
        let (_dir, mut backend) = unlocked();
        assert_eq!(
            backend
                .change_password("guess guess guess", OTHER_PASSWORD)
                .unwrap_err()
                .code,
            "wrong_password"
        );
        assert_eq!(
            backend
                .change_password(PASSWORD, "no rules at all")
                .unwrap_err()
                .code,
            "password_rules"
        );
        backend.change_password(PASSWORD, OTHER_PASSWORD).unwrap();
        backend.lock();
        backend.unlock(OTHER_PASSWORD).unwrap();
    }

    #[test]
    fn views_are_masked_until_a_field_is_asked_for() {
        let (_dir, mut backend) = unlocked();
        let item = login("hunter2-secret");
        let id = backend.save_item(item).unwrap();

        let view = backend.item_view(id).unwrap();
        let text = view.to_string();
        assert!(!text.contains("hunter2-secret"), "{text}");
        assert!(text.contains(MASKED));
        assert!(text.contains("you@example.com"));

        assert_eq!(
            backend.field(id, "/data/password").unwrap().as_str(),
            "hunter2-secret"
        );
        assert_eq!(
            backend.field(id, "/data/nothing").unwrap_err().code,
            "not_found"
        );

        let summaries = serde_json::to_string(&backend.items().unwrap()).unwrap();
        assert!(!summaries.contains("hunter2-secret"));
        assert!(summaries.contains("you@example.com"));
    }

    #[test]
    fn a_masked_item_cannot_be_saved_back() {
        let (_dir, mut backend) = unlocked();
        let id = backend.save_item(login("hunter2-secret")).unwrap();
        let view = backend.item_view(id).unwrap();
        let masked: Item = serde_json::from_value(view).unwrap();
        assert_eq!(backend.save_item(masked).unwrap_err().code, "masked_value");
        assert_eq!(
            backend.field(id, "/data/password").unwrap().as_str(),
            "hunter2-secret"
        );
    }

    #[test]
    fn a_changed_password_goes_into_the_history() {
        let (_dir, mut backend) = unlocked();
        let id = backend.save_item(login("first password")).unwrap();

        let mut edited = backend.item_for_edit(id).unwrap();
        if let ItemData::Login(login) = &mut edited.data {
            login.password = Secret::new("second password");
        }
        backend.save_item(edited).unwrap();

        let ItemData::Login(saved) = backend.item_for_edit(id).unwrap().data else {
            panic!("not a login")
        };
        assert_eq!(saved.password.expose(), "second password");
        assert_eq!(saved.password_history.len(), 1);
        assert_eq!(
            saved.password_history[0].password.expose(),
            "first password"
        );

        // Saving without a change adds nothing.
        let unchanged = backend.item_for_edit(id).unwrap();
        backend.save_item(unchanged).unwrap();
        let ItemData::Login(again) = backend.item_for_edit(id).unwrap().data else {
            panic!("not a login")
        };
        assert_eq!(again.password_history.len(), 1);
    }

    #[test]
    fn services_group_items_and_keep_them_from_being_orphaned() {
        let (_dir, mut backend) = unlocked();
        let mut service = Backend::empty_service("  Anthropic ");
        service.domains = vec![
            DomainRule::new("https://Console.Anthropic.com/settings/keys"),
            DomainRule::new("   "),
        ];
        let service_id = backend.save_service(service).unwrap();
        assert_eq!(backend.service(service_id).unwrap().name, "Anthropic");
        assert_eq!(
            backend.service(service_id).unwrap().domains[0].host,
            "console.anthropic.com"
        );

        let mut key = Backend::empty_item(ItemType::ApiKey);
        key.service_id = Some(service_id);
        if let ItemData::ApiKey(data) = &mut key.data {
            data.key = Secret::new("sk-1");
            data.key_id = Some("key_01".into());
        }
        let key_id = backend.save_item(key).unwrap();

        let services = backend.services().unwrap();
        assert_eq!(services[0].item_count, 1);
        let rows = backend.items().unwrap();
        assert_eq!(rows[0].service_name.as_deref(), Some("Anthropic"));
        assert_eq!(rows[0].subtitle.as_deref(), Some("key_01"));

        assert_eq!(
            backend.trash_service(service_id).unwrap_err().code,
            "service_not_empty"
        );
        backend.trash_item(key_id).unwrap();
        assert_eq!(backend.trash().unwrap().len(), 1);
        backend.trash_service(service_id).unwrap();

        let mut orphan = Backend::empty_item(ItemType::Note);
        orphan.service_id = Some(Uuid::new_v4());
        assert_eq!(backend.save_item(orphan).unwrap_err().code, "not_found");
    }

    #[test]
    fn the_trash_restores_and_empties() {
        let (_dir, mut backend) = unlocked();
        let id = backend.save_item(login("pw")).unwrap();
        backend.trash_item(id).unwrap();
        assert!(backend.items().unwrap().is_empty());
        backend.restore_item(id).unwrap();
        assert_eq!(backend.items().unwrap().len(), 1);
        assert_eq!(backend.purge_item(id).unwrap_err().code, "not_found");
        backend.trash_item(id).unwrap();
        assert_eq!(backend.empty_trash().unwrap(), 1);
        assert!(backend.trash().unwrap().is_empty());
    }

    #[test]
    fn totp_codes_come_from_logins_and_totp_items() {
        let (_dir, mut backend) = unlocked();
        let mut item = login("pw");
        if let ItemData::Login(data) = &mut item.data {
            data.totp = Some(TotpConfig {
                secret: Secret::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
                ..TotpConfig::default()
            });
        }
        let id = backend.save_item(item).unwrap();
        let now = backend.totp_now(id).unwrap();
        assert_eq!(now.code.len(), 6);
        assert!((1..=30).contains(&now.remaining));
        assert!(backend.items().unwrap()[0].has_totp);

        let key = Backend::empty_item(ItemType::ApiKey);
        let key_id = backend.save_item(key).unwrap();
        assert_eq!(backend.totp_now(key_id).unwrap_err().code, "no_totp");
        let _ = ApiKey::default();
        let _ = Login::default();
    }

    #[test]
    fn auto_lock_waits_for_the_configured_idle_time() {
        let (_dir, mut backend) = unlocked();
        let start = Instant::now();
        backend.touch();
        assert!(!backend.lock_if_idle(start + Duration::from_secs(14 * 60)));
        assert!(backend.lock_if_idle(Instant::now() + Duration::from_secs(15 * 60)));
        assert!(!backend.status().unlocked);

        backend.unlock(PASSWORD).unwrap();
        let mut never = backend.status().settings;
        never.auto_lock_minutes = 0;
        backend.save_settings(never).unwrap();
        assert!(!backend.lock_if_idle(Instant::now() + Duration::from_secs(24 * 3600)));
    }

    #[test]
    fn a_vault_it_cannot_open_is_reported_and_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(vault_path(dir.path()), b"not a vault, keep me").unwrap();
        let mut backend = Backend::open(dir.path().to_owned(), FAST);
        let status = backend.status();
        assert!(status.vault_exists);
        assert_eq!(status.problem.unwrap().code, "not_a_vault");
        assert_eq!(
            backend.create_vault(PASSWORD).unwrap_err().code,
            "vault_exists"
        );
        assert_eq!(
            fs::read(vault_path(dir.path())).unwrap(),
            b"not a vault, keep me"
        );
    }

    #[test]
    fn hosts_are_normalized() {
        assert_eq!(
            normalize_host(" HTTPS://GitHub.com/login?x=1 "),
            "github.com"
        );
        assert_eq!(normalize_host("example.org."), "example.org");
        assert_eq!(normalize_host("localhost:5173/app"), "localhost:5173");
    }

    #[test]
    fn a_csv_import_shows_a_preview_and_can_delete_its_file() {
        let (dir, mut backend) = unlocked();
        backend.save_item(login("pw-existing")).unwrap();
        let path = csv_file(
            dir.path(),
            "name,url,username,password,note\n\
             GitHub,https://github.com,octo,pw-1,\n\
             Groq,https://console.groq.com,you@example.com,pw-2,\n",
        );

        let preview = backend.import_open(path.clone()).unwrap();
        assert!(!preview.needs_password);
        assert!(preview.plaintext);
        assert_eq!(preview.source, Some(Source::Chromium));
        assert_eq!(preview.total, 2);
        assert_eq!(preview.new_services, ["GitHub", "Groq"]);
        assert_eq!(preview.counts.len(), 1);
        let json = serde_json::to_string(&preview).unwrap();
        assert!(!json.contains("pw-1"), "the preview carries no secrets");

        let result = backend.import_commit(true).unwrap();
        assert_eq!(
            (result.items, result.services, result.source_deleted),
            (2, 2, true)
        );
        assert!(!path.exists());
        assert_eq!(backend.items().unwrap().len(), 3);
        assert_eq!(backend.import_commit(false).unwrap_err().code, "no_import");
    }

    #[test]
    fn an_export_comes_back_through_import_with_its_password() {
        let (dir, mut backend) = unlocked();
        let mut service = Backend::empty_service("Anthropic");
        service.domains = vec![DomainRule::new("anthropic.com")];
        let service_id = backend.save_service(service).unwrap();
        let mut key = Backend::empty_item(ItemType::ApiKey);
        key.service_id = Some(service_id);
        if let ItemData::ApiKey(data) = &mut key.data {
            data.key = Secret::new("sk-exported");
        }
        backend.save_item(key).unwrap();
        backend.save_item(login("pw-exported")).unwrap();

        let export_path = dir.path().join("export.json");
        assert_eq!(
            backend.export_to(&export_path, "weak").unwrap_err().code,
            "password_rules"
        );
        assert!(!export_path.exists());
        backend.export_to(&export_path, EXPORT_PASSWORD).unwrap();
        let text = fs::read_to_string(&export_path).unwrap();
        assert!(!text.contains("sk-exported") && !text.contains("Anthropic"));

        let other_dir = tempfile::tempdir().unwrap();
        let mut other = Backend::open(other_dir.path().to_owned(), FAST);
        other.create_vault(PASSWORD).unwrap();
        let preview = other.import_open(export_path.clone()).unwrap();
        assert!(preview.needs_password);
        assert_eq!(
            other.import_unlock("Wrong-password-5").unwrap_err().code,
            "import_wrong_password"
        );
        let preview = other.import_unlock(EXPORT_PASSWORD).unwrap();
        assert_eq!(
            (preview.total, preview.source, preview.plaintext),
            (2, Some(Source::Krypt), false)
        );
        assert_eq!(preview.new_services, ["Anthropic"]);
        let result = other.import_commit(true).unwrap();
        assert!(
            !result.source_deleted,
            "a Krypt export is encrypted and stays"
        );
        assert!(export_path.exists());
        assert_eq!(other.services().unwrap()[0].name, "Anthropic");
        assert_eq!(other.items().unwrap().len(), 2);

        backend.import_open(export_path).unwrap();
        let again = backend.import_unlock(EXPORT_PASSWORD).unwrap();
        assert_eq!((again.total, again.duplicates), (0, 2));
    }

    #[test]
    fn locking_forgets_a_prepared_import() {
        let (dir, mut backend) = unlocked();
        let path = csv_file(
            dir.path(),
            "name,url,username,password\nX,https://x.example,u,p\n",
        );
        backend.import_open(path).unwrap();
        backend.lock();
        backend.unlock(PASSWORD).unwrap();
        assert_eq!(backend.import_commit(false).unwrap_err().code, "no_import");
    }

    #[test]
    fn files_that_hold_nothing_to_import_are_reported() {
        let (dir, mut backend) = unlocked();
        let numbers = csv_file(dir.path(), "just,some,numbers\n1,2,3\n");
        assert_eq!(
            backend.import_open(numbers).unwrap_err().code,
            "import_unknown_format"
        );
        let empty = csv_file(dir.path(), "name,url,username,password\n");
        assert_eq!(backend.import_open(empty).unwrap_err().code, "import_empty");
    }

    #[test]
    fn the_generator_needs_no_vault() {
        let generated = Backend::generate(&GeneratorOptions::default()).unwrap();
        assert_eq!(generated.value.expose().chars().count(), 20);
        assert_eq!(generated.bits, 128);
    }

    #[test]
    fn dates_for_file_names() {
        assert_eq!(date_from_days(0), "1970-01-01");
        assert_eq!(date_from_days(11_016), "2000-02-29");
        assert_eq!(date_from_days(20_711), "2026-09-15");
    }

    #[test]
    fn windows_hello_opens_the_vault_once_it_is_turned_on() {
        let (dir, mut backend) = unlocked();
        assert!(!backend.status().hello.offer, "not without Windows Hello");
        assert_eq!(
            backend.hello_enroll_request().unwrap_err().code,
            "hello_unavailable"
        );
        backend.set_hello_supported(true);
        assert!(
            backend.status().hello.offer,
            "offered after the master password was set"
        );

        let request = enroll(&mut backend);
        let hello = backend.status().hello;
        assert!(hello.enrolled && !hello.offer && !hello.password_due);
        assert!(backend.status().settings.hello_offered);
        assert!(dir.path().join("device.json").exists());

        backend.lock();
        let unlock = backend.hello_unlock_request().unwrap();
        assert_eq!(unlock.key_name, request.key_name);
        assert_eq!(unlock.challenge, request.challenge);
        backend
            .unlock_with_hello(&sign(HELLO_SECRET, &unlock))
            .unwrap();
        assert!(backend.status().unlocked);
        assert_eq!(
            backend.hello_unlock_request().unwrap_err().code,
            "already_unlocked"
        );
    }

    #[test]
    fn a_wrong_signature_leaves_the_vault_locked() {
        let (_dir, mut backend) = with_hello();
        enroll(&mut backend);
        backend.lock();
        let request = backend.hello_unlock_request().unwrap();
        assert_eq!(
            backend
                .unlock_with_hello(&sign(b"another key", &request))
                .unwrap_err()
                .code,
            "device_key_rejected"
        );
        assert_eq!(
            backend.unlock_with_hello(&[1, 2, 3]).unwrap_err().code,
            "hello_failed"
        );
        assert!(!backend.status().unlocked);
        backend.unlock(PASSWORD).unwrap();
    }

    #[test]
    fn the_master_password_comes_back_after_the_reminder_interval() {
        let (dir, mut backend) = with_hello();
        let request = enroll(&mut backend);
        backend.lock();
        age_password_unlock(dir.path(), 15);
        assert!(backend.status().hello.password_due);
        assert_eq!(
            backend.hello_unlock_request().unwrap_err().code,
            "password_due"
        );
        assert_eq!(
            backend
                .unlock_with_hello(&sign(HELLO_SECRET, &request))
                .unwrap_err()
                .code,
            "password_due"
        );

        backend.unlock(PASSWORD).unwrap();
        assert!(
            !backend.status().hello.password_due,
            "the password resets the reminder"
        );
        backend.lock();
        backend.hello_unlock_request().unwrap();

        let mut never = backend.status().settings;
        never.password_reminder_days = 0;
        backend.save_settings(never).unwrap();
        age_password_unlock(dir.path(), 400);
        backend.hello_unlock_request().unwrap();
    }

    #[test]
    fn forgetting_this_pc_removes_the_slot_and_the_file() {
        let (dir, mut backend) = with_hello();
        let request = enroll(&mut backend);
        assert_eq!(
            backend.hello_forget().unwrap(),
            Some(request.key_name.clone())
        );
        assert!(!dir.path().join("device.json").exists());
        assert!(!backend.status().hello.enrolled);
        backend.lock();
        assert_eq!(
            backend.hello_unlock_request().unwrap_err().code,
            "no_device"
        );
        assert_eq!(
            backend
                .unlock_with_hello(&sign(HELLO_SECRET, &request))
                .unwrap_err()
                .code,
            "no_device"
        );
    }

    #[test]
    fn turning_windows_hello_on_again_replaces_the_old_slot() {
        let (_dir, mut backend) = with_hello();
        let first = enroll(&mut backend);
        let second = backend.hello_enroll_request().unwrap();
        assert_eq!(
            backend
                .hello_enroll(&second, &sign(b"a new key", &second))
                .unwrap(),
            Some(first.key_name.clone())
        );
        backend.lock();
        assert_eq!(
            backend
                .unlock_with_hello(&sign(HELLO_SECRET, &first))
                .unwrap_err()
                .code,
            "device_key_rejected"
        );
        backend
            .unlock_with_hello(&sign(b"a new key", &second))
            .unwrap();
    }

    #[test]
    fn a_dismissed_offer_does_not_come_back() {
        let (_dir, mut backend) = with_hello();
        assert!(backend.status().hello.offer);
        backend.hello_dismiss().unwrap();
        assert!(!backend.status().hello.offer);
        backend.lock();
        backend.unlock(PASSWORD).unwrap();
        assert!(!backend.status().hello.offer);

        // Settings saved from the window cannot bring the offer back.
        let mut settings = backend.status().settings;
        settings.hello_offered = false;
        backend.save_settings(settings).unwrap();
        assert!(backend.status().settings.hello_offered);
    }

    #[test]
    fn a_device_file_of_another_vault_is_ignored() {
        let (dir, mut backend) = with_hello();
        let request = enroll(&mut backend);
        let mut record = DeviceRecord::load(dir.path()).unwrap();
        record.vault_id = Uuid::new_v4();
        record.save(dir.path()).unwrap();
        assert!(!backend.status().hello.enrolled);
        backend.lock();
        assert_eq!(
            backend
                .unlock_with_hello(&sign(HELLO_SECRET, &request))
                .unwrap_err()
                .code,
            "no_device"
        );
    }
}
