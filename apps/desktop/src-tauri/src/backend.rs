//! Everything the window can ask for, kept free of Tauri so it can be tested directly.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use krypt_core::crypto::KdfParams;
use krypt_core::model::{Item, ItemData, ItemType, PasswordChange, Service};
use krypt_core::recovery::RecoveryKey;
use krypt_core::secret::{self, MASKED};
use krypt_core::totp::TotpConfig;
use krypt_store::{BackupRetention, LockedVault, Record, Vault};
use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::error::{AppError, AppResult};
use crate::settings::Settings;

/// Shortest master password the app accepts.
pub const MIN_PASSWORD_CHARS: usize = 12;
const PASSWORD_HISTORY_KEPT: usize = 20;
/// The ten newest copies, plus the newest copy of each of the last eight weeks.
const BACKUPS: BackupRetention = BackupRetention {
    recent: 10,
    weeks: 8,
};

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
        }
    }

    pub fn status(&self) -> Status {
        Status {
            vault_exists: vault_path(&self.data_dir).exists(),
            unlocked: matches!(self.slot, VaultSlot::Unlocked(_)),
            problem: self.problem.clone(),
            backup_failed: self.backup_failed,
            settings: self.settings.clone(),
            min_password_chars: MIN_PASSWORD_CHARS,
        }
    }

    /// Creates the vault and returns the recovery key, formatted to be shown once.
    pub fn create_vault(&mut self, password: &str) -> AppResult<Zeroizing<String>> {
        check_length(password)?;
        if !matches!(self.slot, VaultSlot::Missing) || self.problem.is_some() {
            return Err(AppError::new("vault_exists"));
        }
        let created = Vault::create(vault_path(&self.data_dir), password, self.kdf)?;
        let shown = created.recovery_key.to_display_string();
        // A brand-new vault has nothing worth a backup yet.
        self.backed_up = true;
        self.slot = VaultSlot::Unlocked(created.vault);
        self.touch();
        Ok(shown)
    }

    pub fn unlock(&mut self, password: &str) -> AppResult<()> {
        let locked = self.take_locked()?;
        match locked.unlock_with_password(password) {
            Ok(mut vault) => {
                self.strengthen(&mut vault, password);
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

    /// Opens the vault with the recovery key and sets a new master password.
    pub fn recover(&mut self, recovery_key: &str, new_password: &str) -> AppResult<()> {
        check_length(new_password)?;
        let key = RecoveryKey::parse(recovery_key)?;
        let locked = self.take_locked()?;
        match locked.unlock_with_recovery_key(&key) {
            Ok(mut vault) => {
                let changed = vault.change_password(new_password, self.kdf);
                self.finish_unlock(vault);
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
        check_length(new_password)?;
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

    pub fn clipboard_clear_after(&self) -> Duration {
        Duration::from_secs(u64::from(self.settings.clipboard_clear_seconds))
    }

    pub fn save_settings(&mut self, settings: Settings) -> AppResult<Settings> {
        let settings = settings.sanitized();
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

pub fn vault_path(data_dir: &Path) -> PathBuf {
    data_dir.join("vault.db")
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
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

fn check_length(password: &str) -> AppResult<()> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        Err(AppError::new("password_too_short"))
    } else {
        Ok(())
    }
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
    use krypt_core::secret::Secret;

    use super::*;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    const PASSWORD: &str = "correct horse battery";

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
        assert_eq!(
            backend.create_vault("short").unwrap_err().code,
            "password_too_short"
        );

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
        assert_eq!(
            std::fs::read_dir(dir.path().join("backups"))
                .unwrap()
                .count(),
            1
        );
        assert!(!next_start.status().backup_failed);
    }

    #[test]
    fn the_recovery_key_sets_a_new_password() {
        let dir = tempfile::tempdir().unwrap();
        let mut backend = Backend::open(dir.path().to_owned(), FAST);
        let recovery_key = backend.create_vault(PASSWORD).unwrap();
        backend.lock();

        assert_eq!(
            backend
                .recover("not a key", "a brand new password")
                .unwrap_err()
                .code,
            "invalid_recovery_key"
        );
        backend
            .recover(&recovery_key.to_lowercase(), "a brand new password")
            .unwrap();
        backend.lock();
        assert_eq!(backend.unlock(PASSWORD).unwrap_err().code, "wrong_password");
        backend.unlock("a brand new password").unwrap();
    }

    #[test]
    fn changing_the_password_needs_the_current_one() {
        let (_dir, mut backend) = unlocked();
        assert_eq!(
            backend
                .change_password("guess guess guess", "another good password")
                .unwrap_err()
                .code,
            "wrong_password"
        );
        backend
            .change_password(PASSWORD, "another good password")
            .unwrap();
        backend.lock();
        backend.unlock("another good password").unwrap();
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
        std::fs::write(vault_path(dir.path()), b"not a vault, keep me").unwrap();
        let mut backend = Backend::open(dir.path().to_owned(), FAST);
        let status = backend.status();
        assert!(status.vault_exists);
        assert_eq!(status.problem.unwrap().code, "not_a_vault");
        assert_eq!(
            backend.create_vault(PASSWORD).unwrap_err().code,
            "vault_exists"
        );
        assert_eq!(
            std::fs::read(vault_path(dir.path())).unwrap(),
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
}
