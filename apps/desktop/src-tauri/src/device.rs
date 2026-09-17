//! `device.json`: what this PC needs to open the vault with Windows Hello. It lives next to
//! `settings.json`, never inside the vault and never in a sync. Nothing in it is secret: without
//! the key Windows Hello keeps, the challenge is worthless.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AppError, AppResult};

const FILE: &str = "device.json";
const VERSION: u32 = 1;
pub const CHALLENGE_LEN: usize = 32;
const DAY_MS: i64 = 86_400_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub version: u32,
    pub vault_id: Uuid,
    /// The vault's key slot of kind "device".
    pub slot_id: Uuid,
    /// Name of the key Windows Hello keeps for Krypt.
    pub key_name: String,
    /// What Windows Hello signs to rebuild the slot's key. Random per enrollment.
    pub challenge: Vec<u8>,
    /// Unix time in milliseconds.
    pub enrolled_at: i64,
    /// Unix time in milliseconds of the last unlock with the master password.
    pub last_password_unlock: i64,
}

impl DeviceRecord {
    pub fn new(
        vault_id: Uuid,
        slot_id: Uuid,
        key_name: String,
        challenge: Vec<u8>,
        now: i64,
        last_password_unlock: i64,
    ) -> Self {
        Self {
            version: VERSION,
            vault_id,
            slot_id,
            key_name,
            challenge,
            enrolled_at: now,
            last_password_unlock,
        }
    }

    /// None if there is no file or it cannot be used.
    pub fn load(dir: &Path) -> Option<Self> {
        let record: Self = serde_json::from_slice(&fs::read(dir.join(FILE)).ok()?).ok()?;
        (record.version == VERSION
            && record.challenge.len() == CHALLENGE_LEN
            && !record.key_name.is_empty())
        .then_some(record)
    }

    /// Writes to a temporary file first, like the settings.
    pub fn save(&self, dir: &Path) -> AppResult<()> {
        let io = |_| AppError::new("io");
        fs::create_dir_all(dir).map_err(io)?;
        let json = serde_json::to_vec_pretty(self).map_err(|_| AppError::new("internal"))?;
        let temporary = dir.join("device.json.tmp");
        fs::write(&temporary, json).map_err(io)?;
        fs::rename(&temporary, dir.join(FILE)).map_err(io)?;
        Ok(())
    }

    pub fn remove(dir: &Path) -> AppResult<()> {
        match fs::remove_file(dir.join(FILE)) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
            Err(_) => Err(AppError::new("io")),
        }
    }

    /// Whether the master password is asked for again instead of Windows Hello. A reminder
    /// against forgetting it, not a lock against attackers: anyone who can edit this file can
    /// already use the Windows account.
    pub fn password_due(&self, reminder_days: u32, now: i64) -> bool {
        reminder_days != 0
            && now.saturating_sub(self.last_password_unlock) >= i64::from(reminder_days) * DAY_MS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> DeviceRecord {
        DeviceRecord::new(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "dev.imkirit.krypt.test".into(),
            vec![7; CHALLENGE_LEN],
            1_000,
            1_000,
        )
    }

    #[test]
    fn saves_loads_and_removes() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(DeviceRecord::load(dir.path()), None);
        let record = record();
        record.save(dir.path()).unwrap();
        assert_eq!(DeviceRecord::load(dir.path()), Some(record));
        DeviceRecord::remove(dir.path()).unwrap();
        assert_eq!(DeviceRecord::load(dir.path()), None);
        DeviceRecord::remove(dir.path()).unwrap();
    }

    #[test]
    fn unusable_files_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(FILE), b"{ not json").unwrap();
        assert_eq!(DeviceRecord::load(dir.path()), None);

        let mut short = record();
        short.challenge = vec![1; 4];
        short.save(dir.path()).unwrap();
        assert_eq!(DeviceRecord::load(dir.path()), None);

        let mut newer = record();
        newer.version = 2;
        newer.save(dir.path()).unwrap();
        assert_eq!(DeviceRecord::load(dir.path()), None);
    }

    #[test]
    fn the_password_is_due_after_the_reminder_interval() {
        let record = record();
        let day = DAY_MS;
        assert!(!record.password_due(14, 1_000 + 14 * day - 1));
        assert!(record.password_due(14, 1_000 + 14 * day));
        assert!(
            !record.password_due(0, 1_000 + 3_650 * day),
            "0 means never"
        );
        assert!(
            !record.password_due(14, 0),
            "a clock set backwards is not due"
        );
    }
}
