use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{AppError, AppResult};

const FILE: &str = "settings.json";

/// Preferences that are not secret, stored next to the vault as plain JSON.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// "en" or "de". Empty until the user picks one; the interface then follows the system.
    pub language: Option<String>,
    /// Minutes without activity before the vault locks. 0 turns it off.
    pub auto_lock_minutes: u32,
    /// Seconds before a copied value is removed from the clipboard.
    pub clipboard_clear_seconds: u32,
    /// Also lock when the Windows session locks or the computer goes to sleep.
    pub lock_with_windows: bool,
    /// Krypt offers Windows Hello once after an unlock with the master password; this remembers
    /// that it did, whatever the answer was.
    pub hello_offered: bool,
    /// Days after which a PC with Windows Hello asks for the master password again. 0 never.
    pub password_reminder_days: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            language: None,
            auto_lock_minutes: 15,
            clipboard_clear_seconds: 30,
            lock_with_windows: true,
            hello_offered: false,
            password_reminder_days: 14,
        }
    }
}

impl Settings {
    /// Falls back to the defaults if the file is missing or unreadable.
    pub fn load(dir: &Path) -> Self {
        fs::read(dir.join(FILE))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Settings>(&bytes).ok())
            .map(Settings::sanitized)
            .unwrap_or_default()
    }

    pub fn sanitized(mut self) -> Self {
        if !matches!(self.language.as_deref(), None | Some("en") | Some("de")) {
            self.language = None;
        }
        self.auto_lock_minutes = self.auto_lock_minutes.min(24 * 60);
        self.clipboard_clear_seconds = self.clipboard_clear_seconds.clamp(5, 600);
        self.password_reminder_days = self.password_reminder_days.min(365);
        self
    }

    /// Writes to a temporary file first, so a crash never leaves half a settings file.
    pub fn save(&self, dir: &Path) -> AppResult<()> {
        let io = |_| AppError::new("io");
        fs::create_dir_all(dir).map_err(io)?;
        let json = serde_json::to_vec_pretty(self).map_err(|_| AppError::new("internal"))?;
        let temporary = dir.join("settings.json.tmp");
        fs::write(&temporary, json).map_err(io)?;
        fs::rename(&temporary, dir.join(FILE)).map_err(io)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_loads_and_repairs_values() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Settings::load(dir.path()), Settings::default());

        let settings = Settings {
            language: Some("de".into()),
            auto_lock_minutes: 5,
            clipboard_clear_seconds: 45,
            lock_with_windows: false,
            hello_offered: true,
            password_reminder_days: 30,
        };
        settings.save(dir.path()).unwrap();
        assert_eq!(Settings::load(dir.path()), settings);

        let odd = Settings {
            language: Some("fr".into()),
            auto_lock_minutes: 100_000,
            clipboard_clear_seconds: 0,
            password_reminder_days: 10_000,
            ..Settings::default()
        }
        .sanitized();
        assert_eq!(odd.language, None);
        assert_eq!(odd.auto_lock_minutes, 1440);
        assert_eq!(odd.clipboard_clear_seconds, 5);
        assert_eq!(odd.password_reminder_days, 365);
    }

    #[test]
    fn a_file_from_an_older_build_keeps_its_values_and_gets_new_defaults() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join(FILE),
            br#"{ "language": "de", "auto_lock_minutes": 5, "clipboard_clear_seconds": 60 }"#,
        )
        .unwrap();
        let loaded = Settings::load(dir.path());
        assert_eq!(loaded.language.as_deref(), Some("de"));
        assert_eq!(loaded.auto_lock_minutes, 5);
        assert!(loaded.lock_with_windows);
        assert!(!loaded.hello_offered);
        assert_eq!(loaded.password_reminder_days, 14);
    }

    #[test]
    fn a_broken_file_falls_back_to_defaults() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(FILE), b"{ not json").unwrap();
        assert_eq!(Settings::load(dir.path()), Settings::default());
    }
}
