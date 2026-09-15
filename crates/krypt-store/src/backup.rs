//! Copies of the vault file in `backups/` next to it.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::time::{days_from_civil, now_ms, stamp};
use crate::{Error, Result};

const PREFIX: &str = "vault-";
const EXTENSION: &str = ".db";
const UPGRADE_MARK: &str = "-before-upgrade-from-v";

/// Which regular backups survive when a new one is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackupRetention {
    /// The newest copies, whatever their age. At least one is always kept.
    pub recent: usize,
    /// In addition, the newest copy of each of this many calendar weeks, newest weeks first.
    pub weeks: usize,
}

pub(crate) fn directory(vault_path: &Path) -> PathBuf {
    vault_path.with_file_name("backups")
}

/// Copies the open database through SQLite's backup API, which stays consistent while the
/// vault is in use. The copy is encrypted exactly like the original.
pub(crate) fn copy(conn: &Connection, dest: &Path) -> Result<()> {
    if dest.exists() {
        return Err(Error::AlreadyExists);
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)?;
    }
    conn.backup(rusqlite::MAIN_DB, dest, None)?;
    Ok(())
}

/// Taken before a format upgrade. Never pruned.
pub(crate) fn before_upgrade(
    conn: &Connection,
    vault_path: &Path,
    from_version: i32,
) -> Result<PathBuf> {
    let dest = free_name(
        &directory(vault_path),
        &format!("{UPGRADE_MARK}{from_version}"),
    );
    copy(conn, &dest)?;
    Ok(dest)
}

/// Writes a regular backup, then prunes older ones by `retention`.
pub(crate) fn rotate(
    conn: &Connection,
    vault_path: &Path,
    retention: BackupRetention,
) -> Result<PathBuf> {
    let dir = directory(vault_path);
    let dest = free_name(&dir, "");
    copy(conn, &dest)?;
    prune(&dir, retention)?;
    Ok(dest)
}

/// Deletes regular backups that are neither among the newest `recent` nor the newest copy of
/// one of the last `weeks` weeks that have a copy. Copies taken before an upgrade and any other
/// file stay untouched.
pub(crate) fn prune(dir: &Path, retention: BackupRetention) -> Result<()> {
    let mut regular: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| is_regular_backup(path))
        .collect();
    // Names start with a UTC timestamp, so sorting by name sorts by age. Newest first.
    regular.sort();
    regular.reverse();

    let mut keep: HashSet<&PathBuf> = regular.iter().take(retention.recent.max(1)).collect();
    let mut weeks_seen: Vec<i64> = Vec::new();
    for path in &regular {
        let Some(week) = week_of(path) else { continue };
        if weeks_seen.contains(&week) {
            continue;
        }
        if weeks_seen.len() == retention.weeks {
            break;
        }
        weeks_seen.push(week);
        keep.insert(path);
    }

    for path in &regular {
        if !keep.contains(&path) {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

/// `vault-20260913-182005-123-00.db`, counting up if several copies land in one millisecond.
fn free_name(dir: &Path, mark: &str) -> PathBuf {
    let base = stamp(now_ms());
    (0..)
        .map(|n| dir.join(format!("{PREFIX}{base}-{n:02}{mark}{EXTENSION}")))
        .find(|path| !path.exists())
        .expect("an unused backup name")
}

fn is_regular_backup(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.starts_with(PREFIX) && name.ends_with(EXTENSION) && !name.contains(UPGRADE_MARK)
        })
}

/// The week a backup was written in, read from its file name. Weeks start on Monday.
fn week_of(path: &Path) -> Option<i64> {
    let name = path.file_name()?.to_str()?;
    let date = name.strip_prefix(PREFIX)?.get(..8)?;
    if !date.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let year: i64 = date[..4].parse().ok()?;
    let month: u32 = date[4..6].parse().ok()?;
    let day: u32 = date[6..8].parse().ok()?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    // 1970-01-01 was a Thursday; three days later every bucket starts on a Monday.
    Some((days_from_civil(year, month, day) + 3).div_euclid(7))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create(dir: &Path, names: &[&str]) {
        for name in names {
            fs::write(dir.join(name), b"").unwrap();
        }
    }

    fn remaining(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn keeps_the_newest_copies_and_one_per_week() {
        let dir = tempfile::tempdir().unwrap();
        create(
            dir.path(),
            &[
                "vault-20260803-100000-000-00.db",
                "vault-20260805-100000-000-00.db",
                "vault-20260817-100000-000-00.db",
                "vault-20260831-100000-000-00.db",
                "vault-20260906-100000-000-00.db",
                "vault-20260910-090000-000-00.db",
                "vault-20260911-090000-000-00.db",
                "vault-20260912-090000-000-00.db",
                "vault-20260913-090000-000-00.db",
                "vault-20260801-100000-000-00-before-upgrade-from-v1.db",
                "notes.txt",
            ],
        );
        prune(
            dir.path(),
            BackupRetention {
                recent: 2,
                weeks: 3,
            },
        )
        .unwrap();
        assert_eq!(
            remaining(dir.path()),
            [
                "notes.txt",
                "vault-20260801-100000-000-00-before-upgrade-from-v1.db",
                // Newest of the week of 17 August.
                "vault-20260817-100000-000-00.db",
                // Newest of the week of 31 August (Sunday 6 September).
                "vault-20260906-100000-000-00.db",
                // The two newest; 13 September also stands for its week.
                "vault-20260912-090000-000-00.db",
                "vault-20260913-090000-000-00.db",
            ]
        );
    }

    #[test]
    fn without_weeks_only_the_newest_stay_and_never_none() {
        let dir = tempfile::tempdir().unwrap();
        create(
            dir.path(),
            &[
                "vault-20260910-090000-000-00.db",
                "vault-20260911-090000-000-00.db",
            ],
        );
        prune(
            dir.path(),
            BackupRetention {
                recent: 0,
                weeks: 0,
            },
        )
        .unwrap();
        assert_eq!(remaining(dir.path()), ["vault-20260911-090000-000-00.db"]);
    }

    #[test]
    fn weeks_start_on_monday() {
        let week = |name: &str| week_of(Path::new(name)).unwrap();
        assert_eq!(
            week("vault-20260831-000000-000-00.db"),
            week("vault-20260906-235959-999-00.db")
        );
        assert_eq!(
            week("vault-20260907-000000-000-00.db"),
            week("vault-20260906-000000-000-00.db") + 1
        );
        assert_eq!(week_of(Path::new("vault-2026ab13-000000-000-00.db")), None);
        assert_eq!(week_of(Path::new("vault-20261313-000000-000-00.db")), None);
    }
}
