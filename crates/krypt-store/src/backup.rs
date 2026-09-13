//! Copies of the vault file in `backups/` next to it.

use std::fs;
use std::path::{Path, PathBuf};

use rusqlite::Connection;

use crate::time::{now_ms, stamp};
use crate::{Error, Result};

const PREFIX: &str = "vault-";
const EXTENSION: &str = ".db";
const UPGRADE_MARK: &str = "-before-upgrade-from-v";

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

/// Taken before a format upgrade. Never rotated away.
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

/// A regular backup. Keeps the newest `keep` regular backups, at least one.
pub(crate) fn rotate(conn: &Connection, vault_path: &Path, keep: usize) -> Result<PathBuf> {
    let dir = directory(vault_path);
    let dest = free_name(&dir, "");
    copy(conn, &dest)?;

    let mut regular: Vec<PathBuf> = fs::read_dir(&dir)?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| is_regular_backup(path))
        .collect();
    regular.sort();
    let excess = regular.len().saturating_sub(keep.max(1));
    for old in &regular[..excess] {
        fs::remove_file(old)?;
    }
    Ok(dest)
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
