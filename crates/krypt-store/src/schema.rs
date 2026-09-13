//! The vault file format and its migrations.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rusqlite::{Connection, ErrorCode, Transaction};

use crate::{Error, Result, backup};

/// "KRYP" in ASCII, written into the SQLite header so other databases are refused.
pub(crate) const APPLICATION_ID: i32 = 0x4B52_5950;

pub(crate) struct Migration {
    pub version: i32,
    pub sql: &'static str,
}

/// Every format change is a new entry. Released entries are never edited.
pub(crate) const MIGRATIONS: &[Migration] = &[Migration {
    version: 1,
    sql: V1,
}];

const V1: &str = "
CREATE TABLE vault_meta (
    id       INTEGER PRIMARY KEY CHECK (id = 1),
    vault_id TEXT    NOT NULL,
    created  INTEGER NOT NULL
);

CREATE TABLE key_slots (
    id            TEXT    PRIMARY KEY,
    kind          TEXT    NOT NULL,
    kdf_algorithm TEXT,
    kdf_m_cost    INTEGER,
    kdf_t_cost    INTEGER,
    kdf_p_cost    INTEGER,
    kdf_salt      BLOB,
    wrapped_key   BLOB    NOT NULL,
    created       INTEGER NOT NULL
);

CREATE TABLE services (
    id         TEXT    PRIMARY KEY,
    revision   INTEGER NOT NULL,
    updated    INTEGER NOT NULL,
    deleted_at INTEGER,
    data       BLOB    NOT NULL
);

CREATE TABLE items (
    id         TEXT    PRIMARY KEY,
    revision   INTEGER NOT NULL,
    updated    INTEGER NOT NULL,
    deleted_at INTEGER,
    data       BLOB    NOT NULL
);
";

pub(crate) fn latest_version(migrations: &[Migration]) -> i32 {
    migrations.last().map_or(0, |m| m.version)
}

/// Durability over speed: a lost write in a password manager is a lost password.
pub(crate) fn configure(conn: &Connection) -> Result<()> {
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update_and_check(None, "journal_mode", "WAL", |row| row.get::<_, String>(0))?;
    conn.pragma_update(None, "synchronous", "FULL")?;
    // Deleted content is overwritten, so an old key slot does not survive a password change.
    conn.pragma_update_and_check(None, "secure_delete", "ON", |row| row.get::<_, i64>(0))?;
    Ok(())
}

pub(crate) fn user_version(conn: &Connection) -> Result<i32> {
    Ok(conn.pragma_query_value(None, "user_version", |row| row.get(0))?)
}

pub(crate) fn check_application_id(conn: &Connection) -> Result<()> {
    match conn.pragma_query_value(None, "application_id", |row| row.get::<_, i32>(0)) {
        Ok(APPLICATION_ID) => Ok(()),
        Ok(_) => Err(Error::NotAVault),
        Err(rusqlite::Error::SqliteFailure(e, _)) if e.code == ErrorCode::NotADatabase => {
            Err(Error::NotAVault)
        }
        Err(e) => Err(e.into()),
    }
}

/// Lays out a brand-new vault inside the caller's transaction.
pub(crate) fn create(tx: &Transaction<'_>) -> Result<()> {
    for migration in MIGRATIONS {
        tx.execute_batch(migration.sql)?;
    }
    tx.pragma_update(None, "user_version", latest_version(MIGRATIONS))?;
    tx.pragma_update(None, "application_id", APPLICATION_ID)?;
    Ok(())
}

/// Refuses a vault written by a newer build before anything else touches the file.
pub(crate) fn refuse_newer(conn: &Connection, migrations: &[Migration]) -> Result<()> {
    let found = user_version(conn)?;
    let supported = latest_version(migrations);
    if found > supported {
        return Err(Error::NewerFormat { found, supported });
    }
    Ok(())
}

/// Brings an existing vault up to the newest format, copying it into `backups/` first.
/// Returns the path of that copy if anything changed.
pub(crate) fn upgrade(
    conn: &mut Connection,
    vault_path: &Path,
    migrations: &[Migration],
) -> Result<Option<PathBuf>> {
    refuse_newer(conn, migrations)?;
    let current = user_version(conn)?;
    if current == 0 {
        return Err(Error::NotAVault);
    }
    if current == latest_version(migrations) {
        return Ok(None);
    }
    let copy = backup::before_upgrade(conn, vault_path, current)?;
    for migration in migrations.iter().filter(|m| m.version > current) {
        let tx = conn.transaction()?;
        tx.execute_batch(migration.sql)?;
        tx.pragma_update(None, "user_version", migration.version)?;
        tx.commit()?;
    }
    Ok(Some(copy))
}

#[cfg(test)]
mod tests {
    use krypt_core::crypto::KdfParams;

    use super::*;
    use crate::vault::{LockedVault, Vault};

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn an_upgrade_copies_the_vault_before_changing_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        drop(Vault::create(&path, "pw", FAST).unwrap());

        let with_v2 = [
            Migration {
                version: 1,
                sql: V1,
            },
            Migration {
                version: 2,
                sql: "CREATE TABLE added_later (x INTEGER);",
            },
        ];
        let mut conn = Connection::open(&path).unwrap();
        let copy = upgrade(&mut conn, &path, &with_v2)
            .unwrap()
            .expect("a backup copy");

        assert_eq!(user_version(&conn).unwrap(), 2);
        assert!(copy.starts_with(dir.path().join("backups")));
        assert_eq!(user_version(&Connection::open(&copy).unwrap()).unwrap(), 1);
        assert!(upgrade(&mut conn, &path, &with_v2).unwrap().is_none());
        drop(conn);

        // The copy is a complete vault of the old format.
        assert!(
            LockedVault::open(&copy)
                .unwrap()
                .unlock_with_password("pw")
                .is_ok()
        );
    }
}
