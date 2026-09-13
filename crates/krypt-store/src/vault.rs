use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use krypt_core::crypto::{KdfParams, Key, SALT_LEN};
use krypt_core::keyslot::{KeySlot, PasswordKdf, SlotKind};
use krypt_core::model::{Item, Service};
use krypt_core::record::{self, RecordKind};
use krypt_core::recovery::RecoveryKey;
use rusqlite::{Connection, OpenFlags, OptionalExtension, Row, params};
use uuid::Uuid;

use crate::time::now_ms;
use crate::{Error, Result, backup, schema};

/// A decrypted record with the metadata stored next to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record<T> {
    pub value: T,
    /// 1 after the first write, one more for every write after that.
    pub revision: i64,
    /// Unix time in milliseconds of the last write.
    pub updated: i64,
    /// Set while the record is in the trash.
    pub deleted_at: Option<i64>,
}

/// A vault file that is open but not unlocked. It holds no key.
pub struct LockedVault {
    conn: Connection,
    path: PathBuf,
}

/// An unlocked vault. The vault key lives here and is wiped when this is dropped or locked.
pub struct Vault {
    conn: Connection,
    path: PathBuf,
    vault_id: Uuid,
    key: Key,
}

/// Returned by [`Vault::create`]. Show the recovery key once, then drop it.
/// `Debug` prints neither key.
#[derive(Debug)]
pub struct NewVault {
    pub vault: Vault,
    pub recovery_key: RecoveryKey,
}

/// A failed unlock hands the locked vault back, so the caller can simply try again.
pub struct UnlockFailed {
    pub vault: LockedVault,
    pub error: Error,
}

/// Boxed, because a locked vault plus an error is too large to pass around by value.
pub type UnlockResult = std::result::Result<Vault, Box<UnlockFailed>>;

impl Vault {
    /// Creates a vault with a password slot and a recovery slot. Never touches an existing file.
    pub fn create(path: impl AsRef<Path>, password: &str, params: KdfParams) -> Result<NewVault> {
        let path = path.as_ref();
        if path.exists() {
            return Err(Error::AlreadyExists);
        }

        let key = Key::random()?;
        let recovery_key = RecoveryKey::generate()?;
        let password_slot = KeySlot::for_password(&key, password, params)?;
        let recovery_slot = KeySlot::for_recovery_key(&key, &recovery_key)?;
        // Both ways in are proven to work before anything is written.
        ensure_same(&password_slot.unlock_with_password(password)?, &key)?;
        ensure_same(
            &recovery_slot.unlock_with_recovery_key(&recovery_key)?,
            &key,
        )?;

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let vault_id = Uuid::new_v4();
        let written = (|| -> Result<Connection> {
            let mut conn = Connection::open(path)?;
            schema::configure(&conn)?;
            let now = now_ms();
            let tx = conn.transaction()?;
            schema::create(&tx)?;
            tx.execute(
                "INSERT INTO vault_meta (id, vault_id, created) VALUES (1, ?1, ?2)",
                params![vault_id.to_string(), now],
            )?;
            insert_slot(&tx, &password_slot, now)?;
            insert_slot(&tx, &recovery_slot, now)?;
            tx.commit()?;
            Ok(conn)
        })();

        match written {
            Ok(conn) => Ok(NewVault {
                vault: Vault {
                    conn,
                    path: path.to_owned(),
                    vault_id,
                    key,
                },
                recovery_key,
            }),
            Err(error) => {
                // The file did not exist before this call, so a half-written one can go.
                remove_vault_files(path);
                Err(error)
            }
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn vault_id(&self) -> Uuid {
        self.vault_id
    }

    /// Drops the vault key.
    pub fn lock(self) -> LockedVault {
        LockedVault {
            conn: self.conn,
            path: self.path,
        }
    }

    /// Replaces the password slot. The new slot must open the vault before the old one is
    /// removed, and the old one is then purged from the file and the write-ahead log.
    pub fn change_password(&mut self, new_password: &str, params: KdfParams) -> Result<()> {
        let slot = KeySlot::for_password(&self.key, new_password, params)?;
        ensure_same(&slot.unlock_with_password(new_password)?, &self.key)?;
        self.replace_slots(SlotKind::Password, &slot)
    }

    /// Issues a new recovery key. The old one stops working.
    pub fn replace_recovery_key(&mut self) -> Result<RecoveryKey> {
        let recovery_key = RecoveryKey::generate()?;
        let slot = KeySlot::for_recovery_key(&self.key, &recovery_key)?;
        ensure_same(&slot.unlock_with_recovery_key(&recovery_key)?, &self.key)?;
        self.replace_slots(SlotKind::Recovery, &slot)?;
        Ok(recovery_key)
    }

    /// Saves a service and returns its new revision.
    pub fn put_service(&mut self, service: &Service) -> Result<i64> {
        self.put(service)
    }

    pub fn service(&self, id: Uuid) -> Result<Option<Record<Service>>> {
        self.get(id)
    }

    /// Services not in the trash, most recently changed first.
    pub fn services(&self) -> Result<Vec<Record<Service>>> {
        self.list(false)
    }

    pub fn trashed_services(&self) -> Result<Vec<Record<Service>>> {
        self.list(true)
    }

    pub fn trash_service(&mut self, id: Uuid) -> Result<bool> {
        self.set_trashed::<Service>(id, true)
    }

    pub fn restore_service(&mut self, id: Uuid) -> Result<bool> {
        self.set_trashed::<Service>(id, false)
    }

    /// Deletes a service for good. Only works on services already in the trash.
    pub fn purge_service(&mut self, id: Uuid) -> Result<bool> {
        self.purge::<Service>(id)
    }

    /// Saves an item and returns its new revision.
    pub fn put_item(&mut self, item: &Item) -> Result<i64> {
        self.put(item)
    }

    pub fn item(&self, id: Uuid) -> Result<Option<Record<Item>>> {
        self.get(id)
    }

    /// Items not in the trash, most recently changed first.
    pub fn items(&self) -> Result<Vec<Record<Item>>> {
        self.list(false)
    }

    pub fn items_for_service(&self, service_id: Uuid) -> Result<Vec<Record<Item>>> {
        Ok(self
            .items()?
            .into_iter()
            .filter(|record| record.value.service_id == Some(service_id))
            .collect())
    }

    pub fn trashed_items(&self) -> Result<Vec<Record<Item>>> {
        self.list(true)
    }

    pub fn trash_item(&mut self, id: Uuid) -> Result<bool> {
        self.set_trashed::<Item>(id, true)
    }

    pub fn restore_item(&mut self, id: Uuid) -> Result<bool> {
        self.set_trashed::<Item>(id, false)
    }

    /// Deletes an item for good. Only works on items already in the trash.
    pub fn purge_item(&mut self, id: Uuid) -> Result<bool> {
        self.purge::<Item>(id)
    }

    /// Deletes everything that went into the trash before `before` (Unix milliseconds).
    pub fn empty_trash(&mut self, before: i64) -> Result<usize> {
        let tx = self.conn.transaction()?;
        let mut removed = 0;
        for table in [Service::TABLE, Item::TABLE] {
            removed += tx.execute(
                &format!("DELETE FROM {table} WHERE deleted_at IS NOT NULL AND deleted_at < ?1"),
                params![before],
            )?;
        }
        tx.commit()?;
        Ok(removed)
    }

    /// Writes a consistent copy to `dest`. It opens with the same password and recovery key.
    pub fn backup_to(&self, dest: impl AsRef<Path>) -> Result<()> {
        backup::copy(&self.conn, dest.as_ref())
    }

    /// Writes a copy into `backups/` next to the vault and keeps the newest `keep` copies.
    pub fn create_backup(&self, keep: usize) -> Result<PathBuf> {
        backup::rotate(&self.conn, &self.path, keep)
    }

    fn replace_slots(&mut self, kind: SlotKind, slot: &KeySlot) -> Result<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM key_slots WHERE kind = ?1",
            params![kind.as_str()],
        )?;
        insert_slot(&tx, slot, now_ms())?;
        tx.commit()?;
        self.conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    }

    fn put<T: Stored>(&mut self, value: &T) -> Result<i64> {
        let id = value.id();
        let data = value.seal(&self.key)?;
        let sql = format!(
            "INSERT INTO {} (id, revision, updated, deleted_at, data) VALUES (?1, 1, ?2, NULL, ?3)
             ON CONFLICT(id) DO UPDATE SET
                 revision = revision + 1, updated = excluded.updated, data = excluded.data
             RETURNING revision",
            T::TABLE
        );
        Ok(self
            .conn
            .query_row(&sql, params![id.to_string(), now_ms(), data], |row| {
                row.get(0)
            })?)
    }

    fn get<T: Stored>(&self, id: Uuid) -> Result<Option<Record<T>>> {
        let sql = format!(
            "SELECT id, revision, updated, deleted_at, data FROM {} WHERE id = ?1",
            T::TABLE
        );
        let raw = self
            .conn
            .query_row(&sql, params![id.to_string()], RawRecord::from_row)
            .optional()?;
        raw.map(|raw| self.decrypt(raw)).transpose()
    }

    fn list<T: Stored>(&self, trashed: bool) -> Result<Vec<Record<T>>> {
        let filter = if trashed { "IS NOT NULL" } else { "IS NULL" };
        let sql = format!(
            "SELECT id, revision, updated, deleted_at, data FROM {} WHERE deleted_at {filter}
             ORDER BY updated DESC",
            T::TABLE
        );
        let mut statement = self.conn.prepare(&sql)?;
        let raws = statement
            .query_map([], RawRecord::from_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raws.into_iter().map(|raw| self.decrypt(raw)).collect()
    }

    fn set_trashed<T: Stored>(&mut self, id: Uuid, trashed: bool) -> Result<bool> {
        let sql = if trashed {
            format!(
                "UPDATE {} SET deleted_at = ?2, updated = ?2, revision = revision + 1
                 WHERE id = ?1 AND deleted_at IS NULL",
                T::TABLE
            )
        } else {
            format!(
                "UPDATE {} SET deleted_at = NULL, updated = ?2, revision = revision + 1
                 WHERE id = ?1 AND deleted_at IS NOT NULL",
                T::TABLE
            )
        };
        Ok(self.conn.execute(&sql, params![id.to_string(), now_ms()])? == 1)
    }

    fn purge<T: Stored>(&mut self, id: Uuid) -> Result<bool> {
        let sql = format!(
            "DELETE FROM {} WHERE id = ?1 AND deleted_at IS NOT NULL",
            T::TABLE
        );
        Ok(self.conn.execute(&sql, params![id.to_string()])? == 1)
    }

    fn decrypt<T: Stored>(&self, raw: RawRecord) -> Result<Record<T>> {
        let id = Uuid::parse_str(&raw.id).map_err(|_| Error::Corrupt("record id is not a UUID"))?;
        let value = T::open(&self.key, id, &raw.data)?;
        if value.id() != id {
            return Err(Error::Corrupt("record content belongs to another id"));
        }
        Ok(Record {
            value,
            revision: raw.revision,
            updated: raw.updated,
            deleted_at: raw.deleted_at,
        })
    }
}

impl LockedVault {
    /// Opens an existing vault without unlocking it. A vault from a newer Krypt is refused
    /// before anything touches the file; an older format is copied into `backups/` and upgraded.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(Error::NotFound);
        }
        let mut conn = Connection::open_with_flags(path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
        schema::check_application_id(&conn)?;
        schema::refuse_newer(&conn, schema::MIGRATIONS)?;
        schema::configure(&conn)?;
        schema::upgrade(&mut conn, path, schema::MIGRATIONS)?;
        Ok(Self {
            conn,
            path: path.to_owned(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn unlock_with_password(self, password: &str) -> UnlockResult {
        let attempt = self.slots(SlotKind::Password).and_then(|slots| {
            for slot in slots {
                match slot.unlock_with_password(password) {
                    Ok(key) => return Ok(key),
                    Err(krypt_core::Error::Decrypt) => {}
                    Err(other) => return Err(other.into()),
                }
            }
            Err(Error::WrongPassword)
        });
        self.finish_unlock(attempt)
    }

    pub fn unlock_with_recovery_key(self, recovery_key: &RecoveryKey) -> UnlockResult {
        let attempt = self.slots(SlotKind::Recovery).and_then(|slots| {
            for slot in slots {
                match slot.unlock_with_recovery_key(recovery_key) {
                    Ok(key) => return Ok(key),
                    Err(krypt_core::Error::Decrypt) => {}
                    Err(other) => return Err(other.into()),
                }
            }
            Err(Error::WrongRecoveryKey)
        });
        self.finish_unlock(attempt)
    }

    fn finish_unlock(self, attempt: Result<Key>) -> UnlockResult {
        let key = match attempt {
            Ok(key) => key,
            Err(error) => return Err(Box::new(UnlockFailed { vault: self, error })),
        };
        match self.vault_id() {
            Ok(vault_id) => Ok(Vault {
                conn: self.conn,
                path: self.path,
                vault_id,
                key,
            }),
            Err(error) => Err(Box::new(UnlockFailed { vault: self, error })),
        }
    }

    fn slots(&self, kind: SlotKind) -> Result<Vec<KeySlot>> {
        let mut statement = self.conn.prepare(
            "SELECT id, kdf_algorithm, kdf_m_cost, kdf_t_cost, kdf_p_cost, kdf_salt, wrapped_key
             FROM key_slots WHERE kind = ?1",
        )?;
        let rows = statement
            .query_map(params![kind.as_str()], |row| {
                Ok(SlotRow {
                    id: row.get(0)?,
                    kdf_algorithm: row.get(1)?,
                    m_cost: row.get(2)?,
                    t_cost: row.get(3)?,
                    p_cost: row.get(4)?,
                    salt: row.get(5)?,
                    wrapped_key: row.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter().map(|row| row.into_slot(kind)).collect()
    }

    fn vault_id(&self) -> Result<Uuid> {
        let id: String =
            self.conn
                .query_row("SELECT vault_id FROM vault_meta WHERE id = 1", [], |row| {
                    row.get(0)
                })?;
        Uuid::parse_str(&id).map_err(|_| Error::Corrupt("vault id is not a UUID"))
    }
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("vault_id", &self.vault_id)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for LockedVault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LockedVault")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for UnlockFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnlockFailed")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for UnlockFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl std::error::Error for UnlockFailed {}

/// What the vault stores, and where.
trait Stored: Sized {
    const TABLE: &'static str;
    fn id(&self) -> Uuid;
    fn seal(&self, key: &Key) -> krypt_core::Result<Vec<u8>>;
    fn open(key: &Key, id: Uuid, data: &[u8]) -> krypt_core::Result<Self>;
}

impl Stored for Service {
    const TABLE: &'static str = "services";

    fn id(&self) -> Uuid {
        self.id
    }

    fn seal(&self, key: &Key) -> krypt_core::Result<Vec<u8>> {
        record::seal(key, RecordKind::Service, self.id, self)
    }

    fn open(key: &Key, id: Uuid, data: &[u8]) -> krypt_core::Result<Self> {
        record::open(key, RecordKind::Service, id, data)
    }
}

impl Stored for Item {
    const TABLE: &'static str = "items";

    fn id(&self) -> Uuid {
        self.id
    }

    fn seal(&self, key: &Key) -> krypt_core::Result<Vec<u8>> {
        record::seal(key, RecordKind::Item, self.id, self)
    }

    fn open(key: &Key, id: Uuid, data: &[u8]) -> krypt_core::Result<Self> {
        record::open(key, RecordKind::Item, id, data)
    }
}

struct RawRecord {
    id: String,
    revision: i64,
    updated: i64,
    deleted_at: Option<i64>,
    data: Vec<u8>,
}

impl RawRecord {
    fn from_row(row: &Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            id: row.get(0)?,
            revision: row.get(1)?,
            updated: row.get(2)?,
            deleted_at: row.get(3)?,
            data: row.get(4)?,
        })
    }
}

struct SlotRow {
    id: String,
    kdf_algorithm: Option<String>,
    m_cost: Option<i64>,
    t_cost: Option<i64>,
    p_cost: Option<i64>,
    salt: Option<Vec<u8>>,
    wrapped_key: Vec<u8>,
}

impl SlotRow {
    fn into_slot(self, kind: SlotKind) -> Result<KeySlot> {
        let id =
            Uuid::parse_str(&self.id).map_err(|_| Error::Corrupt("key slot id is not a UUID"))?;
        let kdf = match kind {
            SlotKind::Password => Some(self.password_kdf()?),
            SlotKind::Recovery | SlotKind::Device | SlotKind::Passkey => None,
        };
        Ok(KeySlot {
            id,
            kind,
            kdf,
            wrapped_key: self.wrapped_key,
        })
    }

    fn password_kdf(&self) -> Result<PasswordKdf> {
        if self.kdf_algorithm.as_deref() != Some("argon2id") {
            return Err(Error::Corrupt(
                "password slot uses an unknown key derivation",
            ));
        }
        let cost = |value: Option<i64>| {
            value
                .and_then(|v| u32::try_from(v).ok())
                .ok_or(Error::Corrupt(
                    "password slot has invalid key derivation costs",
                ))
        };
        let params = KdfParams {
            m_cost_kib: cost(self.m_cost)?,
            t_cost: cost(self.t_cost)?,
            p_cost: cost(self.p_cost)?,
        };
        let salt: [u8; SALT_LEN] = self
            .salt
            .as_deref()
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::Corrupt("password slot has an invalid salt"))?;
        Ok(PasswordKdf { params, salt })
    }
}

fn insert_slot(conn: &Connection, slot: &KeySlot, now: i64) -> Result<()> {
    let kdf = slot.kdf.as_ref();
    conn.execute(
        "INSERT INTO key_slots
             (id, kind, kdf_algorithm, kdf_m_cost, kdf_t_cost, kdf_p_cost, kdf_salt, wrapped_key, created)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            slot.id.to_string(),
            slot.kind.as_str(),
            kdf.map(|_| "argon2id"),
            kdf.map(|k| k.params.m_cost_kib),
            kdf.map(|k| k.params.t_cost),
            kdf.map(|k| k.params.p_cost),
            kdf.map(|k| k.salt.to_vec()),
            slot.wrapped_key,
            now,
        ],
    )?;
    Ok(())
}

fn ensure_same(opened: &Key, expected: &Key) -> Result<()> {
    if opened.same_as(expected) {
        Ok(())
    } else {
        Err(Error::Corrupt("a new key slot did not open the vault"))
    }
}

fn remove_vault_files(path: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        let mut name = OsString::from(path.as_os_str());
        name.push(suffix);
        let _ = fs::remove_file(PathBuf::from(name));
    }
}
