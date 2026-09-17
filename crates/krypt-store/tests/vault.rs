use std::fs;
use std::path::{Path, PathBuf};

use krypt_core::crypto::KdfParams;
use krypt_core::model::{ApiKey, DomainRule, Item, ItemData, Login, Service};
use krypt_core::recovery::RecoveryKey;
use krypt_core::secret::Secret;
use krypt_store::{BackupRetention, Error, LockedVault, Vault};
use rusqlite::{Connection, params};

/// Real parameters cost 64 MiB per unlock; the tests only need the same code path.
const FAST: KdfParams = KdfParams {
    m_cost_kib: 64,
    t_cost: 1,
    p_cost: 1,
};
const PASSWORD: &str = "correct horse battery staple";

fn new_vault(dir: &Path) -> (Vault, RecoveryKey) {
    let created = Vault::create(dir.join("vault.db"), PASSWORD, FAST).unwrap();
    (created.vault, created.recovery_key)
}

fn login(service: &Service, email: &str, password: &str) -> Item {
    let mut item = Item::new(
        ItemData::Login(Login {
            email: Some(email.into()),
            password: Secret::new(password),
            ..Login::default()
        }),
        1,
    );
    item.service_id = Some(service.id);
    item
}

fn api_key(service: &Service, label: &str, key: &str) -> Item {
    let mut item = Item::new(
        ItemData::ApiKey(ApiKey {
            key: Secret::new(key),
            ..ApiKey::default()
        }),
        1,
    );
    item.service_id = Some(service.id);
    item.label = label.into();
    item
}

fn raw(path: &Path) -> Connection {
    Connection::open(path).unwrap()
}

/// The main file plus the write-ahead log, which is where fresh writes land first.
fn bytes_on_disk(path: &Path) -> Vec<u8> {
    let mut bytes = fs::read(path).unwrap();
    let mut wal = path.as_os_str().to_owned();
    wal.push("-wal");
    if let Ok(more) = fs::read(PathBuf::from(wal)) {
        bytes.extend(more);
    }
    bytes
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[test]
fn keeps_a_service_with_an_account_and_two_keys_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = new_vault(dir.path());

    let mut anthropic = Service::new("Anthropic");
    anthropic.domains.push(DomainRule::new("anthropic.com"));
    let account = login(&anthropic, "you@example.com", "hunter2");
    let first_key = api_key(&anthropic, "Production", "sk-ant-1");
    let second_key = api_key(&anthropic, "Staging", "sk-ant-2");
    let groq = Service::new("Groq");
    let groq_key = api_key(&groq, "Personal", "gsk-1");

    vault.put_service(&anthropic).unwrap();
    vault.put_service(&groq).unwrap();
    for item in [&account, &first_key, &second_key, &groq_key] {
        vault.put_item(item).unwrap();
    }
    let path = vault.path().to_owned();
    drop(vault.lock());

    let vault = LockedVault::open(&path)
        .unwrap()
        .unlock_with_password(PASSWORD)
        .unwrap();
    assert_eq!(
        vault.service(anthropic.id).unwrap().unwrap().value,
        anthropic
    );
    assert_eq!(vault.services().unwrap().len(), 2);

    let under_anthropic: Vec<Item> = vault
        .items_for_service(anthropic.id)
        .unwrap()
        .into_iter()
        .map(|r| r.value)
        .collect();
    assert_eq!(under_anthropic.len(), 3);
    for expected in [&account, &first_key, &second_key] {
        assert!(
            under_anthropic.contains(expected),
            "{:?} missing",
            expected.label
        );
    }
    assert_eq!(vault.items_for_service(groq.id).unwrap().len(), 1);
}

#[test]
fn a_wrong_password_hands_the_locked_vault_back() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _) = new_vault(dir.path());
    let failed = vault
        .lock()
        .unlock_with_password("correct horse battery stapl")
        .unwrap_err();
    assert!(
        matches!(failed.error, Error::WrongPassword),
        "{:?}",
        failed.error
    );
    assert!(failed.vault.unlock_with_password(PASSWORD).is_ok());
}

#[test]
fn the_recovery_key_opens_the_vault_and_sets_a_new_password() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, recovery_key) = new_vault(dir.path());

    let mut vault = vault
        .lock()
        .unlock_with_recovery_key(&recovery_key)
        .unwrap();
    vault.change_password("a whole new password", FAST).unwrap();

    let failed = vault.lock().unlock_with_password(PASSWORD).unwrap_err();
    assert!(matches!(failed.error, Error::WrongPassword));
    let vault = failed
        .vault
        .unlock_with_password("a whole new password")
        .unwrap();
    assert!(vault.lock().unlock_with_recovery_key(&recovery_key).is_ok());
}

#[test]
fn a_replaced_recovery_key_stops_working() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, old_key) = new_vault(dir.path());
    let new_key = vault.replace_recovery_key().unwrap();

    let failed = vault.lock().unlock_with_recovery_key(&old_key).unwrap_err();
    assert!(matches!(failed.error, Error::WrongRecoveryKey));
    assert!(failed.vault.unlock_with_recovery_key(&new_key).is_ok());
}

#[test]
fn a_password_change_leaves_no_trace_of_the_old_slot() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = new_vault(dir.path());
    let path = vault.path().to_owned();

    let old_slot: Vec<u8> = raw(&path)
        .query_row(
            "SELECT wrapped_key FROM key_slots WHERE kind = 'password'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(
        contains(&bytes_on_disk(&path), &old_slot),
        "precondition: old slot is on disk"
    );

    vault.change_password("new password", FAST).unwrap();
    assert!(!contains(&bytes_on_disk(&path), &old_slot));
}

#[test]
fn nothing_readable_ends_up_on_disk() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, recovery_key) = new_vault(dir.path());

    let mut service = Service::new("Anthropic");
    service
        .domains
        .push(DomainRule::new("console.anthropic.com"));
    vault.put_service(&service).unwrap();
    vault
        .put_item(&login(
            &service,
            "you@example.com",
            "hunter2-plaintext-check",
        ))
        .unwrap();
    vault
        .put_item(&api_key(
            &service,
            "Deploy pipeline",
            "sk-ant-plaintext-check",
        ))
        .unwrap();

    let disk = bytes_on_disk(vault.path());
    let shown = recovery_key.to_display_string();
    let needles: [&str; 9] = [
        "Anthropic",
        "console.anthropic.com",
        "you@example.com",
        "hunter2-plaintext-check",
        "sk-ant-plaintext-check",
        "Deploy pipeline",
        "api_key",
        PASSWORD,
        shown.as_str(),
    ];
    for needle in needles {
        assert!(
            !contains(&disk, needle.as_bytes()),
            "{needle} found in the vault file"
        );
    }
}

#[test]
fn a_changed_byte_in_an_item_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = new_vault(dir.path());
    let item = api_key(&Service::new("Groq"), "Personal", "gsk-1");
    vault.put_item(&item).unwrap();

    let conn = raw(vault.path());
    let mut data: Vec<u8> = conn
        .query_row(
            "SELECT data FROM items WHERE id = ?1",
            params![item.id.to_string()],
            |row| row.get(0),
        )
        .unwrap();
    let last = data.len() - 1;
    data[last] ^= 0x01;
    conn.execute(
        "UPDATE items SET data = ?1 WHERE id = ?2",
        params![data, item.id.to_string()],
    )
    .unwrap();

    let err = vault.item(item.id).unwrap_err();
    assert!(
        matches!(err, Error::Core(krypt_core::Error::Decrypt)),
        "{err:?}"
    );
}

#[test]
fn swapping_two_items_in_the_file_is_detected() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = new_vault(dir.path());
    let groq = Service::new("Groq");
    let a = api_key(&groq, "A", "gsk-a");
    let b = api_key(&groq, "B", "gsk-b");
    vault.put_item(&a).unwrap();
    vault.put_item(&b).unwrap();

    let conn = raw(vault.path());
    let read = |id: &Item| -> Vec<u8> {
        conn.query_row(
            "SELECT data FROM items WHERE id = ?1",
            params![id.id.to_string()],
            |row| row.get(0),
        )
        .unwrap()
    };
    let (data_a, data_b) = (read(&a), read(&b));
    conn.execute(
        "UPDATE items SET data = ?1 WHERE id = ?2",
        params![data_b, a.id.to_string()],
    )
    .unwrap();
    conn.execute(
        "UPDATE items SET data = ?1 WHERE id = ?2",
        params![data_a, b.id.to_string()],
    )
    .unwrap();

    for id in [a.id, b.id] {
        assert!(matches!(
            vault.item(id).unwrap_err(),
            Error::Core(krypt_core::Error::Decrypt)
        ));
    }
}

#[test]
fn revisions_grow_and_the_trash_keeps_things_until_emptied() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = new_vault(dir.path());
    let groq = Service::new("Groq");
    let mut item = api_key(&groq, "Personal", "gsk-1");

    assert_eq!(vault.put_item(&item).unwrap(), 1);
    item.label = "Renamed".into();
    assert_eq!(vault.put_item(&item).unwrap(), 2);
    assert_eq!(vault.item(item.id).unwrap().unwrap().value.label, "Renamed");

    assert!(
        !vault.purge_item(item.id).unwrap(),
        "only trashed items can be purged"
    );
    assert!(vault.trash_item(item.id).unwrap());
    assert!(!vault.trash_item(item.id).unwrap());
    assert!(vault.items().unwrap().is_empty());
    let trashed = vault.trashed_items().unwrap();
    assert_eq!(trashed.len(), 1);
    assert!(trashed[0].deleted_at.is_some());
    assert_eq!(trashed[0].revision, 3);

    assert!(vault.restore_item(item.id).unwrap());
    assert_eq!(vault.items().unwrap().len(), 1);

    let other = api_key(&groq, "Other", "gsk-2");
    vault.put_item(&other).unwrap();
    vault.trash_item(other.id).unwrap();
    vault.trash_item(item.id).unwrap();
    assert!(vault.purge_item(item.id).unwrap());
    assert!(vault.item(item.id).unwrap().is_none());
    assert_eq!(vault.empty_trash(i64::MAX).unwrap(), 1);
    assert!(vault.trashed_items().unwrap().is_empty());
}

#[test]
fn create_never_overwrites_a_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    fs::write(&path, b"my own notes").unwrap();
    assert!(matches!(
        Vault::create(&path, PASSWORD, FAST).unwrap_err(),
        Error::AlreadyExists
    ));
    assert_eq!(fs::read(&path).unwrap(), b"my own notes");
}

#[test]
fn open_refuses_what_is_not_a_vault() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        LockedVault::open(dir.path().join("missing.db")).unwrap_err(),
        Error::NotFound
    ));

    let text = dir.path().join("text.db");
    fs::write(
        &text,
        "not a database at all, just some text that is long enough. ".repeat(10),
    )
    .unwrap();
    assert!(matches!(
        LockedVault::open(&text).unwrap_err(),
        Error::NotAVault
    ));

    let other = dir.path().join("other.db");
    raw(&other)
        .execute_batch("CREATE TABLE notes (text TEXT);")
        .unwrap();
    assert!(matches!(
        LockedVault::open(&other).unwrap_err(),
        Error::NotAVault
    ));
}

#[test]
fn a_vault_from_a_newer_krypt_is_refused_untouched() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _) = new_vault(dir.path());
    let path = vault.path().to_owned();
    drop(vault);
    raw(&path).pragma_update(None, "user_version", 99).unwrap();

    let before = fs::read(&path).unwrap();
    let err = LockedVault::open(&path).unwrap_err();
    assert!(
        matches!(
            err,
            Error::NewerFormat {
                found: 99,
                supported: 1
            }
        ),
        "{err:?}"
    );
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn absurd_costs_written_into_the_file_are_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let (vault, _) = new_vault(dir.path());
    raw(vault.path())
        .execute(
            "UPDATE key_slots SET kdf_m_cost = 4000000 WHERE kind = 'password'",
            [],
        )
        .unwrap();

    let failed = vault.lock().unlock_with_password(PASSWORD).unwrap_err();
    assert!(
        matches!(failed.error, Error::Core(krypt_core::Error::KdfParams)),
        "{:?}",
        failed.error
    );
}

#[test]
fn backups_open_like_the_original_and_rotate() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, recovery_key) = new_vault(dir.path());
    let groq = Service::new("Groq");
    vault.put_service(&groq).unwrap();

    let copy = dir.path().join("copy.db");
    vault.backup_to(&copy).unwrap();
    assert!(matches!(
        vault.backup_to(&copy).unwrap_err(),
        Error::AlreadyExists
    ));
    let restored = LockedVault::open(&copy)
        .unwrap()
        .unlock_with_password(PASSWORD)
        .unwrap();
    assert_eq!(restored.service(groq.id).unwrap().unwrap().value, groq);
    assert!(
        restored
            .lock()
            .unlock_with_recovery_key(&recovery_key)
            .is_ok()
    );

    for _ in 0..5 {
        vault
            .create_backup(BackupRetention {
                recent: 3,
                weeks: 0,
            })
            .unwrap();
    }
    let kept = fs::read_dir(dir.path().join("backups")).unwrap().count();
    assert_eq!(kept, 3);
}

#[test]
fn the_password_can_be_checked_without_changing_anything() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = new_vault(dir.path());
    assert!(vault.check_password(PASSWORD).unwrap());
    assert!(!vault.check_password("not it").unwrap());
    vault.change_password("next password", FAST).unwrap();
    assert!(!vault.check_password(PASSWORD).unwrap());
    assert!(vault.check_password("next password").unwrap());
}

#[test]
fn the_password_slot_reports_its_costs() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = new_vault(dir.path());
    assert_eq!(vault.password_kdf_params().unwrap(), Some(FAST));
    let stronger = KdfParams {
        m_cost_kib: 128,
        t_cost: 2,
        p_cost: 1,
    };
    vault.change_password(PASSWORD, stronger).unwrap();
    assert_eq!(vault.password_kdf_params().unwrap(), Some(stronger));
}

#[test]
fn many_records_are_written_in_one_go() {
    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = new_vault(dir.path());
    let github = Service::new("GitHub");
    let groq = Service::new("Groq");
    let items: Vec<Item> = (0..50)
        .map(|i| api_key(&groq, &format!("key {i}"), &format!("gsk_{i}")))
        .chain([login(&github, "you@example.com", "pw")])
        .collect();
    vault
        .put_all(&[github.clone(), groq.clone()], &items)
        .unwrap();
    let path = vault.path().to_owned();
    drop(vault);

    let vault = LockedVault::open(&path)
        .unwrap()
        .unlock_with_password(PASSWORD)
        .unwrap();
    assert_eq!(vault.services().unwrap().len(), 2);
    assert_eq!(vault.items().unwrap().len(), 51);
    assert_eq!(vault.items_for_service(groq.id).unwrap().len(), 50);
    assert_eq!(vault.items_for_service(github.id).unwrap().len(), 1);
}

#[test]
fn a_device_slot_opens_the_vault_until_it_is_removed() {
    use krypt_core::crypto::Key;
    use krypt_core::keyslot::SlotKind;

    let dir = tempfile::tempdir().unwrap();
    let (mut vault, _) = new_vault(dir.path());
    let vault_id = vault.vault_id();
    let kek = Key::random().unwrap();
    let slot_id = vault.add_external_slot(SlotKind::Device, &kek).unwrap();
    assert!(vault.has_slot(slot_id).unwrap());
    assert!(matches!(
        vault.add_external_slot(SlotKind::Password, &kek),
        Err(Error::Core(krypt_core::Error::SlotKind))
    ));
    let path = vault.path().to_owned();
    drop(vault);

    let locked = LockedVault::open(&path).unwrap();
    assert_eq!(locked.vault_id().unwrap(), vault_id);
    assert!(locked.has_slot(slot_id).unwrap());
    let failed = *locked
        .unlock_with_external_key(slot_id, &Key::random().unwrap())
        .unwrap_err();
    assert!(matches!(failed.error, Error::WrongDeviceKey));
    let failed = *failed
        .vault
        .unlock_with_external_key(uuid::Uuid::new_v4(), &kek)
        .unwrap_err();
    assert!(matches!(failed.error, Error::SlotNotFound));
    let mut vault = failed
        .vault
        .unlock_with_external_key(slot_id, &kek)
        .unwrap();
    assert_eq!(vault.items().unwrap().len(), 0);

    assert!(vault.remove_external_slot(slot_id).unwrap());
    assert!(!vault.remove_external_slot(slot_id).unwrap());
    let locked = vault.lock();
    assert!(!locked.has_slot(slot_id).unwrap());
    let failed = *locked.unlock_with_external_key(slot_id, &kek).unwrap_err();
    assert!(matches!(failed.error, Error::SlotNotFound));
    // The password still opens the vault.
    failed.vault.unlock_with_password(PASSWORD).unwrap();
}
