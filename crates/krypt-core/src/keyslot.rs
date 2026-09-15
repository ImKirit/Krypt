//! Key slots: every way into a vault holds its own encrypted copy of the vault key.
//!
//! The vault key never changes. Adding a way in (a new device, a passkey) adds a slot,
//! changing the master password rewrites one slot, and no entry is re-encrypted for either.

use uuid::Uuid;
use zeroize::Zeroize;

use crate::crypto::{self, KEY_LEN, KdfParams, Key, SALT_LEN};
use crate::recovery::RecoveryKey;
use crate::{Error, Result};

const INFO_PASSWORD: &str = "krypt/v1/kek/password";
const INFO_RECOVERY: &str = "krypt/v1/kek/recovery";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SlotKind {
    /// Opened with the master password through Argon2id.
    Password,
    /// Opened with the recovery key shown once at setup.
    Recovery,
    /// Opened with a key the operating system keeps for this device.
    Device,
    /// Opened with the PRF output of a passkey.
    Passkey,
}

impl SlotKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SlotKind::Password => "password",
            SlotKind::Recovery => "recovery",
            SlotKind::Device => "device",
            SlotKind::Passkey => "passkey",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "password" => Some(SlotKind::Password),
            "recovery" => Some(SlotKind::Recovery),
            "device" => Some(SlotKind::Device),
            "passkey" => Some(SlotKind::Passkey),
            _ => None,
        }
    }
}

/// Argon2id settings of a password slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PasswordKdf {
    pub params: KdfParams,
    pub salt: [u8; SALT_LEN],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySlot {
    pub id: Uuid,
    pub kind: SlotKind,
    /// Present for password slots only.
    pub kdf: Option<PasswordKdf>,
    /// The vault key, sealed with this slot's key-encryption key.
    pub wrapped_key: Vec<u8>,
}

impl KeySlot {
    pub fn for_password(vault_key: &Key, password: &str, params: KdfParams) -> Result<Self> {
        let mut salt = [0u8; SALT_LEN];
        crypto::random_bytes(&mut salt)?;
        let kdf = PasswordKdf { params, salt };
        let kek = password_kek(password, &kdf)?;
        Self::wrap(SlotKind::Password, Some(kdf), vault_key, &kek)
    }

    pub fn for_recovery_key(vault_key: &Key, recovery_key: &RecoveryKey) -> Result<Self> {
        let kek = crypto::derive_key(recovery_key.as_bytes(), INFO_RECOVERY)?;
        Self::wrap(SlotKind::Recovery, None, vault_key, &kek)
    }

    /// For slots whose key-encryption key comes from outside the core: a device key held by
    /// the operating system, or a passkey PRF output passed through [`crypto::derive_key`].
    pub fn for_external_key(kind: SlotKind, vault_key: &Key, kek: &Key) -> Result<Self> {
        match kind {
            SlotKind::Device | SlotKind::Passkey => Self::wrap(kind, None, vault_key, kek),
            SlotKind::Password | SlotKind::Recovery => Err(Error::SlotKind),
        }
    }

    pub fn unlock_with_password(&self, password: &str) -> Result<Key> {
        let kdf = match (self.kind, &self.kdf) {
            (SlotKind::Password, Some(kdf)) => kdf,
            _ => return Err(Error::SlotKind),
        };
        let kek = password_kek(password, kdf)?;
        self.unwrap(&kek)
    }

    pub fn unlock_with_recovery_key(&self, recovery_key: &RecoveryKey) -> Result<Key> {
        if self.kind != SlotKind::Recovery {
            return Err(Error::SlotKind);
        }
        let kek = crypto::derive_key(recovery_key.as_bytes(), INFO_RECOVERY)?;
        self.unwrap(&kek)
    }

    pub fn unlock_with_external_key(&self, kek: &Key) -> Result<Key> {
        match self.kind {
            SlotKind::Device | SlotKind::Passkey => self.unwrap(kek),
            SlotKind::Password | SlotKind::Recovery => Err(Error::SlotKind),
        }
    }

    fn wrap(kind: SlotKind, kdf: Option<PasswordKdf>, vault_key: &Key, kek: &Key) -> Result<Self> {
        let id = Uuid::new_v4();
        let wrapped_key = crypto::seal(kek, vault_key.as_bytes(), &aad(kind, id))?;
        Ok(Self {
            id,
            kind,
            kdf,
            wrapped_key,
        })
    }

    fn unwrap(&self, kek: &Key) -> Result<Key> {
        let bytes = crypto::open(kek, &self.wrapped_key, &aad(self.kind, self.id))?;
        let mut array: [u8; KEY_LEN] = bytes.as_slice().try_into().map_err(|_| Error::Decrypt)?;
        let key = Key::from_bytes(array);
        array.zeroize();
        Ok(key)
    }
}

fn aad(kind: SlotKind, id: Uuid) -> Vec<u8> {
    format!("krypt/v1/keyslot/{}/{}", kind.as_str(), id).into_bytes()
}

fn password_kek(password: &str, kdf: &PasswordKdf) -> Result<Key> {
    let normalized = crate::password::normalize(password);
    let master = crypto::argon2id(normalized.as_bytes(), &kdf.salt, kdf.params)?;
    crypto::derive_key(master.as_bytes(), INFO_PASSWORD)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };

    #[test]
    fn password_slot_opens_with_the_right_password_only() {
        let vault_key = Key::random().unwrap();
        let slot = KeySlot::for_password(&vault_key, "correct horse", FAST).unwrap();
        assert!(
            slot.unlock_with_password("correct horse")
                .unwrap()
                .same_as(&vault_key)
        );
        assert_eq!(
            slot.unlock_with_password("correct horsE").unwrap_err(),
            Error::Decrypt
        );
        assert_eq!(slot.unlock_with_password("").unwrap_err(), Error::Decrypt);
    }

    #[test]
    fn composed_and_decomposed_accents_open_the_same_slot() {
        let vault_key = Key::random().unwrap();
        let slot = KeySlot::for_password(&vault_key, "caf\u{e9}", FAST).unwrap();
        assert!(
            slot.unlock_with_password("cafe\u{301}")
                .unwrap()
                .same_as(&vault_key)
        );
    }

    #[test]
    fn two_slots_for_the_same_password_differ() {
        let vault_key = Key::random().unwrap();
        let a = KeySlot::for_password(&vault_key, "pw", FAST).unwrap();
        let b = KeySlot::for_password(&vault_key, "pw", FAST).unwrap();
        assert_ne!(a.kdf.unwrap().salt, b.kdf.unwrap().salt);
        assert_ne!(a.wrapped_key, b.wrapped_key);
    }

    #[test]
    fn recovery_slot_opens_with_its_recovery_key_only() {
        let vault_key = Key::random().unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        let slot = KeySlot::for_recovery_key(&vault_key, &recovery_key).unwrap();
        assert!(
            slot.unlock_with_recovery_key(&recovery_key)
                .unwrap()
                .same_as(&vault_key)
        );
        let other = RecoveryKey::generate().unwrap();
        assert_eq!(
            slot.unlock_with_recovery_key(&other).unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn device_and_passkey_slots_use_the_given_key() {
        let vault_key = Key::random().unwrap();
        let device_key = Key::random().unwrap();
        let slot = KeySlot::for_external_key(SlotKind::Device, &vault_key, &device_key).unwrap();
        assert!(
            slot.unlock_with_external_key(&device_key)
                .unwrap()
                .same_as(&vault_key)
        );
        assert_eq!(
            KeySlot::for_external_key(SlotKind::Password, &vault_key, &device_key).unwrap_err(),
            Error::SlotKind
        );
    }

    #[test]
    fn a_slot_is_bound_to_its_id_and_kind() {
        let vault_key = Key::random().unwrap();
        let kek = Key::random().unwrap();
        let slot = KeySlot::for_external_key(SlotKind::Device, &vault_key, &kek).unwrap();

        let mut moved = slot.clone();
        moved.id = Uuid::new_v4();
        assert_eq!(
            moved.unlock_with_external_key(&kek).unwrap_err(),
            Error::Decrypt
        );

        let mut relabeled = slot.clone();
        relabeled.kind = SlotKind::Passkey;
        assert_eq!(
            relabeled.unlock_with_external_key(&kek).unwrap_err(),
            Error::Decrypt
        );
    }

    #[test]
    fn a_slot_refuses_the_wrong_way_in() {
        let vault_key = Key::random().unwrap();
        let slot = KeySlot::for_password(&vault_key, "pw", FAST).unwrap();
        let recovery_key = RecoveryKey::generate().unwrap();
        assert_eq!(
            slot.unlock_with_recovery_key(&recovery_key).unwrap_err(),
            Error::SlotKind
        );
        assert_eq!(
            slot.unlock_with_external_key(&vault_key).unwrap_err(),
            Error::SlotKind
        );
    }

    #[test]
    fn kinds_round_trip_through_text() {
        for kind in [
            SlotKind::Password,
            SlotKind::Recovery,
            SlotKind::Device,
            SlotKind::Passkey,
        ] {
            assert_eq!(SlotKind::parse(kind.as_str()), Some(kind));
        }
        assert_eq!(SlotKind::parse("master"), None);
    }
}
