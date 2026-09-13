//! Encrypting services and items for storage and sync.
//!
//! Every platform uses these functions, so a record written on the desktop decrypts on a
//! phone. The associated data binds each ciphertext to its kind and id: moving a record to
//! another row makes it fail to decrypt instead of showing up under the wrong entry.

use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::crypto::{self, Key};
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecordKind {
    Service,
    Item,
}

impl RecordKind {
    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::Service => "service",
            RecordKind::Item => "item",
        }
    }
}

pub fn aad(kind: RecordKind, id: Uuid) -> Vec<u8> {
    format!("krypt/v1/{}/{}", kind.as_str(), id).into_bytes()
}

pub fn seal<T: Serialize>(
    vault_key: &Key,
    kind: RecordKind,
    id: Uuid,
    value: &T,
) -> Result<Vec<u8>> {
    let mut json = Zeroizing::new(Vec::with_capacity(1024));
    serde_json::to_writer(&mut *json, value).map_err(|_| Error::Format)?;
    crypto::seal(vault_key, &json, &aad(kind, id))
}

pub fn open<T: DeserializeOwned>(
    vault_key: &Key,
    kind: RecordKind,
    id: Uuid,
    ciphertext: &[u8],
) -> Result<T> {
    let json = crypto::open(vault_key, ciphertext, &aad(kind, id))?;
    serde_json::from_slice(&json).map_err(|_| Error::Format)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Service;

    #[test]
    fn round_trips_a_service() {
        let key = Key::random().unwrap();
        let service = Service::new("Groq");
        let sealed = seal(&key, RecordKind::Service, service.id, &service).unwrap();
        let back: Service = open(&key, RecordKind::Service, service.id, &sealed).unwrap();
        assert_eq!(back, service);
    }

    #[test]
    fn a_record_only_opens_under_its_own_kind_and_id() {
        let key = Key::random().unwrap();
        let service = Service::new("Groq");
        let sealed = seal(&key, RecordKind::Service, service.id, &service).unwrap();
        let other_id = open::<Service>(&key, RecordKind::Service, Uuid::new_v4(), &sealed);
        let other_kind = open::<Service>(&key, RecordKind::Item, service.id, &sealed);
        assert_eq!(other_id.unwrap_err(), Error::Decrypt);
        assert_eq!(other_kind.unwrap_err(), Error::Decrypt);
    }

    #[test]
    fn a_format_error_does_not_quote_the_decrypted_data() {
        let key = Key::random().unwrap();
        let id = Uuid::new_v4();
        let not_a_service = serde_json::json!({ "id": "not-a-uuid", "name": "hunter2" });
        let sealed = seal(&key, RecordKind::Service, id, &not_a_service).unwrap();
        let err = open::<Service>(&key, RecordKind::Service, id, &sealed).unwrap_err();
        assert_eq!(err, Error::Format);
        assert!(!err.to_string().contains("hunter2"));
    }
}
