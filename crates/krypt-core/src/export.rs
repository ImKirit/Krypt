//! Encrypted exports: every service and entry in one file, locked with a password of its own.
//!
//! The file is JSON, so it can be recognized and its version read without the password:
//!
//! ```text
//! {
//!   "format": "krypt-export",
//!   "version": 1,
//!   "kdf": { "algorithm": "argon2id", "m_cost_kib": 65536, "t_cost": 3, "p_cost": 4, "salt": "..." },
//!   "data": "..."
//! }
//! ```
//!
//! `salt` and `data` are standard Base64. `data` is [`crypto::seal`] of the JSON payload under a
//! key derived the way a password slot derives its key: Argon2id over the NFC form of the
//! password, then HKDF-SHA256 with the info string `krypt/v1/export`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto::{self, KdfParams, Key, SALT_LEN};
use crate::model::{Item, Service};
use crate::{Error, Result, secret};

pub const FORMAT: &str = "krypt-export";
pub const VERSION: u32 = 1;
const KDF_ALGORITHM: &str = "argon2id";
const INFO: &str = "krypt/v1/export";
const AAD: &[u8] = b"krypt/v1/export";

/// What an export holds. Items in the trash are not part of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportPayload {
    /// Unix time in milliseconds.
    #[serde(default)]
    pub exported_at: i64,
    #[serde(default)]
    pub services: Vec<Service>,
    #[serde(default)]
    pub items: Vec<Item>,
}

#[derive(Deserialize)]
struct Header {
    format: String,
    version: u32,
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    format: String,
    version: u32,
    kdf: EnvelopeKdf,
    data: String,
}

#[derive(Serialize, Deserialize)]
struct EnvelopeKdf {
    algorithm: String,
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    salt: String,
}

/// Encrypts `payload` with `password`. Refuses to run inside [`secret::masked`], where every
/// secret would be written as a placeholder.
pub fn seal(payload: &ExportPayload, password: &str, params: KdfParams) -> Result<Vec<u8>> {
    if secret::masking_active() {
        return Err(Error::Format);
    }
    let mut salt = [0u8; SALT_LEN];
    crypto::random_bytes(&mut salt)?;
    let key = export_key(password, &salt, params)?;
    let plaintext = Zeroizing::new(serde_json::to_vec(payload).map_err(|_| Error::Format)?);
    let data = crypto::seal(&key, &plaintext, AAD)?;
    let envelope = Envelope {
        format: FORMAT.into(),
        version: VERSION,
        kdf: EnvelopeKdf {
            algorithm: KDF_ALGORITHM.into(),
            m_cost_kib: params.m_cost_kib,
            t_cost: params.t_cost,
            p_cost: params.p_cost,
            salt: BASE64.encode(salt),
        },
        data: BASE64.encode(data),
    };
    serde_json::to_vec_pretty(&envelope).map_err(|_| Error::Format)
}

/// True if `bytes` are a Krypt export of any version.
pub fn is_export(bytes: &[u8]) -> bool {
    header(bytes).is_some()
}

/// Decrypts an export. A wrong password and a damaged file both fail with [`Error::Decrypt`].
pub fn open(bytes: &[u8], password: &str) -> Result<ExportPayload> {
    let header = header(bytes).ok_or(Error::NotAnExport)?;
    if header.version != VERSION {
        return Err(Error::ExportVersion(header.version));
    }
    let envelope: Envelope = serde_json::from_slice(bytes).map_err(|_| Error::Format)?;
    if envelope.kdf.algorithm != KDF_ALGORITHM {
        return Err(Error::Format);
    }
    let params = KdfParams {
        m_cost_kib: envelope.kdf.m_cost_kib,
        t_cost: envelope.kdf.t_cost,
        p_cost: envelope.kdf.p_cost,
    };
    let salt: [u8; SALT_LEN] = BASE64
        .decode(&envelope.kdf.salt)
        .ok()
        .and_then(|salt| salt.try_into().ok())
        .ok_or(Error::Format)?;
    let data = BASE64.decode(&envelope.data).map_err(|_| Error::Format)?;
    let key = export_key(password, &salt, params)?;
    let plaintext = crypto::open(&key, &data, AAD)?;
    serde_json::from_slice(&plaintext).map_err(|_| Error::Format)
}

fn header(bytes: &[u8]) -> Option<Header> {
    serde_json::from_slice::<Header>(bytes)
        .ok()
        .filter(|header| header.format == FORMAT)
}

fn export_key(password: &str, salt: &[u8; SALT_LEN], params: KdfParams) -> Result<Key> {
    let normalized = crate::password::normalize(password);
    let master = crypto::argon2id(normalized.as_bytes(), salt, params)?;
    crypto::derive_key(master.as_bytes(), INFO)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use super::*;
    use crate::model::{ApiKey, ItemData};
    use crate::secret::Secret;

    const FAST: KdfParams = KdfParams {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    };
    const PASSWORD: &str = "Export-pass-1";

    fn payload() -> ExportPayload {
        let service = Service::new("Anthropic");
        let mut item = Item::new(
            ItemData::ApiKey(ApiKey {
                key: Secret::new("sk-export-secret"),
                ..ApiKey::default()
            }),
            1,
        );
        item.service_id = Some(service.id);
        ExportPayload {
            exported_at: 1,
            services: vec![service],
            items: vec![item],
        }
    }

    fn edit(sealed: &[u8], change: impl FnOnce(&mut Value)) -> Vec<u8> {
        let mut envelope: Value = serde_json::from_slice(sealed).unwrap();
        change(&mut envelope);
        serde_json::to_vec(&envelope).unwrap()
    }

    #[test]
    fn round_trips_without_plaintext_in_the_file() {
        let payload = payload();
        let sealed = seal(&payload, PASSWORD, FAST).unwrap();
        let text = String::from_utf8(sealed.clone()).unwrap();
        for plain in ["sk-export-secret", "Anthropic", "api_key"] {
            assert!(!text.contains(plain), "{plain} is readable");
        }
        assert!(is_export(&sealed));
        assert_eq!(open(&sealed, PASSWORD).unwrap(), payload);
    }

    #[test]
    fn a_wrong_password_or_a_changed_byte_fails() {
        let sealed = seal(&payload(), PASSWORD, FAST).unwrap();
        assert_eq!(open(&sealed, "Export-pass-2").unwrap_err(), Error::Decrypt);
        let tampered = edit(&sealed, |envelope| {
            let mut data = BASE64.decode(envelope["data"].as_str().unwrap()).unwrap();
            let last = data.len() - 1;
            data[last] ^= 1;
            envelope["data"] = BASE64.encode(&data).into();
        });
        assert_eq!(open(&tampered, PASSWORD).unwrap_err(), Error::Decrypt);
        let other_costs = edit(&sealed, |envelope| envelope["kdf"]["t_cost"] = 2.into());
        assert_eq!(open(&other_costs, PASSWORD).unwrap_err(), Error::Decrypt);
    }

    #[test]
    fn composed_and_decomposed_accents_open_the_same_export() {
        let sealed = seal(&payload(), "Caf\u{e9}-Export-1", FAST).unwrap();
        assert!(open(&sealed, "Cafe\u{301}-Export-1").is_ok());
    }

    #[test]
    fn other_versions_and_other_files_are_told_apart() {
        let sealed = seal(&payload(), PASSWORD, FAST).unwrap();
        let newer = edit(&sealed, |envelope| envelope["version"] = 2.into());
        assert!(is_export(&newer));
        assert_eq!(open(&newer, PASSWORD).unwrap_err(), Error::ExportVersion(2));
        for other in [
            &br#"{"encrypted":false,"items":[]}"#[..],
            b"name,url,username,password",
            b"",
        ] {
            assert!(!is_export(other));
            assert_eq!(open(other, PASSWORD).unwrap_err(), Error::NotAnExport);
        }
        let broken_salt = edit(&sealed, |envelope| envelope["kdf"]["salt"] = "AAAA".into());
        assert_eq!(open(&broken_salt, PASSWORD).unwrap_err(), Error::Format);
    }

    #[test]
    fn refuses_to_seal_masked_secrets() {
        let result = secret::masked(|| seal(&payload(), PASSWORD, FAST));
        assert_eq!(result.unwrap_err(), Error::Format);
    }
}
