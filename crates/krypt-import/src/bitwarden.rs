//! Bitwarden's JSON export. Password protected and account encrypted exports cannot be read
//! here; Bitwarden can export the same vault without encryption.

use std::collections::HashMap;

use krypt_core::model::{Address, Card, CustomField, IdDocument, Identity, ItemData, SshKey};
use krypt_core::secret::Secret;
use serde_json::Value;

use crate::draft::{self, Draft};
use crate::{Candidate, Error, Parsed, Result, Source};

const LOGIN: u64 = 1;
const NOTE: u64 = 2;
const CARD: u64 = 3;
const IDENTITY: u64 = 4;
const SSH_KEY: u64 = 5;
const HIDDEN_FIELD: u64 = 1;

pub(crate) fn parse(text: &str) -> Result<Parsed> {
    let root: Value = serde_json::from_str(text).map_err(|_| Error::UnknownFormat)?;
    if root.get("encrypted").and_then(Value::as_bool) == Some(true) {
        return Err(Error::Encrypted);
    }
    let items = root
        .get("items")
        .and_then(Value::as_array)
        .ok_or(Error::UnknownFormat)?;

    // Folders in a personal export, collections in an organization export.
    let mut groups = HashMap::new();
    for key in ["folders", "collections"] {
        for group in root
            .get(key)
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let (Some(id), Some(name)) = (text_at(group, "id"), text_at(group, "name")) {
                groups.insert(id, name);
            }
        }
    }

    let mut parsed = Parsed {
        source: Source::Bitwarden,
        candidates: Vec::new(),
        skipped: 0,
    };
    for entry in items {
        match candidate(entry, &groups) {
            Some(candidate) => parsed.candidates.push(candidate),
            None => parsed.skipped += 1,
        }
    }
    Ok(parsed)
}

fn candidate(entry: &Value, groups: &HashMap<String, String>) -> Option<Candidate> {
    let mut tags: Vec<String> = text_at(entry, "folderId")
        .and_then(|id| groups.get(&id).cloned())
        .into_iter()
        .collect();
    for id in entry
        .get("collectionIds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        if let Some(name) = id.as_str().and_then(|id| groups.get(id)) {
            tags.push(name.clone());
        }
    }
    let fields = entry
        .get("fields")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|field| {
            let name = text_at(field, "name").unwrap_or_default();
            let value = secret_at(field, "value").unwrap_or_default();
            if name.is_empty() && value.is_empty() {
                return None;
            }
            Some(CustomField {
                hidden: field.get("type").and_then(Value::as_u64) == Some(HIDDEN_FIELD),
                name,
                value: Secret::new(value),
            })
        })
        .collect();

    let mut draft = Draft {
        name: text_at(entry, "name"),
        notes: text_at(entry, "notes"),
        favorite: entry
            .get("favorite")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        tags,
        fields,
        ..Draft::default()
    };

    match entry.get("type").and_then(Value::as_u64)? {
        LOGIN => {
            if let Some(login) = entry.get("login") {
                draft.urls = login
                    .get("uris")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|uri| text_at(uri, "uri"))
                    .collect();
                draft.username = text_at(login, "username");
                draft.password = secret_at(login, "password");
                draft.totp = text_at(login, "totp");
            }
            draft.into_login()
        }
        NOTE => draft.into_note(),
        CARD => {
            let card = entry.get("card")?;
            let data = Card {
                holder: text_at(card, "cardholderName"),
                number: Secret::new(text_at(card, "number").unwrap_or_default()),
                expiry_month: text_at(card, "expMonth").and_then(|m| draft::month_of(&m)),
                expiry_year: text_at(card, "expYear").and_then(|y| draft::year_of(&y)),
                cvc: text_at(card, "code").map(Secret::new),
                pin: None,
                brand: text_at(card, "brand"),
            };
            Some(draft.into_item(ItemData::Card(data)))
        }
        IDENTITY => {
            let identity = entry.get("identity")?;
            let joined = |keys: &[&str], separator: &str| {
                let parts: Vec<String> = keys
                    .iter()
                    .filter_map(|key| text_at(identity, key))
                    .collect();
                draft::clean(&parts.join(separator))
            };
            let address = Address {
                street: joined(&["address1", "address2", "address3"], ", "),
                postal_code: text_at(identity, "postalCode"),
                city: text_at(identity, "city"),
                region: text_at(identity, "state"),
                country: text_at(identity, "country"),
            };
            let documents = [
                ("ssn", "social security number"),
                ("passportNumber", "passport"),
                ("licenseNumber", "driver's license"),
            ]
            .into_iter()
            .filter_map(|(key, kind)| {
                text_at(identity, key).map(|number| IdDocument {
                    kind: kind.into(),
                    number: Secret::new(number),
                    expires: None,
                })
            })
            .collect();
            for (key, name) in [("company", "Company"), ("username", "Username")] {
                if let Some(value) = text_at(identity, key) {
                    draft.fields.push(CustomField {
                        name: name.into(),
                        value: Secret::new(value),
                        hidden: false,
                    });
                }
            }
            let data = Identity {
                full_name: joined(&["firstName", "middleName", "lastName"], " ")
                    .or_else(|| draft.name.clone())
                    .unwrap_or_default(),
                email: text_at(identity, "email"),
                phone: text_at(identity, "phone"),
                birthday: None,
                address: (address != Address::default()).then_some(address),
                documents,
            };
            Some(draft.into_item(ItemData::Identity(data)))
        }
        SSH_KEY => {
            let key = entry.get("sshKey")?;
            let data = SshKey {
                private_key: Secret::new(secret_at(key, "privateKey").unwrap_or_default()),
                public_key: text_at(key, "publicKey"),
                passphrase: None,
                fingerprint: text_at(key, "keyFingerprint"),
                comment: None,
            };
            Some(draft.into_item(ItemData::SshKey(data)))
        }
        _ => None,
    }
}

fn text_at(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().and_then(draft::clean)
}

fn secret_at(value: &Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().and_then(draft::keep)
}
