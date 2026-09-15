//! KeePass 2 XML, as KeePass writes it under "Export, KeePass XML (2.x)". The .kdbx database
//! itself is encrypted and not read here.

use krypt_core::model::CustomField;
use krypt_core::secret::Secret;
use krypt_core::totp::{TotpAlgorithm, TotpConfig};
use serde::Deserialize;

use crate::draft::{self, Draft};
use crate::{Candidate, Error, Parsed, Result, Source};

/// What KeePass writes as the recycle bin when there is none.
const NO_UUID: &str = "AAAAAAAAAAAAAAAAAAAAAA==";

#[derive(Deserialize)]
struct KeePassFile {
    #[serde(rename = "Meta", default)]
    meta: Meta,
    #[serde(rename = "Root")]
    root: Root,
}

#[derive(Default, Deserialize)]
struct Meta {
    #[serde(rename = "RecycleBinUUID", default)]
    recycle_bin: Option<String>,
}

#[derive(Deserialize)]
struct Root {
    #[serde(rename = "Group", default)]
    groups: Vec<Group>,
}

#[derive(Deserialize)]
struct Group {
    #[serde(rename = "UUID", default)]
    uuid: Option<String>,
    #[serde(rename = "Name", default)]
    name: Option<String>,
    #[serde(rename = "Entry", default)]
    entries: Vec<Entry>,
    #[serde(rename = "Group", default)]
    groups: Vec<Group>,
}

/// Older versions of an entry sit in its `History` element, which is left out on purpose.
#[derive(Deserialize)]
struct Entry {
    #[serde(rename = "String", default)]
    strings: Vec<Field>,
    #[serde(rename = "Tags", default)]
    tags: Option<String>,
}

#[derive(Deserialize)]
struct Field {
    #[serde(rename = "Key", default)]
    key: String,
    #[serde(rename = "Value", default)]
    value: FieldValue,
}

#[derive(Default, Deserialize)]
struct FieldValue {
    #[serde(rename = "@ProtectInMemory", default)]
    protected: Option<String>,
    #[serde(rename = "$text", default)]
    text: String,
}

pub(crate) fn parse(text: &str) -> Result<Parsed> {
    let file: KeePassFile = quick_xml::de::from_str(text).map_err(|_| Error::UnknownFormat)?;
    let recycle_bin = file
        .meta
        .recycle_bin
        .filter(|uuid| !uuid.trim().is_empty() && uuid != NO_UUID);
    let mut parsed = Parsed {
        source: Source::KeePass,
        candidates: Vec::new(),
        skipped: 0,
    };
    for group in file.root.groups {
        // The top group stands for the database, so its name is no folder.
        walk(group, None, recycle_bin.as_deref(), &mut parsed);
    }
    Ok(parsed)
}

fn walk(group: Group, folder: Option<&str>, recycle_bin: Option<&str>, parsed: &mut Parsed) {
    if recycle_bin.is_some() && group.uuid.as_deref() == recycle_bin {
        parsed.skipped += count(&group);
        return;
    }
    for entry in group.entries {
        match candidate(entry, folder) {
            Some(candidate) => parsed.candidates.push(candidate),
            None => parsed.skipped += 1,
        }
    }
    for child in group.groups {
        let name = child.name.clone();
        walk(child, name.as_deref(), recycle_bin, parsed);
    }
}

fn count(group: &Group) -> usize {
    group.entries.len() + group.groups.iter().map(count).sum::<usize>()
}

fn candidate(entry: Entry, folder: Option<&str>) -> Option<Candidate> {
    let mut tags: Vec<String> = folder.map(str::to_owned).into_iter().collect();
    if let Some(list) = &entry.tags {
        tags.extend(list.split([',', ';']).map(str::to_owned));
    }
    let mut result = Draft {
        tags,
        ..Draft::default()
    };
    let mut seed = None;
    let mut digits = None;
    let mut period = None;
    let mut algorithm = TotpAlgorithm::Sha1;

    for field in entry.strings {
        let text = field.value.text.as_str();
        match field.key.as_str() {
            "Title" => result.name = draft::clean(text),
            "UserName" => result.username = draft::clean(text),
            "Password" => result.password = draft::keep(text),
            "URL" => result.urls.extend(draft::clean(text)),
            "Notes" => result.notes = draft::clean(text),
            // KeePassXC keeps an otpauth link here.
            "otp" => result.totp = draft::clean(text),
            // KeePass 2.47 and later, and older KeePassXC versions, keep the parts separately.
            "TimeOtp-Secret-Base32" | "TOTP Seed" => seed = draft::clean(text),
            "TimeOtp-Length" => digits = text.trim().parse().ok(),
            "TimeOtp-Period" => period = text.trim().parse().ok(),
            "TimeOtp-Algorithm" => {
                algorithm = match text.trim() {
                    "HMAC-SHA-256" => TotpAlgorithm::Sha256,
                    "HMAC-SHA-512" => TotpAlgorithm::Sha512,
                    _ => TotpAlgorithm::Sha1,
                }
            }
            _ => {
                if let Some(value) = draft::keep(text) {
                    result.fields.push(CustomField {
                        name: field.key.clone(),
                        value: Secret::new(value),
                        hidden: field
                            .value
                            .protected
                            .as_deref()
                            .is_some_and(|flag| flag.eq_ignore_ascii_case("true")),
                    });
                }
            }
        }
    }

    if let Some(seed) = seed {
        let config = TotpConfig {
            secret: Secret::new(seed.as_str()),
            algorithm,
            digits: digits.unwrap_or(6),
            period: period.unwrap_or(30),
            issuer: None,
            account: None,
        };
        if config.code_at(0).is_ok() {
            result.totp_config = Some(config);
        } else {
            result.fields.push(CustomField {
                name: "TimeOtp-Secret-Base32".into(),
                value: Secret::new(seed),
                hidden: true,
            });
        }
    }
    result.into_login()
}
