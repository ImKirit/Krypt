//! The fields every format fills in, turned into Krypt items the same way for all of them.

use std::time::{SystemTime, UNIX_EPOCH};

use krypt_core::model::{CustomField, Item, ItemData, Login, Note};
use krypt_core::secret::Secret;
use krypt_core::totp::{self, TotpConfig};

use crate::Candidate;
use crate::site::host_of;

#[derive(Default)]
pub(crate) struct Draft {
    pub name: Option<String>,
    /// Web addresses; the first one decides the service.
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    /// An otpauth link or a bare Base32 secret.
    pub totp: Option<String>,
    /// For formats that store the code settings in separate fields.
    pub totp_config: Option<TotpConfig>,
    pub notes: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub fields: Vec<CustomField>,
}

impl Draft {
    /// A login, or a note when there is nothing to sign in with. None when nothing is left.
    pub fn into_login(mut self) -> Option<Candidate> {
        let signs_in = self.username.is_some()
            || self.email.is_some()
            || self.password.is_some()
            || self.totp.is_some()
            || self.totp_config.is_some()
            || !self.urls.is_empty();
        if !signs_in {
            return self.into_note();
        }

        let mut username = self.username.take();
        let mut email = self.email.take();
        if email.is_none() && username.as_deref().is_some_and(looks_like_email) {
            email = username.take();
        }
        let totp = match (self.totp_config.take(), self.totp.take()) {
            (Some(config), _) => Some(config),
            (None, Some(value)) => {
                let parsed = parse_totp(&value);
                if parsed.is_none() {
                    // Kept as it is, so nothing gets lost: Steam codes, HOTP links, typos.
                    self.fields.push(CustomField {
                        name: "TOTP".into(),
                        value: Secret::new(value),
                        hidden: true,
                    });
                }
                parsed
            }
            (None, None) => None,
        };
        let mut urls = std::mem::take(&mut self.urls);
        let url = if urls.first().is_some_and(|first| host_of(first).is_some()) {
            Some(urls.remove(0))
        } else {
            None
        };
        let login = Login {
            username,
            email,
            password: Secret::new(self.password.take().unwrap_or_default()),
            totp,
            urls,
            password_history: Vec::new(),
        };
        Some(self.finish(ItemData::Login(login), url))
    }

    /// A note made of the notes and the custom fields. None when both are empty.
    pub fn into_note(mut self) -> Option<Candidate> {
        if self.notes.is_none() && self.fields.is_empty() {
            return None;
        }
        let text = self.notes.take().unwrap_or_default();
        Some(self.finish(
            ItemData::Note(Note {
                text: Secret::new(text),
            }),
            None,
        ))
    }

    pub fn into_item(self, data: ItemData) -> Candidate {
        self.finish(data, None)
    }

    fn finish(self, data: ItemData, url: Option<String>) -> Candidate {
        let mut item = Item::new(data, now_ms());
        item.notes = Secret::new(self.notes.unwrap_or_default());
        item.favorite = self.favorite;
        item.custom_fields = self.fields;
        for tag in self.tags {
            let tag = tag.trim().trim_matches('/').trim();
            if !tag.is_empty() && !item.tags.iter().any(|known| known == tag) {
                item.tags.push(tag.to_owned());
            }
        }
        Candidate {
            name: self.name,
            url,
            service: None,
            item,
        }
    }
}

/// An otpauth link or a bare Base32 secret with the usual settings.
pub(crate) fn parse_totp(value: &str) -> Option<TotpConfig> {
    let value = value.trim();
    if value
        .get(..10)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("otpauth://"))
    {
        return TotpConfig::from_uri(value).ok();
    }
    totp::decode_secret(value).ok()?;
    Some(TotpConfig {
        secret: Secret::new(value),
        ..TotpConfig::default()
    })
}

/// Trimmed, or None when empty. For names, addresses and other plain text.
pub(crate) fn clean(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_owned())
}

/// Untouched, or None when blank. For passwords and other values where spaces may matter.
pub(crate) fn keep(value: &str) -> Option<String> {
    (!value.trim().is_empty()).then(|| value.to_owned())
}

pub(crate) fn looks_like_email(value: &str) -> bool {
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
        && !value.contains(char::is_whitespace)
}

/// Whether a custom field with this name should be masked.
pub(crate) fn sounds_secret(name: &str) -> bool {
    let name = name.to_lowercase();
    [
        "password", "passwort", "secret", "token", "key", "pin", "cvv", "cvc", "code", "otp",
    ]
    .iter()
    .any(|word| name.contains(word))
}

pub(crate) fn is_true(value: &str) -> bool {
    matches!(
        value.trim().to_lowercase().as_str(),
        "1" | "true" | "yes" | "y" | "x" | "ja"
    )
}

/// Month and year from `05/27`, `05/2027` or `2027-05`.
pub(crate) fn expiry(value: &str) -> (Option<u8>, Option<u16>) {
    let parts: Vec<&str> = value
        .split(['/', '-', '.', ' '])
        .filter(|part| !part.is_empty())
        .collect();
    let (month, year) = match parts.as_slice() {
        [year, month] if year.len() == 4 => (*month, *year),
        [month, year] => (*month, *year),
        _ => return (None, None),
    };
    (month_of(month), year_of(year))
}

pub(crate) fn month_of(value: &str) -> Option<u8> {
    value
        .trim()
        .parse()
        .ok()
        .filter(|month| (1..=12).contains(month))
}

pub(crate) fn year_of(value: &str) -> Option<u16> {
    value
        .trim()
        .parse::<u16>()
        .ok()
        .map(|year| if year < 100 { 2000 + year } else { year })
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}
