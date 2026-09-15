//! CSV exports. Every app names its columns a little differently, so columns are recognized by
//! the names below, and whatever is left over becomes a custom field.

use std::collections::HashSet;

use krypt_core::model::{Address, Card, CustomField, Identity, ItemData};
use krypt_core::secret::Secret;

use crate::draft::{self, Draft};
use crate::site::host_of;
use crate::{Candidate, Error, Parsed, Result, Source};

// Column names as compared: lower case, with spaces and dashes turned into underscores.
// Earlier names win when a file has several of them.
const NAME: &[&str] = &["name", "title", "item_name", "titel"];
const URL: &[&str] = &[
    "url",
    "login_uri",
    "website",
    "web_site",
    "uri",
    "login_url",
    "hostname",
    "site",
    "urls",
    "webseite",
];
const USERNAME: &[&str] = &[
    "username",
    "login_username",
    "login",
    "user",
    "user_name",
    "login_name",
    "userid",
    "benutzername",
    "benutzer",
];
const EMAIL: &[&str] = &["email", "e_mail", "email_address", "login_email"];
const PASSWORD: &[&str] = &[
    "password",
    "login_password",
    "pwd",
    "pass",
    "passwd",
    "passwort",
    "kennwort",
];
const TOTP: &[&str] = &[
    "totp",
    "login_totp",
    "otpauth",
    "otp",
    "otpsecret",
    "otp_secret",
    "otpurl",
    "otp_url",
    "one_time_password",
    "2fa",
    "authenticator_key",
    "mfa",
];
const NOTES: &[&str] = &[
    "notes",
    "note",
    "extra",
    "comments",
    "comment",
    "notizen",
    "notiz",
    "bemerkung",
];
const FOLDER: &[&str] = &[
    "folder",
    "grouping",
    "group",
    "vault",
    "category",
    "collection",
    "ordner",
    "gruppe",
];
const FAVORITE: &[&str] = &["favorite", "fav", "favourite", "starred", "favorit"];
const TAGS: &[&str] = &["tags", "tag", "labels"];
const KIND: &[&str] = &["type", "item_type", "kind"];
const FIELDS: &[&str] = &["fields", "custom_fields"];
const CARD_HOLDER: &[&str] = &[
    "cardholdername",
    "cardholder",
    "cardholder_name",
    "card_holder",
    "name_on_card",
];
const CARD_NUMBER: &[&str] = &["cardnumber", "card_number"];
const CARD_CVC: &[&str] = &[
    "cvc",
    "cvv",
    "security_code",
    "card_cvc",
    "verification_number",
];
const CARD_EXPIRY: &[&str] = &[
    "expirydate",
    "expiry_date",
    "expiration_date",
    "expiration",
    "exp_date",
];
const FULL_NAME: &[&str] = &["full_name", "fullname"];
const PHONE: &[&str] = &["phone", "phone_number", "telephone", "telefon"];
const STREET: &[&str] = &["address1", "address_1", "street", "address"];
const STREET2: &[&str] = &["address2", "address_2"];
const POSTAL_CODE: &[&str] = &["zipcode", "zip", "zip_code", "postal_code", "postcode"];
const CITY: &[&str] = &["city", "town"];
const REGION: &[&str] = &["state", "region", "province"];
const COUNTRY: &[&str] = &["country"];
/// Bookkeeping columns with nothing worth keeping.
const IGNORED: &[&str] = &[
    "id",
    "guid",
    "uuid",
    "created",
    "createtime",
    "create_time",
    "creation_time",
    "created_at",
    "modified",
    "modifytime",
    "modify_time",
    "last_modified",
    "modified_at",
    "updated",
    "updated_at",
    "timecreated",
    "timelastused",
    "timepasswordchanged",
    "last_used",
    "httprealm",
    "formactionorigin",
    "reprompt",
    "icon",
    "archived",
    "password_strength",
    "matchurl",
    "rffieldsv2",
];

pub(crate) fn parse(text: &str) -> Result<Parsed> {
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter(text))
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers: Vec<String> = reader
        .headers()
        .map_err(|_| Error::UnknownFormat)?
        .iter()
        .map(str::to_owned)
        .collect();
    let layout = Layout::new(&headers)?;
    let mut parsed = Parsed {
        source: detect(&headers),
        candidates: Vec::new(),
        skipped: 0,
    };
    for record in reader.records() {
        let record = record.map_err(|_| Error::Malformed)?;
        if record.iter().all(|field| field.trim().is_empty()) {
            continue;
        }
        match layout.row(&headers, &record) {
            Some(candidate) => parsed.candidates.push(candidate),
            None => parsed.skipped += 1,
        }
    }
    Ok(parsed)
}

fn normalize(header: &str) -> String {
    header
        .trim()
        .trim_start_matches('\u{feff}')
        .trim()
        .to_lowercase()
        .replace([' ', '-'], "_")
}

/// Semicolons and tabs show up in files saved by spreadsheet programs.
fn delimiter(text: &str) -> u8 {
    let first = text.lines().next().unwrap_or_default();
    let count = |byte: u8| first.bytes().filter(|&b| b == byte).count();
    let (commas, semicolons, tabs) = (count(b','), count(b';'), count(b'\t'));
    if tabs > commas && tabs > semicolons {
        b'\t'
    } else if semicolons > commas {
        b';'
    } else {
        b','
    }
}

fn detect(headers: &[String]) -> Source {
    let names: HashSet<String> = headers.iter().map(|header| normalize(header)).collect();
    let has = |name: &str| names.contains(name);
    if has("login_uri") || has("login_username") {
        Source::Bitwarden
    } else if has("httprealm") || has("formactionorigin") {
        Source::Firefox
    } else if has("grouping") && has("extra") {
        Source::LastPass
    } else if has("otpauth") && has("archived") {
        Source::OnePassword
    } else if has("otpauth") {
        Source::Safari
    } else if has("group") && has("title") && has("last_modified") {
        Source::KeePass
    } else if has("username2") || has("otpsecret") || has("otpurl") {
        Source::Dashlane
    } else if has("createtime") && has("vault") {
        Source::ProtonPass
    } else if has("cardholdername") && has("full_name") {
        Source::NordPass
    } else if has("pwd") && has("matchurl") {
        Source::RoboForm
    } else if names.len() >= 4
        && names
            .iter()
            .all(|name| ["name", "url", "username", "password", "note"].contains(&name.as_str()))
    {
        Source::Chromium
    } else {
        Source::Csv
    }
}

/// Which column holds what.
struct Layout {
    name: Option<usize>,
    url: Option<usize>,
    username: Option<usize>,
    email: Option<usize>,
    password: Option<usize>,
    totp: Option<usize>,
    notes: Option<usize>,
    folder: Option<usize>,
    favorite: Option<usize>,
    tags: Option<usize>,
    kind: Option<usize>,
    fields: Option<usize>,
    card_holder: Option<usize>,
    card_number: Option<usize>,
    card_cvc: Option<usize>,
    card_expiry: Option<usize>,
    full_name: Option<usize>,
    phone: Option<usize>,
    street: Option<usize>,
    street2: Option<usize>,
    postal_code: Option<usize>,
    city: Option<usize>,
    region: Option<usize>,
    country: Option<usize>,
    /// Columns nothing above took, kept as custom fields.
    unused: Vec<usize>,
}

impl Layout {
    fn new(headers: &[String]) -> Result<Self> {
        let normalized: Vec<String> = headers.iter().map(|header| normalize(header)).collect();
        let mut used: Vec<bool> = normalized
            .iter()
            .map(|header| header.is_empty() || IGNORED.contains(&header.as_str()))
            .collect();
        let mut take = |names: &[&str]| -> Option<usize> {
            for name in names {
                if let Some(index) =
                    (0..normalized.len()).find(|&i| !used[i] && normalized[i] == *name)
                {
                    used[index] = true;
                    return Some(index);
                }
            }
            None
        };
        let mut layout = Self {
            name: take(NAME),
            url: take(URL),
            username: take(USERNAME),
            email: take(EMAIL),
            password: take(PASSWORD),
            totp: take(TOTP),
            notes: take(NOTES),
            folder: take(FOLDER),
            favorite: take(FAVORITE),
            tags: take(TAGS),
            kind: take(KIND),
            fields: take(FIELDS),
            card_holder: take(CARD_HOLDER),
            card_number: take(CARD_NUMBER),
            card_cvc: take(CARD_CVC),
            card_expiry: take(CARD_EXPIRY),
            full_name: take(FULL_NAME),
            phone: take(PHONE),
            street: take(STREET),
            street2: take(STREET2),
            postal_code: take(POSTAL_CODE),
            city: take(CITY),
            region: take(REGION),
            country: take(COUNTRY),
            unused: Vec::new(),
        };
        layout.unused = (0..used.len()).filter(|&i| !used[i]).collect();

        let recognized = [
            layout.url,
            layout.username,
            layout.email,
            layout.password,
            layout.notes,
            layout.card_number,
            layout.full_name,
        ]
        .iter()
        .any(Option::is_some);
        if recognized {
            Ok(layout)
        } else {
            Err(Error::UnknownFormat)
        }
    }

    fn row(&self, headers: &[String], record: &csv::StringRecord) -> Option<Candidate> {
        let raw = |index: Option<usize>| index.and_then(|i| record.get(i));
        let text = |index: Option<usize>| raw(index).and_then(draft::clean);

        let kind = text(self.kind)
            .map(|kind| kind.to_lowercase().replace([' ', '-', '_'], ""))
            .unwrap_or_default();
        let url = text(self.url);
        // LastPass writes secure notes as rows with the address http://sn.
        let lastpass_note = url.as_deref() == Some("http://sn");

        let mut tags: Vec<String> = text(self.folder).into_iter().collect();
        if let Some(list) = text(self.tags) {
            tags.extend(list.split([',', ';']).map(str::to_owned));
        }
        let mut fields = text(self.fields)
            .map(|fields| bitwarden_fields(&fields))
            .unwrap_or_default();
        for &index in &self.unused {
            if let Some(value) = record.get(index).and_then(draft::keep) {
                let name = headers[index].trim().trim_start_matches('\u{feff}').trim();
                fields.push(CustomField {
                    hidden: draft::sounds_secret(name),
                    name: name.to_owned(),
                    value: Secret::new(value),
                });
            }
        }

        let mut draft = Draft {
            name: text(self.name),
            urls: match url {
                Some(url) if !lastpass_note => split_urls(&url),
                _ => Vec::new(),
            },
            username: text(self.username),
            email: text(self.email),
            password: raw(self.password).and_then(draft::keep),
            totp: text(self.totp),
            notes: text(self.notes),
            tags,
            favorite: text(self.favorite).is_some_and(|value| draft::is_true(&value)),
            fields,
            ..Draft::default()
        };

        match kind.as_str() {
            "note" | "notes" | "securenote" => draft.into_note(),
            "card" | "creditcard" | "paymentcard" => {
                let (expiry_month, expiry_year) = text(self.card_expiry)
                    .map(|value| draft::expiry(&value))
                    .unwrap_or((None, None));
                let card = Card {
                    holder: text(self.card_holder),
                    number: Secret::new(text(self.card_number).unwrap_or_default()),
                    expiry_month,
                    expiry_year,
                    cvc: text(self.card_cvc).map(Secret::new),
                    pin: None,
                    brand: None,
                };
                Some(draft.into_item(ItemData::Card(card)))
            }
            "identity" => {
                let street: Vec<String> = [text(self.street), text(self.street2)]
                    .into_iter()
                    .flatten()
                    .collect();
                let address = Address {
                    street: draft::clean(&street.join(", ")),
                    postal_code: text(self.postal_code),
                    city: text(self.city),
                    region: text(self.region),
                    country: text(self.country),
                };
                let identity = Identity {
                    full_name: text(self.full_name)
                        .or_else(|| draft.name.clone())
                        .unwrap_or_default(),
                    email: draft.email.take().or_else(|| draft.username.take()),
                    phone: text(self.phone),
                    birthday: None,
                    address: (address != Address::default()).then_some(address),
                    documents: Vec::new(),
                };
                Some(draft.into_item(ItemData::Identity(identity)))
            }
            _ if lastpass_note => draft.into_note(),
            _ => draft.into_login(),
        }
    }
}

/// Bitwarden puts several addresses into one column, separated by commas.
fn split_urls(value: &str) -> Vec<String> {
    let parts: Vec<&str> = value
        .split([',', '\n'])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    if parts.len() > 1 && parts.iter().all(|part| host_of(part).is_some()) {
        parts.into_iter().map(str::to_owned).collect()
    } else {
        vec![value.trim().to_owned()]
    }
}

/// Bitwarden's `fields` column: one `name: value` per line.
fn bitwarden_fields(text: &str) -> Vec<CustomField> {
    text.lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(": ").unwrap_or((line, ""));
            let name = name.trim();
            if name.is_empty() && value.trim().is_empty() {
                return None;
            }
            Some(CustomField {
                hidden: draft::sounds_secret(name),
                name: name.to_owned(),
                value: Secret::new(value),
            })
        })
        .collect()
}
