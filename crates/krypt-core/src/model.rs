//! What a vault holds: services and the entries that belong to them.
//!
//! A service (Anthropic, GitHub) knows its domains. An item belongs to at most one service and
//! has exactly one type. Any number of items of any type can share a service: one account and
//! two API keys under Anthropic, just two keys under Groq.
//!
//! Every struct accepts missing fields (`serde(default)`) and ignores unknown ones, so a vault
//! written by a newer version still opens in an older one and the other way round.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::secret::Secret;
use crate::totp::TotpConfig;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Service {
    pub id: Uuid,
    pub name: String,
    #[serde(default)]
    pub domains: Vec<DomainRule>,
    /// Name of a bundled icon. Icons are never fetched from the network, because that would
    /// tell a server which services someone uses.
    #[serde(default)]
    pub icon: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub favorite: bool,
}

impl Service {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            domains: Vec::new(),
            icon: None,
            tags: Vec::new(),
            favorite: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainRule {
    pub host: String,
    #[serde(default)]
    pub matching: DomainMatch,
}

impl DomainRule {
    pub fn new(host: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            matching: DomainMatch::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainMatch {
    /// Any host under the same registrable domain: `console.anthropic.com` for `anthropic.com`.
    #[default]
    RegistrableDomain,
    /// Only this exact host.
    ExactHost,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub id: Uuid,
    #[serde(default)]
    pub service_id: Option<Uuid>,
    /// Tells items of one service apart: "personal", "production", "CI".
    #[serde(default)]
    pub label: String,
    #[serde(default)]
    pub notes: Secret,
    #[serde(default)]
    pub favorite: bool,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub custom_fields: Vec<CustomField>,
    /// Unix time in milliseconds.
    #[serde(default)]
    pub created: i64,
    pub data: ItemData,
}

impl Item {
    pub fn new(data: ItemData, created: i64) -> Self {
        Self {
            id: Uuid::new_v4(),
            service_id: None,
            label: String::new(),
            notes: Secret::default(),
            favorite: false,
            tags: Vec::new(),
            custom_fields: Vec::new(),
            created,
            data,
        }
    }

    pub fn item_type(&self) -> ItemType {
        self.data.item_type()
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CustomField {
    pub name: String,
    pub value: Secret,
    /// Masked in the interface until revealed.
    pub hidden: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemType {
    Login,
    ApiKey,
    Passkey,
    Totp,
    Note,
    RecoveryCodes,
    Card,
    Identity,
    SshKey,
    EnvFile,
    Database,
}

impl ItemType {
    pub const ALL: [ItemType; 11] = [
        ItemType::Login,
        ItemType::ApiKey,
        ItemType::Passkey,
        ItemType::Totp,
        ItemType::Note,
        ItemType::RecoveryCodes,
        ItemType::Card,
        ItemType::Identity,
        ItemType::SshKey,
        ItemType::EnvFile,
        ItemType::Database,
    ];

    /// Blank fields for this type, used when a new entry is started or its type is switched.
    pub fn empty_data(self) -> ItemData {
        match self {
            ItemType::Login => ItemData::Login(Login::default()),
            ItemType::ApiKey => ItemData::ApiKey(ApiKey::default()),
            ItemType::Passkey => ItemData::Passkey(Passkey::default()),
            ItemType::Totp => ItemData::Totp(TotpConfig::default()),
            ItemType::Note => ItemData::Note(Note::default()),
            ItemType::RecoveryCodes => ItemData::RecoveryCodes(RecoveryCodes::default()),
            ItemType::Card => ItemData::Card(Card::default()),
            ItemType::Identity => ItemData::Identity(Identity::default()),
            ItemType::SshKey => ItemData::SshKey(SshKey::default()),
            ItemType::EnvFile => ItemData::EnvFile(EnvFile::default()),
            ItemType::Database => ItemData::Database(Database::default()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ItemData {
    Login(Login),
    ApiKey(ApiKey),
    Passkey(Passkey),
    Totp(TotpConfig),
    Note(Note),
    RecoveryCodes(RecoveryCodes),
    Card(Card),
    Identity(Identity),
    SshKey(SshKey),
    EnvFile(EnvFile),
    Database(Database),
}

impl ItemData {
    pub fn item_type(&self) -> ItemType {
        match self {
            ItemData::Login(_) => ItemType::Login,
            ItemData::ApiKey(_) => ItemType::ApiKey,
            ItemData::Passkey(_) => ItemType::Passkey,
            ItemData::Totp(_) => ItemType::Totp,
            ItemData::Note(_) => ItemType::Note,
            ItemData::RecoveryCodes(_) => ItemType::RecoveryCodes,
            ItemData::Card(_) => ItemType::Card,
            ItemData::Identity(_) => ItemType::Identity,
            ItemData::SshKey(_) => ItemType::SshKey,
            ItemData::EnvFile(_) => ItemType::EnvFile,
            ItemData::Database(_) => ItemType::Database,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Login {
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Secret,
    /// The usual case: password and code are filled together.
    pub totp: Option<TotpConfig>,
    /// Extra addresses beyond the service's domains.
    pub urls: Vec<String>,
    pub password_history: Vec<PasswordChange>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordChange {
    pub password: Secret,
    /// Unix time in milliseconds when this password was replaced.
    pub replaced_at: i64,
}

/// API keys and access tokens. A token that runs out is an API key with `expires` set.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ApiKey {
    pub key: Secret,
    pub key_id: Option<String>,
    pub secret: Option<Secret>,
    pub organization: Option<String>,
    pub scopes: Vec<String>,
    /// Unix time in milliseconds.
    pub expires: Option<i64>,
    pub console_url: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Passkey {
    pub rp_id: String,
    /// Base64url, as WebAuthn transports it.
    pub credential_id: String,
    /// Base64url.
    pub user_handle: String,
    pub username: Option<String>,
    /// PKCS#8, base64url.
    pub private_key: Secret,
    /// COSE algorithm identifier, -7 for ES256.
    pub algorithm: i32,
    pub sign_count: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Note {
    pub text: Secret,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RecoveryCodes {
    pub codes: Vec<RecoveryCode>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct RecoveryCode {
    pub code: Secret,
    pub used: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Card {
    pub holder: Option<String>,
    pub number: Secret,
    pub expiry_month: Option<u8>,
    pub expiry_year: Option<u16>,
    pub cvc: Option<Secret>,
    pub pin: Option<Secret>,
    pub brand: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Identity {
    pub full_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    /// ISO 8601 date, `YYYY-MM-DD`.
    pub birthday: Option<String>,
    pub address: Option<Address>,
    pub documents: Vec<IdDocument>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Address {
    pub street: Option<String>,
    pub postal_code: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IdDocument {
    /// "passport", "id card", "driver's license".
    pub kind: String,
    pub number: Secret,
    /// ISO 8601 date.
    pub expires: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SshKey {
    pub private_key: Secret,
    pub public_key: Option<String>,
    pub passphrase: Option<Secret>,
    pub fingerprint: Option<String>,
    pub comment: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct EnvFile {
    pub file_name: Option<String>,
    pub project: Option<String>,
    pub content: Secret,
}

impl EnvFile {
    /// `KEY=VALUE` pairs in file order. Blank lines and `#` comments are skipped, a leading
    /// `export ` is ignored, and matching quotes around a value are removed.
    pub fn variables(&self) -> Vec<(String, Secret)> {
        self.content
            .expose()
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    return None;
                }
                let line = line.strip_prefix("export ").unwrap_or(line);
                let (key, value) = line.split_once('=')?;
                Some((
                    key.trim().to_owned(),
                    Secret::new(strip_quotes(value.trim())),
                ))
            })
            .collect()
    }
}

fn strip_quotes(value: &str) -> &str {
    for quote in ['"', '\''] {
        if value.len() >= 2 && value.starts_with(quote) && value.ends_with(quote) {
            return &value[1..value.len() - 1];
        }
    }
    value
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Database {
    /// "postgres", "mysql", "sqlite", ...
    pub engine: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub database: Option<String>,
    pub username: Option<String>,
    pub password: Option<Secret>,
    pub connection_string: Option<Secret>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::totp::TotpAlgorithm;

    fn round_trip(item: &Item) -> Item {
        let json = serde_json::to_string(item).unwrap();
        serde_json::from_str(&json).unwrap()
    }

    #[test]
    fn every_type_round_trips_and_reports_its_type() {
        for item_type in ItemType::ALL {
            let item = Item::new(item_type.empty_data(), 1);
            assert_eq!(item.item_type(), item_type);
            assert_eq!(round_trip(&item), item, "{item_type:?}");
        }
    }

    #[test]
    fn one_service_holds_an_account_and_two_keys() {
        let mut anthropic = Service::new("Anthropic");
        anthropic.domains = vec![
            DomainRule::new("anthropic.com"),
            DomainRule::new("console.anthropic.com"),
        ];

        let mut account = Item::new(
            ItemData::Login(Login {
                email: Some("you@example.com".into()),
                password: Secret::new("hunter2"),
                totp: Some(TotpConfig {
                    secret: Secret::new("GEZDGNBVGY3TQOJQ"),
                    ..TotpConfig::default()
                }),
                ..Login::default()
            }),
            1,
        );
        account.service_id = Some(anthropic.id);

        let keys: Vec<Item> = ["Production", "Staging"]
            .into_iter()
            .map(|label| {
                let mut key = Item::new(
                    ItemData::ApiKey(ApiKey {
                        key: Secret::new(format!("sk-{label}")),
                        ..ApiKey::default()
                    }),
                    1,
                );
                key.service_id = Some(anthropic.id);
                key.label = label.into();
                key
            })
            .collect();

        for item in std::iter::once(&account).chain(&keys) {
            assert_eq!(item.service_id, Some(anthropic.id));
            assert_eq!(&round_trip(item), item);
        }
        assert_eq!(
            keys.iter()
                .filter(|k| k.item_type() == ItemType::ApiKey)
                .count(),
            2
        );
    }

    #[test]
    fn debug_output_contains_no_secrets() {
        let mut item = Item::new(
            ItemData::Card(Card {
                number: Secret::new("4111111111111111"),
                cvc: Some(Secret::new("123")),
                ..Card::default()
            }),
            1,
        );
        item.notes = Secret::new("pin is 9876");
        let debug = format!("{item:?}");
        for secret in ["4111111111111111", "123", "9876"] {
            assert!(!debug.contains(secret), "{secret} leaked: {debug}");
        }
    }

    #[test]
    fn accepts_missing_and_unknown_fields() {
        let id = Uuid::new_v4();
        let json = format!(
            r#"{{"id":"{id}","data":{{"type":"api_key","key":"sk-1","added_later":true}},"future":1}}"#
        );
        let item: Item = serde_json::from_str(&json).unwrap();
        assert_eq!(item.id, id);
        let ItemData::ApiKey(key) = &item.data else {
            panic!("wrong type")
        };
        assert_eq!(key.key.expose(), "sk-1");
        assert_eq!(key.expires, None);
    }

    #[test]
    fn totp_settings_survive_serialization() {
        let config = TotpConfig {
            algorithm: TotpAlgorithm::Sha256,
            digits: 8,
            period: 60,
            ..TotpConfig::default()
        };
        let item = Item::new(ItemData::Totp(config.clone()), 1);
        let ItemData::Totp(back) = round_trip(&item).data else {
            panic!("wrong type")
        };
        assert_eq!(back, config);
    }

    #[test]
    fn env_file_lists_its_variables() {
        let env = EnvFile {
            content: Secret::new(
                "# comment\n\nexport API_KEY=abc123\nDB_URL=\"postgres://x\"\nNAME='krypt'\nEMPTY=\nbroken line\n",
            ),
            ..EnvFile::default()
        };
        let vars: Vec<(String, String)> = env
            .variables()
            .into_iter()
            .map(|(k, v)| (k, v.expose().to_owned()))
            .collect();
        assert_eq!(
            vars,
            vec![
                ("API_KEY".into(), "abc123".into()),
                ("DB_URL".into(), "postgres://x".into()),
                ("NAME".into(), "krypt".into()),
                ("EMPTY".into(), String::new()),
            ]
        );
    }
}
