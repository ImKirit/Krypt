//! Reads exports of browsers and other password managers and turns them into Krypt entries.
//!
//! Importing takes two steps. [`parse`] reads a file into candidates without touching a vault.
//! [`plan`] then sorts them into existing or new services and leaves out what the vault already
//! holds, so the user sees what will happen before anything is written.
//!
//! Read: Krypt's own encrypted export, Bitwarden JSON (unencrypted), KeePass 2 XML, and CSV from
//! Chrome, Edge, Brave, Opera, Firefox, Safari, Bitwarden, 1Password, LastPass, KeePassXC,
//! Dashlane, Proton Pass, NordPass, RoboForm and any other CSV with recognizable column names.

#![forbid(unsafe_code)]

mod bitwarden;
mod csv_file;
mod draft;
mod error;
mod keepass;
mod plan;
mod site;
mod text;

use std::collections::HashMap;

use krypt_core::export::{self, ExportPayload};
use krypt_core::model::{Item, Service};
use serde::Serialize;

pub use error::{Error, Result};
pub use plan::{Plan, plan};
pub use site::{host_of, site_of};

/// Which app wrote a file, as far as its layout tells.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// Krypt's own encrypted export.
    Krypt,
    /// Bitwarden, as JSON or CSV.
    Bitwarden,
    /// Chrome, Edge, Brave, Opera or Vivaldi.
    Chromium,
    Firefox,
    Safari,
    OnePassword,
    LastPass,
    /// KeePass 2 XML or a KeePassXC CSV.
    KeePass,
    Dashlane,
    ProtonPass,
    NordPass,
    RoboForm,
    /// Any other CSV whose column names Krypt recognizes.
    Csv,
}

/// One entry read from a file, not yet sorted into a service.
#[derive(Debug)]
pub struct Candidate {
    /// The entry's name in the other app, like "GitHub" or "github.com".
    pub name: Option<String>,
    /// The first web address, which decides the service.
    pub url: Option<String>,
    /// The whole service, when the file has services of its own (Krypt exports).
    pub service: Option<Service>,
    pub item: Item,
}

#[derive(Debug)]
pub struct Parsed {
    pub source: Source,
    pub candidates: Vec<Candidate>,
    /// Entries with nothing Krypt can keep, like unsupported types or empty notes.
    pub skipped: usize,
}

/// True if the file is an encrypted Krypt export, which needs its password.
pub fn needs_password(bytes: &[u8]) -> bool {
    export::is_export(text::decode(bytes).trim_start().as_bytes())
}

/// Reads a file. `password` is only used for Krypt exports.
pub fn parse(bytes: &[u8], password: Option<&str>) -> Result<Parsed> {
    let text = text::decode(bytes);
    let content = text.trim_start();
    if content.starts_with('{') {
        if export::is_export(content.as_bytes()) {
            let password = password.ok_or(Error::PasswordRequired)?;
            return Ok(from_krypt(export::open(content.as_bytes(), password)?));
        }
        return bitwarden::parse(content);
    }
    if content.starts_with('<') {
        return keepass::parse(content);
    }
    csv_file::parse(content)
}

/// Services without entries are not carried over.
fn from_krypt(payload: ExportPayload) -> Parsed {
    let services: HashMap<_, _> = payload
        .services
        .into_iter()
        .map(|service| (service.id, service))
        .collect();
    let candidates = payload
        .items
        .into_iter()
        .map(|item| Candidate {
            name: None,
            url: None,
            service: item.service_id.and_then(|id| services.get(&id).cloned()),
            item,
        })
        .collect();
    Parsed {
        source: Source::Krypt,
        candidates,
        skipped: 0,
    }
}
