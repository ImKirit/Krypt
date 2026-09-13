//! Vault storage for Krypt: one SQLite file per vault.
//!
//! Only ids, revisions and timestamps are stored in the clear. Service names, domains, item
//! types and every field of every entry are encrypted one record at a time with
//! `krypt_core::record`, so a stolen file reveals how many entries exist and nothing else.

#![forbid(unsafe_code)]

mod backup;
mod error;
mod schema;
mod time;
mod vault;

pub use error::{Error, Result};
pub use vault::{LockedVault, NewVault, Record, UnlockFailed, UnlockResult, Vault};
