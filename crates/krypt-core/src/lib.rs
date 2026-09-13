//! Krypt core: cryptography, key slots, data model and TOTP.
//!
//! This crate knows nothing about files, windows, networks or the UI. That keeps a single
//! implementation for the desktop app, the phone apps and, compiled to WebAssembly, the
//! browser extension.

#![forbid(unsafe_code)]

pub mod crypto;
mod error;
pub mod keyslot;
pub mod model;
pub mod record;
pub mod recovery;
pub mod secret;
pub mod totp;

pub use error::{Error, Result};
