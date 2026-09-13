//! The recovery key: 160 random bits, shown once at setup, written as eight groups of four.

use std::fmt;

use base32::Alphabet;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto;
use crate::{Error, Result};

pub const RECOVERY_KEY_LEN: usize = 20;

/// 20 bytes encode to exactly 32 Base32 characters.
const ENCODED_LEN: usize = 32;
const GROUP: usize = 4;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoveryKey([u8; RECOVERY_KEY_LEN]);

impl RecoveryKey {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; RECOVERY_KEY_LEN];
        crypto::random_bytes(&mut bytes)?;
        let key = Self(bytes);
        bytes.zeroize();
        Ok(key)
    }

    pub fn as_bytes(&self) -> &[u8; RECOVERY_KEY_LEN] {
        &self.0
    }

    /// Crockford Base32 in groups of four, e.g. `8F3K-QW2M-...`. Crockford leaves out I, L, O
    /// and U, so nothing can be misread when copying it by hand.
    pub fn to_display_string(&self) -> Zeroizing<String> {
        let encoded = Zeroizing::new(base32::encode(Alphabet::Crockford, &self.0));
        let mut out = Zeroizing::new(String::with_capacity(ENCODED_LEN + ENCODED_LEN / GROUP - 1));
        for (i, ch) in encoded.chars().enumerate() {
            if i > 0 && i % GROUP == 0 {
                out.push('-');
            }
            out.push(ch);
        }
        out
    }

    /// Accepts upper or lower case, with or without dashes and spaces.
    pub fn parse(input: &str) -> Result<Self> {
        let cleaned: Zeroizing<String> = Zeroizing::new(
            input
                .chars()
                .filter(|c| !c.is_whitespace() && *c != '-')
                .map(|c| c.to_ascii_uppercase())
                .collect(),
        );
        if cleaned.len() != ENCODED_LEN || !cleaned.is_ascii() {
            return Err(Error::InvalidRecoveryKey);
        }
        let bytes = Zeroizing::new(
            base32::decode(Alphabet::Crockford, &cleaned).ok_or(Error::InvalidRecoveryKey)?,
        );
        let mut array: [u8; RECOVERY_KEY_LEN] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::InvalidRecoveryKey)?;
        let key = Self(array);
        array.zeroize();
        Ok(key)
    }
}

impl fmt::Debug for RecoveryKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RecoveryKey(***)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn displays_as_eight_groups_of_four() {
        let key = RecoveryKey::generate().unwrap();
        let shown = key.to_display_string();
        let groups: Vec<&str> = shown.split('-').collect();
        assert_eq!(groups.len(), 8, "{}", shown.as_str());
        assert!(groups.iter().all(|g| g.len() == 4));
        assert!(!shown.contains(['I', 'L', 'O', 'U']));
    }

    #[test]
    fn parses_what_it_displays_in_any_spelling() {
        let key = RecoveryKey::generate().unwrap();
        let shown = key.to_display_string();
        let variants = [
            shown.to_string(),
            shown.to_lowercase(),
            shown.replace('-', ""),
            shown.replace('-', " "),
        ];
        for variant in variants {
            assert_eq!(
                RecoveryKey::parse(&variant).unwrap().as_bytes(),
                key.as_bytes(),
                "{variant}"
            );
        }
    }

    #[test]
    fn rejects_wrong_length_and_foreign_characters() {
        let key = RecoveryKey::generate().unwrap();
        let shown = key.to_display_string();
        assert_eq!(
            RecoveryKey::parse(&shown[..shown.len() - 1]).unwrap_err(),
            Error::InvalidRecoveryKey
        );
        assert_eq!(
            RecoveryKey::parse(&format!("{}A", shown.as_str())).unwrap_err(),
            Error::InvalidRecoveryKey
        );
        assert_eq!(
            RecoveryKey::parse(&"U".repeat(32)).unwrap_err(),
            Error::InvalidRecoveryKey
        );
        assert_eq!(
            RecoveryKey::parse("").unwrap_err(),
            Error::InvalidRecoveryKey
        );
    }

    #[test]
    fn debug_hides_the_key() {
        assert_eq!(
            format!("{:?}", RecoveryKey::generate().unwrap()),
            "RecoveryKey(***)"
        );
    }
}
