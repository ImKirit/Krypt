use std::cell::Cell;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Stands in for a non-empty secret while [`masked`] is active.
pub const MASKED: &str = "__krypt_masked__";

thread_local! {
    static MASKING: Cell<bool> = const { Cell::new(false) };
}

/// A secret string: a password, an API key, a card number, a private key.
///
/// Wiped from memory when dropped and never printed by `Debug`, so a stray `{:?}` in a log
/// line cannot leak it.
#[derive(Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// True if this value is the placeholder written by [`masked`], not a real secret.
    pub fn is_masked(&self) -> bool {
        self.0 == MASKED
    }
}

/// Runs `f` with every non-empty [`Secret`] serializing as [`MASKED`].
///
/// For views that must not carry secrets, like the entry a user interface shows before
/// anything is revealed. Sealing a record refuses to run inside this.
pub fn masked<R>(f: impl FnOnce() -> R) -> R {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            MASKING.with(|m| m.set(self.0));
        }
    }
    let _restore = Restore(MASKING.with(|m| m.replace(true)));
    f()
}

pub(crate) fn masking_active() -> bool {
    MASKING.with(Cell::get)
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if masking_active() && !self.0.is_empty() {
            serializer.serialize_str(MASKED)
        } else {
            serializer.serialize_str(&self.0)
        }
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(***)")
    }
}

impl From<&str> for Secret {
    fn from(value: &str) -> Self {
        Self::new(value)
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_value() {
        let secret = Secret::new("hunter2");
        assert_eq!(format!("{secret:?}"), "Secret(***)");
        assert_eq!(secret.expose(), "hunter2");
    }

    #[test]
    fn serializes_as_a_plain_string() {
        let json = serde_json::to_string(&Secret::new("abc")).unwrap();
        assert_eq!(json, "\"abc\"");
        let back: Secret = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), "abc");
    }

    #[test]
    fn masking_hides_values_only_inside_the_closure() {
        let secrets = [Secret::new("hunter2"), Secret::default()];
        let inside = masked(|| serde_json::to_string(&secrets).unwrap());
        assert_eq!(inside, format!("[\"{MASKED}\",\"\"]"));
        assert_eq!(
            serde_json::to_string(&secrets).unwrap(),
            "[\"hunter2\",\"\"]"
        );
        assert!(!masking_active());
    }

    #[test]
    fn masking_is_restored_after_a_panic() {
        let result = std::panic::catch_unwind(|| masked(|| panic!("boom")));
        assert!(result.is_err());
        assert!(!masking_active());
    }

    #[test]
    fn recognizes_the_placeholder() {
        assert!(Secret::new(MASKED).is_masked());
        assert!(!Secret::new("hunter2").is_masked());
    }
}
