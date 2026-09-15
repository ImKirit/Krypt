//! Rules for the passwords that guard everything at once: the master password and the password
//! of an encrypted export.

use serde::Serialize;
use unicode_normalization::UnicodeNormalization;
use zeroize::Zeroizing;

/// Fewest characters such a password may have, counted after normalization.
pub const MIN_CHARS: usize = 8;

/// Which rules a password meets. New master and export passwords must meet all of them;
/// passwords set before the rules existed keep working.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PasswordRules {
    pub length: bool,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digit: bool,
    /// Any character that is neither a letter, a digit nor white space.
    pub special: bool,
}

impl PasswordRules {
    pub fn check(password: &str) -> Self {
        let normalized = normalize(password);
        let mut rules = Self {
            length: normalized.chars().count() >= MIN_CHARS,
            ..Self::default()
        };
        for c in normalized.chars() {
            if c.is_lowercase() {
                rules.lowercase = true;
            } else if c.is_uppercase() {
                rules.uppercase = true;
            } else if c.is_numeric() {
                rules.digit = true;
            } else if !c.is_alphabetic() && !c.is_whitespace() {
                rules.special = true;
            }
        }
        rules
    }

    pub fn all_met(&self) -> bool {
        self.length && self.lowercase && self.uppercase && self.digit && self.special
    }
}

/// RFC 8265 (OpaqueString): passwords are compared in Unicode NFC, so "é" typed as one code
/// point on one keyboard and as "e" plus an accent on another is the same password.
pub fn normalize(password: &str) -> Zeroizing<String> {
    Zeroizing::new(password.nfc().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_password_with_every_class_passes() {
        assert!(PasswordRules::check("Abcdef1!").all_met());
        assert!(PasswordRules::check("Correct-Horse-7").all_met());
        assert!(PasswordRules::check("Äpfel-Süß-9").all_met());
    }

    #[test]
    fn each_missing_rule_is_reported() {
        let cases = [
            ("Abc1!", "length"),
            ("abcdefg1!", "uppercase"),
            ("ABCDEFG1!", "lowercase"),
            ("Abcdefgh!", "digit"),
            ("Abcdefg1", "special"),
        ];
        for (password, missing) in cases {
            let rules = PasswordRules::check(password);
            assert!(!rules.all_met(), "{password}");
            let broken = match missing {
                "length" => !rules.length,
                "uppercase" => !rules.uppercase,
                "lowercase" => !rules.lowercase,
                "digit" => !rules.digit,
                _ => !rules.special,
            };
            assert!(broken, "{password} should miss {missing}: {rules:?}");
        }
    }

    #[test]
    fn white_space_is_not_a_special_character() {
        assert!(!PasswordRules::check("Abcdef 1").special);
    }

    #[test]
    fn length_is_counted_after_normalization() {
        // Eight code points as typed, seven once "e" and the combining accent become "é".
        let decomposed = "Abce\u{301}1!x";
        assert_eq!(decomposed.chars().count(), 8);
        assert!(!PasswordRules::check(decomposed).length);
        assert_eq!(normalize(decomposed).as_str(), "Abc\u{e9}1!x");
    }
}
