//! Random passwords and passphrases, drawn from the operating system's random number generator.
//!
//! Passphrases use the EFF large wordlist: 7776 words, so every word adds about 12.9 bits. The
//! list is by the Electronic Frontier Foundation and published under CC BY 3.0 US.

use std::ops::RangeInclusive;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::secret::Secret;
use crate::{Error, Result};

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// No quotes, backslash, backtick, space or angle brackets, which some sites reject or break,
/// and no `^`, a dead key on German keyboards.
const SYMBOLS: &str = "!#$%&()*+,-./:;=?@[]_{|}~";
/// Characters that are easy to confuse in some fonts.
const AMBIGUOUS: &str = "Il1O0o|";

const WORDLIST: &str = include_str!("wordlist/eff_large.txt");
pub const WORDLIST_LEN: usize = 7776;

pub const PASSWORD_LENGTH: RangeInclusive<usize> = 4..=128;
pub const PASSPHRASE_WORDS: RangeInclusive<usize> = 3..=20;
pub const MAX_SEPARATOR_CHARS: usize = 3;

/// A safety net only: with valid options, a password that has every class turns up within a
/// few tries.
const MAX_ATTEMPTS: usize = 10_000;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum GeneratorOptions {
    Password(PasswordOptions),
    Passphrase(PassphraseOptions),
}

impl Default for GeneratorOptions {
    fn default() -> Self {
        Self::Password(PasswordOptions::default())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordOptions {
    pub length: usize,
    pub lowercase: bool,
    pub uppercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            digits: true,
            symbols: true,
            avoid_ambiguous: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PassphraseOptions {
    pub words: usize,
    pub separator: String,
    /// Upper case first letter of every word.
    pub capitalize: bool,
    /// One random digit after one random word.
    pub number: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: 5,
            separator: "-".into(),
            capitalize: true,
            number: true,
        }
    }
}

/// A generated password and its strength.
#[derive(Debug)]
pub struct Generated {
    pub value: Secret,
    /// Entropy in bits, rounded down.
    pub bits: u32,
}

pub fn generate(options: &GeneratorOptions) -> Result<Generated> {
    match options {
        GeneratorOptions::Password(options) => password(options),
        GeneratorOptions::Passphrase(options) => passphrase(options),
    }
}

fn password(options: &PasswordOptions) -> Result<Generated> {
    let classes: Vec<Vec<char>> = [
        (options.lowercase, LOWERCASE),
        (options.uppercase, UPPERCASE),
        (options.digits, DIGITS),
        (options.symbols, SYMBOLS),
    ]
    .into_iter()
    .filter(|(enabled, _)| *enabled)
    .map(|(_, set)| {
        set.chars()
            .filter(|c| !(options.avoid_ambiguous && AMBIGUOUS.contains(*c)))
            .collect()
    })
    .collect();
    if !PASSWORD_LENGTH.contains(&options.length)
        || classes.is_empty()
        || classes.len() > options.length
    {
        return Err(Error::GeneratorOptions);
    }
    let pool = classes.concat();

    // Drawing every character from the whole pool and starting over when a class is missing
    // keeps all passwords that meet the options equally likely.
    for _ in 0..MAX_ATTEMPTS {
        // Every character is ASCII, so the buffer never grows and leaves no copies behind.
        let mut value = Zeroizing::new(String::with_capacity(options.length));
        for _ in 0..options.length {
            value.push(pool[random_below(pool.len())?]);
        }
        if classes
            .iter()
            .all(|class| value.chars().any(|c| class.contains(&c)))
        {
            return Ok(Generated {
                bits: floor_bits(options.length as f64 * log2(pool.len())),
                value: Secret::new(std::mem::take(&mut *value)),
            });
        }
    }
    Err(Error::GeneratorOptions)
}

fn passphrase(options: &PassphraseOptions) -> Result<Generated> {
    if !PASSPHRASE_WORDS.contains(&options.words)
        || options.separator.chars().count() > MAX_SEPARATOR_CHARS
    {
        return Err(Error::GeneratorOptions);
    }
    let list = wordlist();
    let mut words = Vec::with_capacity(options.words);
    for _ in 0..options.words {
        let word = list[random_below(list.len())?];
        // Room for the digit, so appending it does not move the word.
        let mut entry = Zeroizing::new(String::with_capacity(word.len() + 1));
        if options.capitalize {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                entry.extend(first.to_uppercase());
            }
            entry.push_str(chars.as_str());
        } else {
            entry.push_str(word);
        }
        words.push(entry);
    }

    let mut bits = options.words as f64 * log2(list.len());
    if options.number {
        let index = random_below(words.len())?;
        let digit = random_below(10)?;
        words[index].push(char::from(b'0' + digit as u8));
        bits += log2(10) + log2(words.len());
    }

    let parts: Vec<&str> = words.iter().map(|word| word.as_str()).collect();
    let mut value = Zeroizing::new(parts.join(&options.separator));
    Ok(Generated {
        bits: floor_bits(bits),
        value: Secret::new(std::mem::take(&mut *value)),
    })
}

fn wordlist() -> &'static [&'static str] {
    static WORDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    WORDS.get_or_init(|| {
        WORDLIST
            .lines()
            .map(str::trim)
            .filter(|word| !word.is_empty())
            .collect()
    })
}

/// A uniformly random number below `n`.
fn random_below(n: usize) -> Result<usize> {
    let n = u64::try_from(n).map_err(|_| Error::GeneratorOptions)?;
    if n == 0 || n > u64::from(u32::MAX) {
        return Err(Error::GeneratorOptions);
    }
    // Values from the incomplete block at the top would make small results more likely, so
    // they are drawn again.
    let limit = (1u64 << 32) / n * n;
    loop {
        let x = u64::from(getrandom::u32().map_err(|_| Error::Random)?);
        if x < limit {
            return Ok((x % n) as usize);
        }
    }
}

fn log2(n: usize) -> f64 {
    (n as f64).log2()
}

fn floor_bits(bits: f64) -> u32 {
    bits.floor() as u32
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;
    use crate::password::PasswordRules;

    fn password_with(options: PasswordOptions) -> String {
        generate(&GeneratorOptions::Password(options))
            .unwrap()
            .value
            .expose()
            .to_owned()
    }

    fn passphrase_with(options: PassphraseOptions) -> Generated {
        generate(&GeneratorOptions::Passphrase(options)).unwrap()
    }

    #[test]
    fn the_wordlist_is_the_complete_eff_large_list() {
        let list = wordlist();
        assert_eq!(list.len(), WORDLIST_LEN);
        assert_eq!(list.iter().collect::<HashSet<_>>().len(), WORDLIST_LEN);
        assert_eq!((list[0], list[WORDLIST_LEN - 1]), ("abacus", "zoom"));
        assert!(
            list.iter()
                .all(|word| word.chars().all(|c| c.is_ascii_lowercase() || c == '-'))
        );
    }

    #[test]
    fn passwords_have_the_length_and_every_class() {
        for length in [4, 12, 20] {
            for _ in 0..100 {
                let value = password_with(PasswordOptions {
                    length,
                    ..PasswordOptions::default()
                });
                assert_eq!(value.chars().count(), length);
                for set in [LOWERCASE, UPPERCASE, DIGITS, SYMBOLS] {
                    assert!(value.chars().any(|c| set.contains(c)), "{value}");
                }
            }
        }
    }

    #[test]
    fn switched_off_classes_and_ambiguous_characters_stay_out() {
        for _ in 0..200 {
            let value = password_with(PasswordOptions {
                length: 32,
                uppercase: false,
                symbols: false,
                avoid_ambiguous: true,
                ..PasswordOptions::default()
            });
            assert!(
                value
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "{value}"
            );
            assert!(!value.chars().any(|c| AMBIGUOUS.contains(c)), "{value}");
        }
    }

    #[test]
    fn the_default_password_reports_its_strength() {
        let generated = generate(&GeneratorOptions::default()).unwrap();
        // 20 characters from 87: 20 * log2(87) = 128.9 bits.
        assert_eq!(generated.bits, 128);
        let other = generate(&GeneratorOptions::default()).unwrap();
        assert_ne!(generated.value.expose(), other.value.expose());
    }

    #[test]
    fn passphrases_are_words_from_the_list() {
        let list: HashSet<&str> = wordlist().iter().copied().collect();
        for _ in 0..100 {
            let generated = passphrase_with(PassphraseOptions {
                words: 6,
                separator: " ".into(),
                capitalize: false,
                number: false,
            });
            let words: Vec<&str> = generated.value.expose().split(' ').collect();
            assert_eq!(words.len(), 6);
            assert!(words.iter().all(|word| list.contains(word)));
            // 6 * log2(7776) = 77.5 bits.
            assert_eq!(generated.bits, 77);
        }
    }

    #[test]
    fn the_default_passphrase_is_capitalized_with_one_digit() {
        for _ in 0..100 {
            let generated = passphrase_with(PassphraseOptions {
                separator: ".".into(),
                ..PassphraseOptions::default()
            });
            let value = generated.value.expose();
            let words: Vec<&str> = value.split('.').collect();
            assert_eq!(words.len(), 5, "{value}");
            assert!(
                words
                    .iter()
                    .all(|word| word.starts_with(|c: char| c.is_ascii_uppercase()))
            );
            assert_eq!(value.chars().filter(char::is_ascii_digit).count(), 1);
            assert!(
                words
                    .iter()
                    .any(|word| word.ends_with(|c: char| c.is_ascii_digit()))
            );
        }
        let default = passphrase_with(PassphraseOptions::default());
        assert!(PasswordRules::check(default.value.expose()).all_met());
    }

    #[test]
    fn impossible_options_are_refused() {
        let no_classes = PasswordOptions {
            lowercase: false,
            uppercase: false,
            digits: false,
            symbols: false,
            ..PasswordOptions::default()
        };
        let too_short = PasswordOptions {
            length: 3,
            ..PasswordOptions::default()
        };
        let too_long = PasswordOptions {
            length: 129,
            ..PasswordOptions::default()
        };
        for options in [no_classes, too_short, too_long] {
            assert_eq!(
                generate(&GeneratorOptions::Password(options)).unwrap_err(),
                Error::GeneratorOptions
            );
        }
        let few_words = PassphraseOptions {
            words: 2,
            ..PassphraseOptions::default()
        };
        let long_separator = PassphraseOptions {
            separator: "----".into(),
            ..PassphraseOptions::default()
        };
        for options in [few_words, long_separator] {
            assert_eq!(
                generate(&GeneratorOptions::Passphrase(options)).unwrap_err(),
                Error::GeneratorOptions
            );
        }
    }

    #[test]
    fn random_below_reaches_every_value() {
        let mut seen = [0usize; 7];
        for _ in 0..7000 {
            seen[random_below(7).unwrap()] += 1;
        }
        // About 1000 each; 700 is more than ten standard deviations away.
        assert!(seen.iter().all(|&count| count > 700), "{seen:?}");
        assert_eq!(random_below(0).unwrap_err(), Error::GeneratorOptions);
    }

    #[test]
    fn options_read_from_json_with_defaults() {
        let options: GeneratorOptions =
            serde_json::from_str(r#"{"kind":"password","length":16}"#).unwrap();
        assert_eq!(
            options,
            GeneratorOptions::Password(PasswordOptions {
                length: 16,
                ..PasswordOptions::default()
            })
        );
        let options: GeneratorOptions = serde_json::from_str(r#"{"kind":"passphrase"}"#).unwrap();
        assert_eq!(
            options,
            GeneratorOptions::Passphrase(PassphraseOptions::default())
        );
    }
}
