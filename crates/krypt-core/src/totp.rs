//! Time-based one-time passwords, RFC 6238 on top of the HOTP truncation from RFC 4226.

use base32::Alphabet;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

use crate::secret::Secret;
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TotpConfig {
    /// Base32, as the service shows it. Spaces and lower case are fine.
    pub secret: Secret,
    pub algorithm: TotpAlgorithm,
    /// 6 to 8.
    pub digits: u8,
    /// Seconds per code, usually 30.
    pub period: u32,
    pub issuer: Option<String>,
    pub account: Option<String>,
}

impl Default for TotpConfig {
    fn default() -> Self {
        Self {
            secret: Secret::default(),
            algorithm: TotpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            issuer: None,
            account: None,
        }
    }
}

impl TotpConfig {
    /// The code valid at `unix_seconds`.
    pub fn code_at(&self, unix_seconds: u64) -> Result<Zeroizing<String>> {
        self.check()?;
        let key = decode_secret(self.secret.expose())?;
        hotp(
            &key,
            unix_seconds / u64::from(self.period),
            self.digits,
            self.algorithm,
        )
    }

    /// Seconds until the code at `unix_seconds` expires, between 1 and `period`.
    pub fn seconds_remaining(&self, unix_seconds: u64) -> Result<u32> {
        self.check()?;
        let period = u64::from(self.period);
        Ok((period - unix_seconds % period) as u32)
    }

    fn check(&self) -> Result<()> {
        if (6..=8).contains(&self.digits) && self.period > 0 {
            Ok(())
        } else {
            Err(Error::InvalidTotpSettings)
        }
    }

    /// Reads an `otpauth://totp/Issuer:account?secret=...` link, the format setup pages put
    /// into their QR codes. HOTP links are refused: Krypt keeps no counter.
    pub fn from_uri(uri: &str) -> Result<Self> {
        const PREFIX: &str = "otpauth://totp/";
        let uri = uri.trim();
        let rest = match uri.get(..PREFIX.len()) {
            Some(scheme) if scheme.eq_ignore_ascii_case(PREFIX) => &uri[PREFIX.len()..],
            _ => return Err(Error::InvalidTotpUri),
        };
        let (label, query) = rest.split_once('?').unwrap_or((rest, ""));
        let label = percent_decode(label)?;
        let (issuer, account) = match label.split_once(':') {
            Some((issuer, account)) => (non_empty(issuer), non_empty(account)),
            None => (None, non_empty(&label)),
        };
        let mut config = Self {
            issuer,
            account,
            ..Self::default()
        };

        let mut secret = None;
        for pair in query.split('&').filter(|pair| !pair.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            let value = percent_decode(value)?;
            match name.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(value),
                // The parameter wins over the label, as in Google's key URI format.
                "issuer" => {
                    if let Some(issuer) = non_empty(&value) {
                        config.issuer = Some(issuer);
                    }
                }
                "algorithm" => {
                    config.algorithm = match value.to_ascii_lowercase().as_str() {
                        "sha1" => TotpAlgorithm::Sha1,
                        "sha256" => TotpAlgorithm::Sha256,
                        "sha512" => TotpAlgorithm::Sha512,
                        _ => return Err(Error::InvalidTotpSettings),
                    }
                }
                "digits" => {
                    config.digits = value
                        .trim()
                        .parse()
                        .map_err(|_| Error::InvalidTotpSettings)?
                }
                "period" => {
                    config.period = value
                        .trim()
                        .parse()
                        .map_err(|_| Error::InvalidTotpSettings)?
                }
                _ => {}
            }
        }

        let secret = secret.ok_or(Error::InvalidTotpSecret)?;
        decode_secret(&secret)?;
        config.secret = Secret::new(secret.as_str());
        config.check()?;
        Ok(config)
    }
}

fn non_empty(text: &str) -> Option<String> {
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// Decodes `%XX` escapes. Anything that is not UTF-8 afterwards is refused.
fn percent_decode(text: &str) -> Result<Zeroizing<String>> {
    let bytes = text.as_bytes();
    let mut out = Zeroizing::new(Vec::with_capacity(bytes.len()));
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text
                .get(i + 1..i + 3)
                .filter(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()))
                .ok_or(Error::InvalidTotpUri)?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| Error::InvalidTotpUri)?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(std::mem::take(&mut *out))
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidTotpUri)
}

/// Decodes a Base32 secret as services print it: any case, spaces, dashes and padding allowed.
pub fn decode_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>> {
    let cleaned: Zeroizing<String> = Zeroizing::new(
        secret
            .chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    );
    if cleaned.is_empty() {
        return Err(Error::InvalidTotpSecret);
    }
    base32::decode(Alphabet::Rfc4648 { padding: false }, &cleaned)
        .filter(|bytes| !bytes.is_empty())
        .map(Zeroizing::new)
        .ok_or(Error::InvalidTotpSecret)
}

macro_rules! hmac_bytes {
    ($digest:ty, $key:expr, $message:expr) => {{
        let mut mac = <Hmac<$digest> as KeyInit>::new_from_slice($key)
            .map_err(|_| Error::InvalidTotpSecret)?;
        mac.update($message);
        mac.finalize().into_bytes().to_vec()
    }};
}

fn hotp(
    key: &[u8],
    counter: u64,
    digits: u8,
    algorithm: TotpAlgorithm,
) -> Result<Zeroizing<String>> {
    let message = counter.to_be_bytes();
    let mac = Zeroizing::new(match algorithm {
        TotpAlgorithm::Sha1 => hmac_bytes!(Sha1, key, &message),
        TotpAlgorithm::Sha256 => hmac_bytes!(Sha256, key, &message),
        TotpAlgorithm::Sha512 => hmac_bytes!(Sha512, key, &message),
    });
    // RFC 4226, section 5.3: dynamic truncation.
    let offset = usize::from(mac[mac.len() - 1] & 0x0f);
    let binary = (u32::from(mac[offset] & 0x7f) << 24)
        | (u32::from(mac[offset + 1]) << 16)
        | (u32::from(mac[offset + 2]) << 8)
        | u32::from(mac[offset + 3]);
    let code = binary % 10u32.pow(u32::from(digits));
    Ok(Zeroizing::new(format!(
        "{code:0width$}",
        width = usize::from(digits)
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238, appendix A and B.
    const SEED_SHA1: &[u8] = b"12345678901234567890";
    const SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    const VECTORS: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ];

    #[test]
    fn matches_all_rfc6238_vectors() {
        for (time, sha1, sha256, sha512) in VECTORS {
            let counter = time / 30;
            assert_eq!(
                hotp(SEED_SHA1, counter, 8, TotpAlgorithm::Sha1)
                    .unwrap()
                    .as_str(),
                sha1,
                "SHA1 {time}"
            );
            assert_eq!(
                hotp(SEED_SHA256, counter, 8, TotpAlgorithm::Sha256)
                    .unwrap()
                    .as_str(),
                sha256,
                "SHA256 {time}"
            );
            assert_eq!(
                hotp(SEED_SHA512, counter, 8, TotpAlgorithm::Sha512)
                    .unwrap()
                    .as_str(),
                sha512,
                "SHA512 {time}"
            );
        }
    }

    #[test]
    fn config_decodes_a_secret_the_way_services_print_it() {
        // SEED_SHA1 in Base32, lower case and grouped like many setup pages show it.
        let config = TotpConfig {
            secret: Secret::new("gezd gnbv gy3t qojq gezd gnbv gy3t qojq"),
            digits: 8,
            ..TotpConfig::default()
        };
        assert_eq!(config.code_at(59).unwrap().as_str(), "94287082");

        let six_digits = TotpConfig {
            digits: 6,
            ..config
        };
        assert_eq!(six_digits.code_at(59).unwrap().as_str(), "287082");
    }

    #[test]
    fn counts_down_within_the_period() {
        let config = TotpConfig::default();
        assert_eq!(config.seconds_remaining(59).unwrap(), 1);
        assert_eq!(config.seconds_remaining(60).unwrap(), 30);
        assert_eq!(config.seconds_remaining(75).unwrap(), 15);
    }

    #[test]
    fn rejects_bad_settings_and_secrets() {
        let secret = Secret::new("GEZDGNBVGY3TQOJQ");
        let five_digits = TotpConfig {
            secret: secret.clone(),
            digits: 5,
            ..TotpConfig::default()
        };
        assert_eq!(
            five_digits.code_at(0).unwrap_err(),
            Error::InvalidTotpSettings
        );
        let no_period = TotpConfig {
            secret,
            period: 0,
            ..TotpConfig::default()
        };
        assert_eq!(
            no_period.code_at(0).unwrap_err(),
            Error::InvalidTotpSettings
        );
        assert_eq!(decode_secret("").unwrap_err(), Error::InvalidTotpSecret);
        assert_eq!(
            decode_secret("not base32!").unwrap_err(),
            Error::InvalidTotpSecret
        );
    }

    #[test]
    fn reads_otpauth_links() {
        let config = TotpConfig::from_uri(
            "otpauth://totp/ACME%20Co:jane%40example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\
             &issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
        )
        .unwrap();
        assert_eq!(config.secret.expose(), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
        assert_eq!(config.issuer.as_deref(), Some("ACME Co"));
        assert_eq!(config.account.as_deref(), Some("jane@example.com"));
        assert_eq!(
            (config.algorithm, config.digits, config.period),
            (TotpAlgorithm::Sha256, 8, 60)
        );

        let minimal = TotpConfig::from_uri("OTPAUTH://TOTP/alice?secret=gezdgnbvgy3tqojq").unwrap();
        assert_eq!(minimal.issuer, None);
        assert_eq!(minimal.account.as_deref(), Some("alice"));
        assert_eq!(
            (minimal.algorithm, minimal.digits, minimal.period),
            (TotpAlgorithm::Sha1, 6, 30)
        );
        assert!(minimal.code_at(59).is_ok());
    }

    #[test]
    fn the_issuer_parameter_wins_over_the_label() {
        let config =
            TotpConfig::from_uri("otpauth://totp/Old:bob?issuer=New&secret=GEZDGNBVGY3TQOJQ")
                .unwrap();
        assert_eq!(config.issuer.as_deref(), Some("New"));
        assert_eq!(config.account.as_deref(), Some("bob"));
    }

    #[test]
    fn refuses_links_it_cannot_use() {
        let cases = [
            (
                "otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=1",
                Error::InvalidTotpUri,
            ),
            (
                "https://example.com/?secret=GEZDGNBVGY3TQOJQ",
                Error::InvalidTotpUri,
            ),
            ("otpauth://totp/x?issuer=y", Error::InvalidTotpSecret),
            (
                "otpauth://totp/x?secret=not-base32!",
                Error::InvalidTotpSecret,
            ),
            (
                "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&algorithm=MD5",
                Error::InvalidTotpSettings,
            ),
            (
                "otpauth://totp/x?secret=GEZDGNBVGY3TQOJQ&digits=12",
                Error::InvalidTotpSettings,
            ),
            (
                "otpauth://totp/%zz?secret=GEZDGNBVGY3TQOJQ",
                Error::InvalidTotpUri,
            ),
            ("otpauth://t\u{f6}tp", Error::InvalidTotpUri),
            ("", Error::InvalidTotpUri),
        ];
        for (uri, expected) in cases {
            assert_eq!(TotpConfig::from_uri(uri).unwrap_err(), expected, "{uri}");
        }
    }
}
