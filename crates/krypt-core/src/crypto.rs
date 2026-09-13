//! The primitives: Argon2id, HKDF-SHA256, XChaCha20-Poly1305 and operating system randomness.
//!
//! Everything else in Krypt goes through these functions. They are thin wrappers around the
//! RustCrypto crates, pinned to published test vectors in the tests at the bottom.

use std::fmt;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{AeadInOut, KeyInit};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{Error, Result};

pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;

/// First byte of every ciphertext. Changes only if the cipher or the layout changes, so old
/// records stay readable.
const CIPHERTEXT_VERSION: u8 = 1;

/// A 256-bit symmetric key. Wiped from memory when dropped, never printed.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    pub fn random() -> Result<Self> {
        let mut bytes = [0u8; KEY_LEN];
        random_bytes(&mut bytes)?;
        let key = Self(bytes);
        bytes.zeroize();
        Ok(key)
    }

    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }

    /// Compares without stopping at the first differing byte.
    pub fn same_as(&self, other: &Key) -> bool {
        self.0
            .iter()
            .zip(other.0.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
    }
}

impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Key(***)")
    }
}

/// Argon2id cost parameters, stored next to every password key slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_cost_kib: u32,
    /// Passes over the memory.
    pub t_cost: u32,
    /// Lanes.
    pub p_cost: u32,
}

impl KdfParams {
    /// Used for new vaults: 64 MiB, 3 passes, 4 lanes.
    pub const DEFAULT: Self = Self {
        m_cost_kib: 65_536,
        t_cost: 3,
        p_cost: 4,
    };

    /// Upper bounds accepted from a vault file, so a crafted file cannot freeze the machine.
    /// No lower bound is needed: weaker parameters produce a different key, which cannot
    /// open the real vault key.
    pub const MAX_M_COST_KIB: u32 = 1_048_576;
    pub const MAX_T_COST: u32 = 20;
    pub const MAX_P_COST: u32 = 16;

    pub fn validate(&self) -> Result<()> {
        let ok = self.m_cost_kib <= Self::MAX_M_COST_KIB
            && (1..=Self::MAX_T_COST).contains(&self.t_cost)
            && (1..=Self::MAX_P_COST).contains(&self.p_cost)
            && self.m_cost_kib >= 8 * self.p_cost;
        if ok { Ok(()) } else { Err(Error::KdfParams) }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Fills `buf` from the operating system CSPRNG.
pub fn random_bytes(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|_| Error::Random)
}

/// Argon2id version 1.3 with a 32-byte output.
pub fn argon2id(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Key> {
    params.validate()?;
    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost,
        Some(KEY_LEN),
    )
    .map_err(|_| Error::KdfParams)?;
    let mut out = [0u8; KEY_LEN];
    let result = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params)
        .hash_password_into(password, salt, &mut out);
    let key = Key(out);
    out.zeroize();
    result.map_err(|_| Error::Kdf)?;
    Ok(key)
}

/// HKDF with SHA-256 as defined in RFC 5869, extract then expand into `okm`.
pub fn hkdf_sha256(salt: Option<&[u8]>, ikm: &[u8], info: &[u8], okm: &mut [u8]) -> Result<()> {
    let (_, hkdf) = Hkdf::<Sha256>::extract(salt, ikm);
    hkdf.expand(info, okm).map_err(|_| Error::Kdf)
}

/// Derives a 32-byte key for one purpose. `info` names the purpose, e.g.
/// `krypt/v1/kek/password`, so keys for different purposes never coincide.
pub fn derive_key(ikm: &[u8], info: &str) -> Result<Key> {
    let mut out = [0u8; KEY_LEN];
    let result = hkdf_sha256(None, ikm, info.as_bytes(), &mut out);
    let key = Key(out);
    out.zeroize();
    result?;
    Ok(key)
}

/// Encrypts with XChaCha20-Poly1305 under a fresh random nonce.
///
/// Layout: `version (1) || nonce (24) || ciphertext || tag (16)`. `aad` is authenticated but
/// not stored; the same bytes must be passed to [`open`].
pub fn seal(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    random_bytes(&mut nonce)?;
    let body = xchacha_encrypt(key.as_bytes(), &nonce, plaintext, aad)?;
    let mut out = Vec::with_capacity(1 + NONCE_LEN + body.len());
    out.push(CIPHERTEXT_VERSION);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Reverses [`seal`]. Any change to the key, the ciphertext or the `aad` fails with
/// [`Error::Decrypt`].
pub fn open(key: &Key, ciphertext: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let (&version, rest) = ciphertext.split_first().ok_or(Error::Truncated)?;
    if version != CIPHERTEXT_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    if rest.len() < NONCE_LEN + TAG_LEN {
        return Err(Error::Truncated);
    }
    let (nonce, body) = rest.split_at(NONCE_LEN);
    let nonce: &[u8; NONCE_LEN] = nonce.try_into().map_err(|_| Error::Truncated)?;
    xchacha_decrypt(key.as_bytes(), nonce, body, aad)
}

fn xchacha_encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    // Plaintext is encrypted in place; if encryption fails, the buffer is wiped on drop.
    let mut buffer = Zeroizing::new(Vec::with_capacity(plaintext.len() + TAG_LEN));
    buffer.extend_from_slice(plaintext);
    cipher
        .encrypt_in_place(&(*nonce).into(), aad, &mut *buffer)
        .map_err(|_| Error::Encrypt)?;
    Ok(std::mem::take(&mut *buffer))
}

fn xchacha_decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = XChaCha20Poly1305::new(&(*key).into());
    let mut buffer = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_in_place(&(*nonce).into(), aad, &mut *buffer)
        .map_err(|_| Error::Decrypt)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    #[test]
    fn argon2id_matches_reference_vectors() {
        // phc-winner-argon2, src/test.c: Argon2id, version 0x13, "password", "somesalt".
        let cases = [
            (
                256,
                2,
                1,
                "9dfeb910e80bad0311fee20f9c0e2b12c17987b4cac90c2ef54d5b3021c68bfe",
            ),
            (
                256,
                2,
                2,
                "6d093c501fd5999645e0ea3bf620d7b8be7fd2db59c20d9fff9539da2bf57037",
            ),
            (
                65_536,
                2,
                1,
                "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7",
            ),
            (
                65_536,
                1,
                1,
                "f6a5adc1ba723dddef9b5ac1d464e180fcd9dffc9d1cbf76cca2fed795d9ca98",
            ),
        ];
        for (m_cost_kib, t_cost, p_cost, expected) in cases {
            let params = KdfParams {
                m_cost_kib,
                t_cost,
                p_cost,
            };
            let key = argon2id(b"password", b"somesalt", params).unwrap();
            assert_eq!(hex::encode(key.as_bytes()), expected, "{params:?}");
        }
    }

    #[test]
    fn hkdf_sha256_matches_rfc5869_test_case_1() {
        let mut okm = [0u8; 42];
        hkdf_sha256(
            Some(&unhex("000102030405060708090a0b0c")),
            &[0x0b; 22],
            &unhex("f0f1f2f3f4f5f6f7f8f9"),
            &mut okm,
        )
        .unwrap();
        assert_eq!(
            hex::encode(okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
        );
    }

    #[test]
    fn xchacha20poly1305_matches_draft_vector() {
        // draft-irtf-cfrg-xchacha-03, appendix A.3.1.
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one \
                          tip for the future, sunscreen would be it.";
        let aad = unhex("50515253c0c1c2c3c4c5c6c7");
        let key: [u8; KEY_LEN] =
            unhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
                .try_into()
                .unwrap();
        let nonce: [u8; NONCE_LEN] = unhex("404142434445464748494a4b4c4d4e4f5051525354555657")
            .try_into()
            .unwrap();
        let expected = unhex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb\
             731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452\
             2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9\
             21f9664c97637da9768812f615c68b13b52e\
             c0875924c1c7987947deafd8780acf49",
        );

        let sealed = xchacha_encrypt(&key, &nonce, plaintext, &aad).unwrap();
        assert_eq!(hex::encode(&sealed), hex::encode(&expected));
        let opened = xchacha_decrypt(&key, &nonce, &sealed, &aad).unwrap();
        assert_eq!(opened.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn seal_then_open_round_trips() {
        let key = Key::random().unwrap();
        let sealed = seal(&key, b"top secret", b"context").unwrap();
        assert_eq!(sealed.len(), 1 + NONCE_LEN + 10 + TAG_LEN);
        assert_eq!(
            open(&key, &sealed, b"context").unwrap().as_slice(),
            b"top secret"
        );
    }

    #[test]
    fn every_seal_uses_a_new_nonce() {
        let key = Key::random().unwrap();
        let a = seal(&key, b"same", b"").unwrap();
        let b = seal(&key, b"same", b"").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn open_rejects_wrong_key_and_wrong_aad() {
        let key = Key::random().unwrap();
        let sealed = seal(&key, b"top secret", b"item/1").unwrap();
        assert_eq!(
            open(&Key::random().unwrap(), &sealed, b"item/1").unwrap_err(),
            Error::Decrypt
        );
        assert_eq!(open(&key, &sealed, b"item/2").unwrap_err(), Error::Decrypt);
    }

    #[test]
    fn open_rejects_any_flipped_byte() {
        let key = Key::random().unwrap();
        let sealed = seal(&key, b"top secret", b"").unwrap();
        // Byte 0 is the version and gets its own error; every other byte must fail to decrypt.
        for i in 1..sealed.len() {
            let mut tampered = sealed.clone();
            tampered[i] ^= 0x01;
            assert_eq!(
                open(&key, &tampered, b"").unwrap_err(),
                Error::Decrypt,
                "byte {i}"
            );
        }
    }

    #[test]
    fn open_rejects_unknown_version_and_short_input() {
        let key = Key::random().unwrap();
        let mut sealed = seal(&key, b"x", b"").unwrap();
        sealed[0] = 2;
        assert_eq!(
            open(&key, &sealed, b"").unwrap_err(),
            Error::UnsupportedVersion(2)
        );
        assert_eq!(open(&key, &[], b"").unwrap_err(), Error::Truncated);
        assert_eq!(
            open(&key, &[1; 1 + NONCE_LEN + TAG_LEN - 1], b"").unwrap_err(),
            Error::Truncated
        );
    }

    #[test]
    fn kdf_params_are_bounded() {
        assert!(KdfParams::DEFAULT.validate().is_ok());
        let too_much_memory = KdfParams {
            m_cost_kib: KdfParams::MAX_M_COST_KIB + 1,
            ..KdfParams::DEFAULT
        };
        let no_passes = KdfParams {
            t_cost: 0,
            ..KdfParams::DEFAULT
        };
        let too_many_lanes = KdfParams {
            p_cost: 17,
            ..KdfParams::DEFAULT
        };
        let memory_below_lanes = KdfParams {
            m_cost_kib: 16,
            t_cost: 1,
            p_cost: 4,
        };
        for params in [
            too_much_memory,
            no_passes,
            too_many_lanes,
            memory_below_lanes,
        ] {
            assert_eq!(
                params.validate().unwrap_err(),
                Error::KdfParams,
                "{params:?}"
            );
        }
    }

    #[test]
    fn keys_compare_and_hide_their_bytes() {
        let a = Key::from_bytes([7; KEY_LEN]);
        let b = Key::from_bytes([7; KEY_LEN]);
        let c = Key::from_bytes([8; KEY_LEN]);
        assert!(a.same_as(&b));
        assert!(!a.same_as(&c));
        assert_eq!(format!("{a:?}"), "Key(***)");
    }
}
