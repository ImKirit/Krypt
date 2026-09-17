/// Errors from the core. Messages never contain secret material, so they are safe to log.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("could not get random bytes from the operating system")]
    Random,
    #[error("key derivation parameters are out of range")]
    KdfParams,
    #[error("key derivation failed")]
    Kdf,
    #[error("encryption failed")]
    Encrypt,
    #[error("decryption failed: wrong key or damaged data")]
    Decrypt,
    #[error("unsupported ciphertext version {0}")]
    UnsupportedVersion(u8),
    #[error("ciphertext is too short")]
    Truncated,
    #[error("this key slot cannot be opened this way")]
    SlotKind,
    #[error("invalid recovery key")]
    InvalidRecoveryKey,
    #[error("invalid TOTP secret")]
    InvalidTotpSecret,
    #[error("invalid TOTP settings")]
    InvalidTotpSettings,
    #[error("invalid otpauth link")]
    InvalidTotpUri,
    #[error("the generator options cannot be met")]
    GeneratorOptions,
    #[error("not a Krypt export")]
    NotAnExport,
    #[error("unsupported export version {0}")]
    ExportVersion(u32),
    #[error("the device signature is too short to derive a key from")]
    InvalidSignature,
    // Deliberately without the serde message: it can quote the value that failed to parse.
    #[error("stored data has an unexpected format")]
    Format,
}

pub type Result<T> = std::result::Result<T, Error>;
