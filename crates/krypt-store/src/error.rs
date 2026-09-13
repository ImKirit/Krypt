#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("a file already exists at this path")]
    AlreadyExists,
    #[error("no vault found at this path")]
    NotFound,
    #[error("this file is not a Krypt vault")]
    NotAVault,
    #[error(
        "this vault was written by a newer version of Krypt (format {found}, this build reads up to {supported})"
    )]
    NewerFormat { found: i32, supported: i32 },
    #[error("wrong password")]
    WrongPassword,
    #[error("wrong recovery key")]
    WrongRecoveryKey,
    #[error("the vault is damaged: {0}")]
    Corrupt(&'static str),
    #[error(transparent)]
    Core(#[from] krypt_core::Error),
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("file error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
