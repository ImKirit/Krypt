/// Errors while reading an import. Messages never quote the file, which is full of secrets.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("the file is not in a format Krypt can import")]
    UnknownFormat,
    #[error("the file was encrypted by the app that exported it")]
    Encrypted,
    #[error("the export needs its password")]
    PasswordRequired,
    #[error("the file is damaged or incomplete")]
    Malformed,
    /// A wrong export password shows up here as `Core(Decrypt)`.
    #[error(transparent)]
    Core(#[from] krypt_core::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
