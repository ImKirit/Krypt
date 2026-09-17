use serde::Serialize;

/// What a command reports to the window: a stable code the interface translates, plus an
/// English message for logs. Neither ever contains secret data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AppError {
    pub code: &'static str,
    pub message: String,
}

pub type AppResult<T> = Result<T, AppError>;

impl AppError {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            message: code.replace('_', " "),
        }
    }
}

impl From<krypt_store::Error> for AppError {
    fn from(error: krypt_store::Error) -> Self {
        use krypt_store::Error as E;
        let code = match &error {
            E::AlreadyExists => "vault_exists",
            E::NotFound => "no_vault",
            E::NotAVault => "not_a_vault",
            E::NewerFormat { .. } => "newer_format",
            E::WrongPassword => "wrong_password",
            E::WrongRecoveryKey => "wrong_recovery_key",
            E::WrongDeviceKey => "device_key_rejected",
            E::SlotNotFound => "no_device",
            E::Corrupt(_) => "corrupt",
            E::Core(core) => core_code(core),
            E::Sqlite(_) => "database",
            E::Io(_) => "io",
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

impl From<krypt_core::Error> for AppError {
    fn from(error: krypt_core::Error) -> Self {
        Self {
            code: core_code(&error),
            message: error.to_string(),
        }
    }
}

impl From<krypt_import::Error> for AppError {
    fn from(error: krypt_import::Error) -> Self {
        use krypt_core::Error as Core;
        use krypt_import::Error as E;
        let code = match &error {
            E::UnknownFormat => "import_unknown_format",
            E::Encrypted => "import_encrypted",
            E::PasswordRequired => "import_password_required",
            // Wrong password and damaged file cannot be told apart.
            E::Core(Core::Decrypt) => "import_wrong_password",
            E::Malformed
            | E::Core(
                Core::Format | Core::Truncated | Core::UnsupportedVersion(_) | Core::KdfParams,
            ) => "import_malformed",
            E::Core(core) => core_code(core),
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

fn core_code(error: &krypt_core::Error) -> &'static str {
    use krypt_core::Error as E;
    match error {
        E::InvalidRecoveryKey => "invalid_recovery_key",
        E::InvalidTotpSecret | E::InvalidTotpSettings | E::InvalidTotpUri => "invalid_totp",
        E::GeneratorOptions => "generator_options",
        E::NotAnExport => "import_unknown_format",
        E::ExportVersion(_) => "export_version",
        E::InvalidSignature => "hello_failed",
        E::Decrypt | E::Truncated | E::UnsupportedVersion(_) | E::Format | E::KdfParams => {
            "corrupt"
        }
        E::Random | E::Kdf | E::Encrypt | E::SlotKind => "internal",
    }
}
