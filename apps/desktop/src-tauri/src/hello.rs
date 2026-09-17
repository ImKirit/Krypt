//! Windows Hello as the key of the device slot.
//!
//! Windows keeps an RSA key for Krypt, asks for PIN, fingerprint or face before every use, and
//! signs the slot's challenge with it. Signatures with PKCS#1 v1.5 padding are deterministic, so
//! the same challenge always gives the same signature, and with it the same key-encryption key.

use zeroize::Zeroizing;

use crate::error::AppError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelloError {
    /// The user closed the prompt or chose the password instead.
    Canceled,
    /// The key Windows kept for Krypt is gone.
    KeyMissing,
    /// Windows Hello is not set up, or the security device is locked.
    Unavailable,
    Failed,
}

impl From<HelloError> for AppError {
    fn from(error: HelloError) -> Self {
        AppError::new(match error {
            HelloError::Canceled => "hello_canceled",
            HelloError::KeyMissing => "hello_key_missing",
            HelloError::Unavailable => "hello_unavailable",
            HelloError::Failed => "hello_failed",
        })
    }
}

pub trait HelloKey: Send + Sync {
    /// Whether Windows Hello is set up on this PC. Shows no prompt.
    fn supported(&self) -> bool;
    /// Creates a key under `name`, replacing one with the same name. Shows the prompt.
    fn create(&self, name: &str) -> Result<(), HelloError>;
    /// Signs `challenge` with the key under `name`. Shows the prompt.
    fn sign(&self, name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, HelloError>;
    /// Removes the key under `name`. A missing key is fine.
    fn delete(&self, name: &str);
}

pub fn provider() -> Box<dyn HelloKey> {
    // Test runs of debug builds cannot answer a Windows Hello prompt.
    #[cfg(debug_assertions)]
    {
        if std::env::var_os("KRYPT_TEST_FAKE_HELLO").is_some() {
            return Box::new(test_key::TestKey::default());
        }
    }
    #[cfg(windows)]
    let key: Box<dyn HelloKey> = Box::new(windows_hello::WindowsHello);
    #[cfg(not(windows))]
    let key: Box<dyn HelloKey> = Box::new(Unsupported);
    key
}

#[cfg(not(windows))]
struct Unsupported;

#[cfg(not(windows))]
impl HelloKey for Unsupported {
    fn supported(&self) -> bool {
        false
    }

    fn create(&self, _name: &str) -> Result<(), HelloError> {
        Err(HelloError::Unavailable)
    }

    fn sign(&self, _name: &str, _challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, HelloError> {
        Err(HelloError::Unavailable)
    }

    fn delete(&self, _name: &str) {}
}

#[cfg(windows)]
mod windows_hello {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;
    use std::time::{Duration, Instant};

    use windows::Security::Credentials::{
        KeyCredentialCreationOption, KeyCredentialManager, KeyCredentialStatus,
    };
    use windows::Security::Cryptography::CryptographicBuffer;
    use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, SetForegroundWindow};
    use windows::core::{Array, HSTRING, PCWSTR, w};
    use zeroize::Zeroizing;

    use super::{HelloError, HelloKey};

    pub struct WindowsHello;

    impl HelloKey for WindowsHello {
        fn supported(&self) -> bool {
            KeyCredentialManager::IsSupportedAsync()
                .and_then(|operation| operation.get())
                .unwrap_or(false)
        }

        fn create(&self, name: &str) -> Result<(), HelloError> {
            let _focus = PromptFocus::start();
            let created = KeyCredentialManager::RequestCreateAsync(
                &HSTRING::from(name),
                KeyCredentialCreationOption::ReplaceExisting,
            )
            .and_then(|operation| operation.get())
            .map_err(|_| HelloError::Failed)?;
            check(created.Status())
        }

        fn sign(&self, name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, HelloError> {
            let opened = KeyCredentialManager::OpenAsync(&HSTRING::from(name))
                .and_then(|operation| operation.get())
                .map_err(|_| HelloError::Failed)?;
            check(opened.Status())?;
            let credential = opened.Credential().map_err(|_| HelloError::Failed)?;
            let data = CryptographicBuffer::CreateFromByteArray(challenge)
                .map_err(|_| HelloError::Failed)?;

            let _focus = PromptFocus::start();
            let signed = credential
                .RequestSignAsync(&data)
                .and_then(|operation| operation.get())
                .map_err(|_| HelloError::Failed)?;
            check(signed.Status())?;
            let buffer = signed.Result().map_err(|_| HelloError::Failed)?;
            let mut bytes = Array::<u8>::new();
            CryptographicBuffer::CopyToByteArray(&buffer, &mut bytes)
                .map_err(|_| HelloError::Failed)?;
            Ok(Zeroizing::new(bytes.to_vec()))
        }

        fn delete(&self, name: &str) {
            let _ = KeyCredentialManager::DeleteAsync(&HSTRING::from(name))
                .and_then(|operation| operation.get());
        }
    }

    fn check(status: windows::core::Result<KeyCredentialStatus>) -> Result<(), HelloError> {
        match status.map_err(|_| HelloError::Failed)? {
            KeyCredentialStatus::Success => Ok(()),
            KeyCredentialStatus::UserCanceled | KeyCredentialStatus::UserPrefersPassword => {
                Err(HelloError::Canceled)
            }
            KeyCredentialStatus::NotFound => Err(HelloError::KeyMissing),
            KeyCredentialStatus::SecurityDeviceLocked => Err(HelloError::Unavailable),
            _ => Err(HelloError::Failed),
        }
    }

    /// A desktop app gets the Windows Hello prompt without a parent window, and it can open
    /// behind Krypt. This brings it to the front as soon as it appears, for at most ten seconds.
    struct PromptFocus {
        done: Arc<AtomicBool>,
    }

    impl PromptFocus {
        fn start() -> Self {
            let done = Arc::new(AtomicBool::new(false));
            let stop = Arc::clone(&done);
            thread::spawn(move || {
                let started = Instant::now();
                while !stop.load(Ordering::Relaxed) && started.elapsed() < Duration::from_secs(10) {
                    // SAFETY: the class name is a static wide string literal and the window name
                    // is null, as FindWindowW allows.
                    let found =
                        unsafe { FindWindowW(w!("Credential Dialog Xaml Host"), PCWSTR::null()) };
                    if let Ok(window) = found
                        && !window.is_invalid()
                    {
                        // SAFETY: the handle comes straight from FindWindowW; a window closed in
                        // the meantime only makes the call fail.
                        let _ = unsafe { SetForegroundWindow(window) };
                        break;
                    }
                    thread::sleep(Duration::from_millis(100));
                }
            });
            Self { done }
        }
    }

    impl Drop for PromptFocus {
        fn drop(&mut self) {
            self.done.store(true, Ordering::Relaxed);
        }
    }
}

/// A stand-in for Windows Hello in debug builds, used by `drive.mjs`: no prompt, and the keys
/// live in memory until the app ends.
#[cfg(debug_assertions)]
mod test_key {
    use std::collections::HashMap;
    use std::sync::Mutex;

    use krypt_core::crypto;
    use zeroize::Zeroizing;

    use super::{HelloError, HelloKey};

    #[derive(Default)]
    pub struct TestKey {
        keys: Mutex<HashMap<String, [u8; 32]>>,
    }

    impl HelloKey for TestKey {
        fn supported(&self) -> bool {
            true
        }

        fn create(&self, name: &str) -> Result<(), HelloError> {
            let mut secret = [0u8; 32];
            crypto::random_bytes(&mut secret).map_err(|_| HelloError::Failed)?;
            self.keys
                .lock()
                .map_err(|_| HelloError::Failed)?
                .insert(name.to_owned(), secret);
            Ok(())
        }

        fn sign(&self, name: &str, challenge: &[u8]) -> Result<Zeroizing<Vec<u8>>, HelloError> {
            let keys = self.keys.lock().map_err(|_| HelloError::Failed)?;
            let secret = keys.get(name).ok_or(HelloError::KeyMissing)?;
            let mut signature = Zeroizing::new(vec![0u8; 256]);
            crypto::hkdf_sha256(
                Some(challenge),
                secret,
                b"krypt test hello",
                signature.as_mut_slice(),
            )
            .map_err(|_| HelloError::Failed)?;
            Ok(signature)
        }

        fn delete(&self, name: &str) {
            if let Ok(mut keys) = self.keys.lock() {
                keys.remove(name);
            }
        }
    }
}
