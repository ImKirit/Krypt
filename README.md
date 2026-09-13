<div align="center">

# Krypt

**Every login, key and code, locked on your own device.**

Krypt is a password manager for Windows, with a Chrome extension that spots new logins and
fills known ones. It keeps accounts, API keys, passkeys, 2FA codes and the rest in one place,
grouped by the service they belong to. Android and iOS follow later.

[![Status](https://img.shields.io/badge/status-early%20development-15151a)](#status)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Chrome-15151a)](#roadmap)
[![License](https://img.shields.io/badge/license-MIT-15151a)](LICENSE)

</div>

---

## Why?

A service like Anthropic is not one password. It is an account and two API keys. Groq is just
two keys. Most password managers are built around one login per website, so keys, recovery
codes and tokens end up in a note field where nothing can find or fill them.

Krypt treats the **service** as the unit and lets it hold any mix of entries. The second
decision is where your data lives: everything works on your own machine without an account.
An account is optional, and the server only ever stores data it cannot read.

## Status

The crypto core and the vault storage exist and are tested. There is no app and no release
yet, so there is nothing to install. This README describes what is being built and will
switch to install instructions and screenshots once the first build exists.

## Planned features

### Store

- **One service, many entries.** Several accounts per site, or an account next to API keys,
  or only keys. Services know their domains, so the extension can match them.
- **Entry types.** Account, API key, passkey, 2FA code (TOTP), secure note, recovery codes,
  card, identity, SSH key, `.env` file and database login. Every type takes custom fields.
- **Switch the type while adding.** Start typing a login, realize it is a key, switch, and the
  label and notes stay.
- **Keys with an expiry date.** Tokens that run out are API keys with `expires` set.

### Fill

- **Save prompt.** The Chrome extension notices when you sign in or sign up and asks whether
  to save the login, or to update the password if it changed.
- **Fill on known sites.** When a page matches a service, Krypt offers the right account in
  the field and fills it with one click. Filling right away can be turned on per service.
  With several accounts for one site, you pick.
- **2FA and passkeys in the browser.** Codes are offered in the one-time-code field, passkeys
  are created and used from the vault.

### Stay in control

- **Local first.** No account, no internet connection needed.
- **Optional account** to keep an encrypted copy in the cloud, later to sync your PC and phone.
  Sign in with a passkey, and a remembered device does not ask you to sign in every time.
- **Nothing sensitive leaves the device in plain text.** Not the master password, not the
  entries, not in logs.

## One service, many entries

```
Anthropic            anthropic.com, console.anthropic.com
├─ Account           you@example.com, password, 2FA
├─ API key           "Production"
└─ API key           "Staging"

Groq                 console.groq.com
├─ API key           "Personal"
└─ API key           "Test"
```

## Security design

The design was written down before any crypto code existed. It has not had an external review
yet; that is planned before the first release.

| Part | Choice |
|---|---|
| Master password to key | Argon2id, 64 MiB, 3 passes, 4 lanes; stored per vault so it can be raised. The password is normalized to Unicode NFC first |
| Encryption | XChaCha20-Poly1305, every service and every entry on its own |
| Tamper detection | each ciphertext is bound to its id, so swapping two records makes both fail to decrypt |
| Key hierarchy | one random vault key, stored once per way in: master password, recovery key, later a remembered device or a passkey |
| Recovery key | 160 random bits, shown once, written as eight groups of four characters |
| Account login | the server never receives anything that can decrypt the vault |
| Extension | talks to the desktop app through Chrome native messaging, paired once |

If you lose the master password, the recovery key and every remembered device, the vault
cannot be opened. That is the cost of the server not being able to read it.

The implementation is checked against published test vectors: Argon2id from the reference
implementation, HKDF from RFC 5869, XChaCha20-Poly1305 from the IETF draft and TOTP from
RFC 6238.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Crypto core, data model, storage format, tests | Done |
| 1 | Windows app: create a vault, unlock, remembered device, add and edit every entry type | Next |
| 2 | Chrome extension: save prompt, fill, 2FA, passkeys | Planned |
| 3 | Optional account: passkey sign-in, encrypted cloud backup | Planned |
| 4 | Android and iOS, sync between devices | Planned |

## Development

Needs a stable Rust toolchain.

```bash
cargo test --workspace                                   # unit tests, test vectors, vault file tests
cargo clippy --workspace --all-targets -- -D warnings    # lints, must pass without warnings
cargo deny check                                         # licenses, sources, advisories
cargo audit                                              # RustSec advisory database
cargo run --release -p krypt-core --example kdf_timing   # how long one unlock takes here
```

`crates/krypt-core` holds the cryptography, key slots, the data model and TOTP. It has no file
system, network or UI code, so the same crate can run in the desktop app, on phones and as
WebAssembly in the extension. `crates/krypt-store` keeps a vault in a single SQLite file with
one encrypted blob per service and per entry, versioned migrations that copy the file first,
a trash and rotating backups. The Tauri app with a React interface follows in `apps/desktop`.

## Built with

[Tauri 2](https://tauri.app) with a Rust core and a React interface in TypeScript. The same
Rust core is planned to run as WebAssembly inside the extension, so there is one
implementation of the crypto everywhere.

## License

[MIT](LICENSE) © ImKirit
