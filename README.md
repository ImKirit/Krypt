<div align="center">

<img src="docs/logo.png" width="96" alt="Krypt logo">

# Krypt

**Every login, key and code, locked on your own device.**

Krypt is a password manager for Windows. It keeps accounts, API keys, 2FA codes, recovery
codes, cards, SSH keys and the rest in one place, grouped by the service they belong to. A
Chrome extension, an optional account and Android and iOS follow later.

[![Status](https://img.shields.io/badge/status-early%20development-15151a)](#status)
[![Platform](https://img.shields.io/badge/platform-Windows-15151a)](#roadmap)
[![License](https://img.shields.io/badge/license-MIT-15151a)](LICENSE)

<img src="docs/main-account.png" width="820" alt="Krypt with the Anthropic account selected, showing its one-time code">

</div>

---

## Why?

A service like Anthropic is not one password. It is an account and two API keys. Groq is just
two keys. Most password managers are built around one login per website, so keys, recovery
codes and tokens end up in a note field where nothing can find or fill them.

Krypt treats the **service** as the unit and lets it hold any mix of entries. The second
decision is where your data lives: everything works on your own machine without an account.
An account will be optional, and the server will only ever store data it cannot read.

## Status

The Windows app runs from source and covers the local vault: setup, unlocking, every entry
type, one-time codes, a password generator, import from other password managers and browsers,
encrypted export, search, trash and auto-lock. There is no release and no installer yet. The
browser extension, the account and the phone apps are not started.

## Getting started

1. **Build and start the app** as described under [Development](#development). On the first
   start Krypt asks for a master password with at least 8 characters, an uppercase and a
   lowercase letter, a digit and a special character. The checklist ticks each rule off as you
   type.

   <img src="docs/tour-1-setup.png" width="620" alt="Setup screen with every master password rule ticked off">

2. **Write down the recovery key.** It is shown once and is the only way back in if you forget
   the master password. Krypt only continues after you confirm.

   <img src="docs/tour-2-recovery-key.png" width="620" alt="Recovery key in eight groups of four characters">

3. **Bring your passwords over, or add an entry with New.** Under Settings, Import reads the
   export of another app and shows what it will add before anything is written. For a new
   entry, pick a type, choose a service or create one on the spot, give it a label like
   Production, and fill in the fields. Paste an `otpauth://` link to add 2FA codes.

   <img src="docs/tour-3-editor.png" width="620" alt="New entry dialog with the API key type selected">

4. **Open a service in the sidebar** to see everything that belongs to it. Secrets stay hidden
   until you show or copy them.

   <img src="docs/main-service.png" width="620" alt="The Anthropic service with an account and two API keys">

## Features

### Store

- **One service, many entries.** Several accounts per site, an account next to API keys, or
  only keys. A service keeps its domains, so the extension will be able to match them.
- **Eleven entry types.** Account, API key, passkey, 2FA code, secure note, recovery codes,
  card, identity, SSH key, `.env` file and database login, each with custom fields, notes and
  tags.
- **Switch the type while adding.** Fields you already typed come back if you switch back.
- **Import from other apps.** Chrome, Edge, Brave, Opera, Firefox, Safari, Bitwarden (CSV and
  JSON), 1Password, LastPass, KeePass (XML), KeePassXC, Dashlane, Proton Pass, NordPass,
  RoboForm, and any CSV file with recognizable column names. Entries are sorted into services
  by site, duplicates are left out, and 2FA secrets, folders and custom fields come along.
- **Password history.** Changing an account password keeps the previous 20, listed under the
  account with the date each one was replaced.
- **Trash.** Deleted entries can be restored until you empty the trash.

### Use

- **Password generator** right under password fields: random characters from the classes you
  pick, or passphrases from the EFF wordlist, with the strength shown in bits.
- **Hidden until asked.** The window receives a secret only when you show or copy that one
  field; lists never contain secrets.
- **Copying cleans up.** Copies are marked so Windows leaves them out of the clipboard history
  and the cloud clipboard, and are removed after 30 seconds unless you copied something else.
- **One-time codes** with a countdown, for accounts and as their own entries.
- **Search** across services, labels, usernames, types and tags.

### Stay in control

- **Local first.** No account, no connection, one encrypted file on your machine.
- **Encrypted export.** Every service and entry in one file, locked with a password of its own,
  which Krypt imports again.
- **Auto-lock** after a chosen idle time, from one minute to never, and when Windows locks or
  goes to sleep unless you turn that off.
- **Backups** of the vault on the first unlock after every start and before every import: the
  newest ten, plus one per week for the last eight weeks.
- **Nothing lost by accident.** Closing an entry with unsaved changes asks first.
- **English and German**, following Windows until you pick one.

## Screens

| | |
|---|---|
| **Password generator.** Characters or words, right under the field. | **Import.** What will be added, and what is already there. |
| <img src="docs/generator.png" width="420" alt="Password generator under the password field of a new entry"> | <img src="docs/import-preview.png" width="420" alt="Import preview with one new and one existing service"> |
| **Unlock.** A wrong password is refused. | **Settings.** Language, auto-lock, clipboard, import and export, master password, recovery key. |
| <img src="docs/tour-4-unlock.png" width="420" alt="Unlock screen"> | <img src="docs/main-settings.png" width="420" alt="Settings dialog"> |

## Keyboard

| Keys | Action |
|---|---|
| `Ctrl+F` | Search |
| `Ctrl+N` | New entry |
| `Ctrl+L` | Lock |
| `Esc` | Close a dialog; asks first if an entry has unsaved changes |

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
| Master password to key | Argon2id, 64 MiB, 3 passes, 4 lanes; stored per vault and raised on the next unlock when Krypt's defaults go up. The password is normalized to Unicode NFC first |
| Master password rules | at least 8 characters with upper and lower case, a digit and a special character, for new master and export passwords |
| Encryption | XChaCha20-Poly1305, every service and every entry on its own |
| Tamper detection | each ciphertext is bound to its id, so swapping two records makes both fail to decrypt |
| Key hierarchy | one random vault key, stored once per way in: master password, recovery key, later a remembered device or a passkey |
| Recovery key | 160 random bits, shown once, written as eight groups of four characters |
| Encrypted export | the export password goes through Argon2id and HKDF, the whole content through XChaCha20-Poly1305; only the format version, the Argon2id costs and the salt stay readable |
| Import | read in Rust and shown as names and counts first; written in one transaction after a backup; the plain text export of the other app can be deleted afterwards |
| Password generator | the operating system's random number generator, with rejection sampling so every character and word is equally likely |
| Desktop app | keys stay in Rust; the web view gets masked entries and single fields on request, under a strict content security policy. File dialogs open from Rust, so the web view never gets file system access |
| Account login | the server never receives anything that can decrypt the vault |

If you lose the master password and the recovery key, the vault cannot be opened. That is the
cost of nobody else being able to open it.

The implementation is checked against published test vectors: Argon2id from the reference
implementation, HKDF from RFC 5869, XChaCha20-Poly1305 from the IETF draft and TOTP from
RFC 6238.

## How data is stored

```
%APPDATA%\dev.imkirit.krypt\
├─ vault.db         one SQLite file, every service and entry encrypted on its own
├─ backups\         copies of vault.db, encrypted the same way
└─ settings.json    language, auto-lock and clipboard timer, nothing secret
```

Names, domains, entry types and every field are encrypted. What stays readable is how many
entries exist and when they changed. Exports are saved wherever you choose.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Crypto core, data model, storage format, tests | Done |
| 1 | Windows app: local vault, every entry type, generator, import and export, auto-lock, remembered device, installer | In progress |
| 2 | Chrome extension: save prompt, fill, 2FA, passkeys | Planned |
| 3 | Optional account: passkey sign-in, encrypted cloud backup | Planned |
| 4 | Android and iOS, sync between devices | Planned |

## Development

Needs a stable Rust toolchain, Node 24 and the WebView2 runtime that ships with Windows 11.

```bash
cargo test --workspace                                   # core, storage, import and app backend
cargo clippy --workspace --all-targets -- -D warnings    # lints, must pass without warnings
cargo deny check                                         # licenses, sources, advisories
cargo audit                                              # RustSec advisory database
cargo run --release -p krypt-core --example kdf_timing   # how long one unlock takes here
```

The app lives in `apps/desktop`:

```bash
npm install                                    # from the repository root
npm run tauri dev                              # run with hot reload
npm run tauri build -- --debug --no-bundle     # debug build with the interface embedded
node scripts/drive.mjs <path to krypt.exe>     # drive the debug build and take screenshots
```

`scripts/drive.mjs` starts the debug build with a throwaway data folder and clicks through
setup, entries, copying, the generator, export, import and locking.

`crates/krypt-core` holds the cryptography, key slots, the data model, TOTP, the password rules,
the generator and the export format, with no file system, network or UI code, so the same crate
can later run on phones and as WebAssembly in the extension. `crates/krypt-store` keeps the vault
in SQLite with migrations that copy the file first. `crates/krypt-import` reads the exports of
other apps and sorts them into services. `apps/desktop` is Tauri 2 with a Rust backend and a
React interface; the backend logic sits in `src-tauri/src/backend.rs` without Tauri types so it
can be tested directly.

## License

[MIT](LICENSE) © ImKirit

Passphrases use the [EFF large wordlist](https://www.eff.org/dice) by the Electronic Frontier
Foundation, licensed under [CC BY 3.0 US](https://creativecommons.org/licenses/by/3.0/us/).
