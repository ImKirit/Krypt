// Mirrors the JSON that krypt-core writes for services and items.

export type ItemType =
  | "login"
  | "api_key"
  | "passkey"
  | "totp"
  | "note"
  | "recovery_codes"
  | "card"
  | "identity"
  | "ssh_key"
  | "env_file"
  | "database";

export const ITEM_TYPES: ItemType[] = [
  "login",
  "api_key",
  "passkey",
  "totp",
  "note",
  "recovery_codes",
  "card",
  "identity",
  "ssh_key",
  "env_file",
  "database",
];

/** What the backend puts in place of a secret until it is revealed. */
export const MASKED = "__krypt_masked__";

export interface TotpConfig {
  secret: string;
  algorithm: "sha1" | "sha256" | "sha512";
  digits: number;
  period: number;
  issuer: string | null;
  account: string | null;
}

export interface PasswordChange {
  password: string;
  replaced_at: number;
}

export interface Login {
  type: "login";
  username: string | null;
  email: string | null;
  password: string;
  totp: TotpConfig | null;
  urls: string[];
  password_history: PasswordChange[];
}

export interface ApiKey {
  type: "api_key";
  key: string;
  key_id: string | null;
  secret: string | null;
  organization: string | null;
  scopes: string[];
  expires: number | null;
  console_url: string | null;
}

export interface Passkey {
  type: "passkey";
  rp_id: string;
  credential_id: string;
  user_handle: string;
  username: string | null;
  private_key: string;
  algorithm: number;
  sign_count: number;
}

export interface Totp extends TotpConfig {
  type: "totp";
}

export interface Note {
  type: "note";
  text: string;
}

export interface RecoveryCode {
  code: string;
  used: boolean;
}

export interface RecoveryCodes {
  type: "recovery_codes";
  codes: RecoveryCode[];
}

export interface Card {
  type: "card";
  holder: string | null;
  number: string;
  expiry_month: number | null;
  expiry_year: number | null;
  cvc: string | null;
  pin: string | null;
  brand: string | null;
}

export interface Address {
  street: string | null;
  postal_code: string | null;
  city: string | null;
  region: string | null;
  country: string | null;
}

export interface IdDocument {
  kind: string;
  number: string;
  expires: string | null;
}

export interface Identity {
  type: "identity";
  full_name: string;
  email: string | null;
  phone: string | null;
  birthday: string | null;
  address: Address | null;
  documents: IdDocument[];
}

export interface SshKey {
  type: "ssh_key";
  private_key: string;
  public_key: string | null;
  passphrase: string | null;
  fingerprint: string | null;
  comment: string | null;
}

export interface EnvFile {
  type: "env_file";
  file_name: string | null;
  project: string | null;
  content: string;
}

export interface Database {
  type: "database";
  engine: string | null;
  host: string;
  port: number | null;
  database: string | null;
  username: string | null;
  password: string | null;
  connection_string: string | null;
}

export type ItemData =
  | Login
  | ApiKey
  | Passkey
  | Totp
  | Note
  | RecoveryCodes
  | Card
  | Identity
  | SshKey
  | EnvFile
  | Database;

export interface CustomField {
  name: string;
  value: string;
  hidden: boolean;
}

export interface Item {
  id: string;
  service_id: string | null;
  label: string;
  notes: string;
  favorite: boolean;
  tags: string[];
  custom_fields: CustomField[];
  created: number;
  data: ItemData;
}

export interface ItemView extends Item {
  revision: number;
  updated: number;
  deleted_at: number | null;
}

export interface DomainRule {
  host: string;
  matching: "registrable_domain" | "exact_host";
}

export interface Service {
  id: string;
  name: string;
  domains: DomainRule[];
  icon: string | null;
  tags: string[];
  favorite: boolean;
}

export interface ServiceSummary {
  id: string;
  name: string;
  domains: string[];
  favorite: boolean;
  item_count: number;
}

export interface ItemSummary {
  id: string;
  service_id: string | null;
  service_name: string | null;
  label: string;
  item_type: ItemType;
  subtitle: string | null;
  favorite: boolean;
  has_totp: boolean;
  tags: string[];
  updated: number;
  deleted_at: number | null;
}

export interface Settings {
  language: "en" | "de" | null;
  auto_lock_minutes: number;
  clipboard_clear_seconds: number;
  lock_with_windows: boolean;
  /** Set by the backend once Windows Hello was offered; the window cannot reset it. */
  hello_offered: boolean;
  /** Days until Windows Hello asks for the master password again. 0 never. */
  password_reminder_days: number;
}

export interface AppError {
  code: string;
  message: string;
}

export interface HelloStatus {
  supported: boolean;
  enrolled: boolean;
  password_due: boolean;
  offer: boolean;
}

export interface Status {
  vault_exists: boolean;
  unlocked: boolean;
  problem: AppError | null;
  backup_failed: boolean;
  settings: Settings;
  min_password_chars: number;
  hello: HelloStatus;
}

export interface TotpNow {
  code: string;
  remaining: number;
  period: number;
}

export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  digits: boolean;
  symbols: boolean;
  avoid_ambiguous: boolean;
}

export interface PassphraseOptions {
  words: number;
  separator: string;
  capitalize: boolean;
  number: boolean;
}

export type GeneratorOptions =
  | ({ kind: "password" } & PasswordOptions)
  | ({ kind: "passphrase" } & PassphraseOptions);

export interface GeneratedPassword {
  value: string;
  bits: number;
}

export type ImportSource =
  | "krypt"
  | "bitwarden"
  | "chromium"
  | "firefox"
  | "safari"
  | "one_password"
  | "last_pass"
  | "kee_pass"
  | "dashlane"
  | "proton_pass"
  | "nord_pass"
  | "robo_form"
  | "csv";

/** Names and counts only; the backend keeps the entries until the import is confirmed. */
export interface ImportPreview {
  file_name: string;
  needs_password: boolean;
  source: ImportSource | null;
  counts: { item_type: ItemType; count: number }[];
  total: number;
  new_services: string[];
  existing_services: string[];
  duplicates: number;
  skipped: number;
  plaintext: boolean;
}

export interface ImportResult {
  items: number;
  services: number;
  source_deleted: boolean;
}
