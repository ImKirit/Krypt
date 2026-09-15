import type { Key } from "./i18n";
import type { ItemData, ItemType, TotpConfig } from "./types";

export type FieldKind =
  | "text"
  | "secret"
  | "multiline"
  | "secretMultiline"
  | "number"
  | "lines"
  | "dateMs"
  | "date"
  | "select";

export interface FieldDef {
  key: string;
  label: Key;
  kind: FieldKind;
  /** Stored as null when left empty. */
  nullable?: boolean;
  monospace?: boolean;
  readOnly?: boolean;
  options?: string[];
  /** Offers the password generator next to the field. */
  generate?: boolean;
}

/** The flat fields of every entry type, in the order they are shown and edited. */
export const FIELDS: Record<ItemType, FieldDef[]> = {
  login: [
    { key: "username", label: "field.username", kind: "text", nullable: true },
    { key: "email", label: "field.email", kind: "text", nullable: true },
    { key: "password", label: "field.password", kind: "secret", monospace: true, generate: true },
    { key: "urls", label: "field.urls", kind: "lines" },
  ],
  api_key: [
    { key: "key", label: "field.key", kind: "secret", monospace: true },
    { key: "key_id", label: "field.key_id", kind: "text", nullable: true, monospace: true },
    { key: "secret", label: "field.secret", kind: "secret", nullable: true, monospace: true },
    { key: "organization", label: "field.organization", kind: "text", nullable: true },
    { key: "expires", label: "field.expires", kind: "dateMs", nullable: true },
    { key: "console_url", label: "field.console_url", kind: "text", nullable: true },
    { key: "scopes", label: "field.scopes", kind: "lines" },
  ],
  passkey: [
    { key: "rp_id", label: "field.rp_id", kind: "text", readOnly: true },
    { key: "username", label: "field.username", kind: "text", nullable: true },
    { key: "credential_id", label: "field.credential_id", kind: "text", readOnly: true, monospace: true },
    { key: "sign_count", label: "field.sign_count", kind: "number", readOnly: true },
  ],
  totp: [
    { key: "secret", label: "field.totp_secret", kind: "secret", monospace: true },
    { key: "issuer", label: "field.issuer", kind: "text", nullable: true },
    { key: "account", label: "field.account", kind: "text", nullable: true },
    { key: "algorithm", label: "field.algorithm", kind: "select", options: ["sha1", "sha256", "sha512"] },
    { key: "digits", label: "field.digits", kind: "number" },
    { key: "period", label: "field.period", kind: "number" },
  ],
  note: [{ key: "text", label: "field.text", kind: "secretMultiline" }],
  recovery_codes: [],
  card: [
    { key: "holder", label: "field.holder", kind: "text", nullable: true },
    { key: "number", label: "field.number", kind: "secret", monospace: true },
    { key: "expiry_month", label: "field.expiry_month", kind: "number", nullable: true },
    { key: "expiry_year", label: "field.expiry_year", kind: "number", nullable: true },
    { key: "cvc", label: "field.cvc", kind: "secret", nullable: true, monospace: true },
    { key: "pin", label: "field.pin", kind: "secret", nullable: true, monospace: true },
    { key: "brand", label: "field.brand", kind: "text", nullable: true },
  ],
  identity: [
    { key: "full_name", label: "field.full_name", kind: "text" },
    { key: "email", label: "field.email", kind: "text", nullable: true },
    { key: "phone", label: "field.phone", kind: "text", nullable: true },
    { key: "birthday", label: "field.birthday", kind: "date", nullable: true },
  ],
  ssh_key: [
    { key: "comment", label: "field.comment", kind: "text", nullable: true },
    { key: "fingerprint", label: "field.fingerprint", kind: "text", nullable: true, monospace: true },
    { key: "passphrase", label: "field.passphrase", kind: "secret", nullable: true, monospace: true },
    { key: "private_key", label: "field.private_key", kind: "secretMultiline", monospace: true },
    { key: "public_key", label: "field.public_key", kind: "multiline", nullable: true, monospace: true },
  ],
  env_file: [
    { key: "file_name", label: "field.file_name", kind: "text", nullable: true, monospace: true },
    { key: "project", label: "field.project", kind: "text", nullable: true },
    { key: "content", label: "field.content", kind: "secretMultiline", monospace: true },
  ],
  database: [
    { key: "engine", label: "field.engine", kind: "text", nullable: true },
    { key: "host", label: "field.host", kind: "text", monospace: true },
    { key: "port", label: "field.port", kind: "number", nullable: true },
    { key: "database", label: "field.database", kind: "text", nullable: true },
    { key: "username", label: "field.username", kind: "text", nullable: true },
    { key: "password", label: "field.password", kind: "secret", nullable: true, monospace: true, generate: true },
    { key: "connection_string", label: "field.connection_string", kind: "secret", nullable: true, monospace: true },
  ],
};

export const ADDRESS_FIELDS: FieldDef[] = [
  { key: "street", label: "field.street", kind: "text", nullable: true },
  { key: "postal_code", label: "field.postal_code", kind: "text", nullable: true },
  { key: "city", label: "field.city", kind: "text", nullable: true },
  { key: "region", label: "field.region", kind: "text", nullable: true },
  { key: "country", label: "field.country", kind: "text", nullable: true },
];

export function isSecret(kind: FieldKind): boolean {
  return kind === "secret" || kind === "secretMultiline";
}

export function isWide(kind: FieldKind): boolean {
  return kind === "multiline" || kind === "secretMultiline" || kind === "lines";
}

export function defaultTotp(): TotpConfig {
  return { secret: "", algorithm: "sha1", digits: 6, period: 30, issuer: null, account: null };
}

export function splitLines(text: string): string[] {
  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
}

/**
 * Reads an `otpauth://totp/Issuer:account?secret=...` link, as setup pages put into their QR
 * codes. Returns null for anything else.
 */
export function parseOtpauth(text: string): TotpConfig | null {
  const trimmed = text.trim();
  if (!trimmed.toLowerCase().startsWith("otpauth://totp/")) return null;
  try {
    const url = new URL(trimmed);
    const params = url.searchParams;
    const secret = params.get("secret");
    if (!secret) return null;
    const label = decodeURIComponent(url.pathname.replace(/^\/+/, ""));
    const colon = label.indexOf(":");
    const labelIssuer = colon >= 0 ? label.slice(0, colon).trim() : null;
    const account = (colon >= 0 ? label.slice(colon + 1) : label).trim();
    const algorithm = (params.get("algorithm") ?? "sha1").toLowerCase();
    return {
      secret,
      issuer: params.get("issuer") ?? labelIssuer ?? null,
      account: account || null,
      algorithm:
        algorithm === "sha256" || algorithm === "sha512" ? algorithm : "sha1",
      digits: Number(params.get("digits")) || 6,
      period: Number(params.get("period")) || 30,
    };
  } catch {
    return null;
  }
}

/** Drops empty lines and empty rows before an entry is saved. */
export function normalizeData(data: ItemData): ItemData {
  const copy = { ...data } as unknown as Record<string, unknown>;
  for (const def of FIELDS[data.type]) {
    const value = copy[def.key];
    if (def.kind === "lines" && Array.isArray(value)) {
      copy[def.key] = (value as string[]).map((line) => line.trim()).filter(Boolean);
    }
  }
  if (data.type === "recovery_codes") {
    copy.codes = data.codes
      .map((code) => ({ ...code, code: code.code.trim() }))
      .filter((code) => code.code);
  }
  if (data.type === "identity") {
    copy.documents = data.documents.filter((doc) => doc.kind.trim() || doc.number.trim());
  }
  return copy as unknown as ItemData;
}
