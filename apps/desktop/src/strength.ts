// A rough estimate for the meter under the master password field. It rewards length and
// variety and punishes the patterns people fall back to. It is a hint, not a guarantee.

const COMMON = [
  "password",
  "passwort",
  "123456",
  "qwerty",
  "qwertz",
  "letmein",
  "welcome",
  "admin",
  "iloveyou",
  "monkey",
  "dragon",
  "master",
  "secret",
  "abc123",
  "111111",
  "sunshine",
  "football",
  "trustno1",
  "hallo",
  "krypt",
];

const SEQUENCES = /(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|qwer|asdf|yxcv|zxcv)/i;

export type Strength = 0 | 1 | 2 | 3 | 4;

export function estimateStrength(password: string): Strength {
  if (!password) return 0;
  const chars = [...password];
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 33;

  const variety = Math.min(1, new Set(chars).size / Math.max(6, chars.length * 0.5));
  let bits = Math.log2(Math.max(pool, 2)) * chars.length * variety;

  const lower = password.toLowerCase();
  if (COMMON.some((word) => lower.includes(word))) bits -= 24;
  if (/(.)\1{2,}/.test(password)) bits -= 10;
  if (SEQUENCES.test(password)) bits -= 10;

  if (bits < 30) return 0;
  if (bits < 45) return 1;
  if (bits < 60) return 2;
  if (bits < 80) return 3;
  return 4;
}
