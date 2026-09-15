// Mirrors the password rules of krypt-core, so the checklist can follow along while typing.
// The backend checks again before a master or export password is used.

export interface RuleState {
  length: boolean;
  uppercase: boolean;
  lowercase: boolean;
  digit: boolean;
  special: boolean;
}

export const RULES: (keyof RuleState)[] = ["length", "uppercase", "lowercase", "digit", "special"];

export function checkRules(password: string, minChars: number): RuleState {
  const text = password.normalize("NFC");
  return {
    length: [...text].length >= minChars,
    uppercase: /\p{Uppercase}/u.test(text),
    lowercase: /\p{Lowercase}/u.test(text),
    digit: /\p{N}/u.test(text),
    special: /[^\p{Alphabetic}\p{N}\p{White_Space}]/u.test(text),
  };
}

export function rulesMet(password: string, minChars: number): boolean {
  return Object.values(checkRules(password, minChars)).every(Boolean);
}
