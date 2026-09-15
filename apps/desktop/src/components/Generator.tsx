import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api";
import { errorText, useT } from "../i18n";
import type { Key } from "../i18n";
import type {
  GeneratedPassword,
  GeneratorOptions,
  PassphraseOptions,
  PasswordOptions,
} from "../types";
import { Button, IconButton } from "../ui";

const STORAGE_KEY = "krypt.generator";

const PASSWORD_DEFAULTS: PasswordOptions = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  avoid_ambiguous: false,
};

const PASSPHRASE_DEFAULTS: PassphraseOptions = {
  words: 5,
  separator: "-",
  capitalize: true,
  number: true,
};

const SEPARATORS: [string, Key | null][] = [
  ["-", null],
  [".", null],
  ["_", null],
  [" ", "generator.space"],
  ["", "generator.none"],
];

const CLASSES = [
  ["uppercase", "generator.uppercase"],
  ["lowercase", "generator.lowercase"],
  ["digits", "generator.digits"],
  ["symbols", "generator.symbols"],
] as const;

interface Choice {
  kind: "password" | "passphrase";
  password: PasswordOptions;
  passphrase: PassphraseOptions;
}

// Only the settings are remembered, never a generated value.
function loadChoice(): Choice {
  try {
    const saved = JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "null") as Partial<Choice> | null;
    return {
      kind: saved?.kind === "passphrase" ? "passphrase" : "password",
      password: { ...PASSWORD_DEFAULTS, ...saved?.password },
      passphrase: { ...PASSPHRASE_DEFAULTS, ...saved?.passphrase },
    };
  } catch {
    return { kind: "password", password: PASSWORD_DEFAULTS, passphrase: PASSPHRASE_DEFAULTS };
  }
}

function toOptions(choice: Choice): GeneratorOptions {
  return choice.kind === "password"
    ? { kind: "password", ...choice.password }
    : { kind: "passphrase", ...choice.passphrase };
}

export function GeneratorPanel({
  onUse,
  onClose,
}: {
  onUse: (value: string) => void;
  onClose: () => void;
}) {
  const { t } = useT();
  const [choice, setChoice] = useState<Choice>(loadChoice);
  const [result, setResult] = useState<GeneratedPassword | null>(null);
  const [error, setError] = useState<string | null>(null);
  const latest = useRef(0);

  const generate = useCallback(
    async (options: GeneratorOptions) => {
      // A slider sends many requests; only the answer to the last one counts.
      const request = ++latest.current;
      try {
        const next = await api.generatePassword(options);
        if (request !== latest.current) return;
        setResult(next);
        setError(null);
      } catch (err) {
        if (request !== latest.current) return;
        setResult(null);
        setError(errorText(t, err));
      }
    },
    [t],
  );

  useEffect(() => {
    void generate(toOptions(choice));
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(choice));
    } catch {
      // Remembering the settings is a convenience only.
    }
  }, [choice, generate]);

  const setPassword = (patch: Partial<PasswordOptions>) =>
    setChoice((current) => ({ ...current, password: { ...current.password, ...patch } }));
  const setPassphrase = (patch: Partial<PassphraseOptions>) =>
    setChoice((current) => ({ ...current, passphrase: { ...current.passphrase, ...patch } }));
  const password = choice.password;
  const passphrase = choice.passphrase;
  const enabledClasses = CLASSES.filter(([key]) => password[key]).length;

  return (
    <div className="generator" id="generator">
      <div className="generator-head">
        <div className="segmented" role="tablist">
          {(["password", "passphrase"] as const).map((kind) => (
            <button
              key={kind}
              type="button"
              role="tab"
              id={`generator-kind-${kind}`}
              aria-selected={choice.kind === kind}
              className={choice.kind === kind ? "active" : ""}
              onClick={() => setChoice((current) => ({ ...current, kind }))}
            >
              {t(`generator.${kind}` as Key)}
            </button>
          ))}
        </div>
        <IconButton icon="x" label={t("common.close")} onClick={onClose} />
      </div>

      <div className="generator-value">
        <output id="generator-value" className="mono">
          {result?.value ?? ""}
        </output>
        <IconButton
          icon="refresh"
          id="generator-again"
          label={t("generator.again")}
          onClick={() => void generate(toOptions(choice))}
        />
      </div>
      {result && <p className="hint generator-bits">{t("generator.bits", { n: result.bits })}</p>}

      {choice.kind === "password" ? (
        <div className="generator-options">
          <label className="range">
            <span>{t("generator.length")}</span>
            <input
              type="range"
              id="generator-length"
              min={8}
              max={64}
              value={password.length}
              onChange={(event) => setPassword({ length: Number(event.target.value) })}
            />
            <span className="range-value">{password.length}</span>
          </label>
          <div className="checks">
            {CLASSES.map(([key, label]) => (
              <label className="check" key={key}>
                <input
                  type="checkbox"
                  checked={password[key]}
                  // The last class cannot be switched off.
                  disabled={password[key] && enabledClasses === 1}
                  onChange={(event) =>
                    setPassword({ [key]: event.target.checked } as Partial<PasswordOptions>)
                  }
                />
                <span>{t(label)}</span>
              </label>
            ))}
            <label className="check">
              <input
                type="checkbox"
                checked={password.avoid_ambiguous}
                onChange={(event) => setPassword({ avoid_ambiguous: event.target.checked })}
              />
              <span>{t("generator.ambiguous")}</span>
            </label>
          </div>
        </div>
      ) : (
        <div className="generator-options">
          <label className="range">
            <span>{t("generator.words")}</span>
            <input
              type="range"
              id="generator-words"
              min={3}
              max={12}
              value={passphrase.words}
              onChange={(event) => setPassphrase({ words: Number(event.target.value) })}
            />
            <span className="range-value">{passphrase.words}</span>
          </label>
          <div className="checks">
            <label className="check">
              <span>{t("generator.separator")}</span>
              <select
                className="input compact"
                id="generator-separator"
                value={passphrase.separator}
                onChange={(event) => setPassphrase({ separator: event.target.value })}
              >
                {SEPARATORS.map(([value, label]) => (
                  <option key={label ?? value} value={value}>
                    {label ? t(label) : value}
                  </option>
                ))}
              </select>
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={passphrase.capitalize}
                onChange={(event) => setPassphrase({ capitalize: event.target.checked })}
              />
              <span>{t("generator.capitalize")}</span>
            </label>
            <label className="check">
              <input
                type="checkbox"
                checked={passphrase.number}
                onChange={(event) => setPassphrase({ number: event.target.checked })}
              />
              <span>{t("generator.number")}</span>
            </label>
          </div>
        </div>
      )}

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="row-end">
        <Button
          variant="primary"
          icon="check"
          id="generator-use"
          disabled={!result}
          onClick={() => result && onUse(result.value)}
        >
          {t("generator.use")}
        </Button>
      </div>
    </div>
  );
}
