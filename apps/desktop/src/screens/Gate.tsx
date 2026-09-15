import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../api";
import { errorText, useT } from "../i18n";
import { Icon } from "../icons";
import { Brand, Button, SecretField, StrengthMeter, TextField, useToast } from "../ui";

function passwordProblems(password: string, confirm: string, minChars: number) {
  return {
    tooShort: [...password].length < minChars,
    mismatch: confirm.length > 0 && password !== confirm,
    ready: [...password].length >= minChars && password === confirm,
  };
}

export function Setup({
  minChars,
  onCreated,
}: {
  minChars: number;
  onCreated: (recoveryKey: string) => void;
}) {
  const { t } = useT();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const check = passwordProblems(password, confirm, minChars);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!check.ready || busy) return;
    setBusy(true);
    setError(null);
    try {
      onCreated(await api.createVault(password));
    } catch (err) {
      setError(errorText(t, err, { n: minChars }));
      setBusy(false);
    }
  };

  return (
    <div className="gate">
      <form className="gate-card" id="setup" onSubmit={submit}>
        <Brand />
        <h1>{t("setup.title")}</h1>
        <p className="lead">{t("setup.lead")}</p>
        <SecretField
          id="setup-password"
          label={t("setup.password")}
          value={password}
          onChange={setPassword}
          mono={false}
          autoFocus
        />
        <StrengthMeter password={password} />
        <p className={`hint ${check.tooShort && password ? "warn" : ""}`}>
          {t("setup.min", { n: minChars })}
        </p>
        <SecretField
          id="setup-confirm"
          label={t("setup.confirm")}
          value={confirm}
          onChange={setConfirm}
          mono={false}
        />
        {check.mismatch && <p className="hint warn">{t("setup.mismatch")}</p>}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <Button type="submit" variant="primary" id="setup-create" disabled={busy || !check.ready}>
          {busy ? t("setup.creating") : t("setup.create")}
        </Button>
      </form>
    </div>
  );
}

export function RecoveryKeyPanel({
  value,
  doneLabel,
  onDone,
}: {
  value: string;
  doneLabel: string;
  onDone: () => void;
}) {
  const { t } = useT();
  const toast = useToast();
  const [saved, setSaved] = useState(false);
  const copy = async () => {
    try {
      const seconds = await api.copyText(value);
      toast(t("detail.copied", { n: seconds }));
    } catch (err) {
      toast(errorText(t, err));
    }
  };
  return (
    <div className="recovery">
      <div className="recovery-key" id="recovery-key-value">
        {value.split("-").map((group, index) => (
          <span key={index}>{group}</span>
        ))}
      </div>
      <Button icon="copy" onClick={copy}>
        {t("recovery.copy")}
      </Button>
      <label className="check">
        <input
          type="checkbox"
          id="recovery-saved"
          checked={saved}
          onChange={(event) => setSaved(event.target.checked)}
        />
        <span>{t("recovery.saved")}</span>
      </label>
      <Button variant="primary" id="recovery-done" disabled={!saved} onClick={onDone}>
        {doneLabel}
      </Button>
    </div>
  );
}

export function RecoveryKeyScreen({ value, onDone }: { value: string; onDone: () => void }) {
  const { t } = useT();
  return (
    <div className="gate">
      <div className="gate-card wide" id="recovery-screen">
        <Brand />
        <h1>{t("recovery.title")}</h1>
        <p className="lead">{t("recovery.lead")}</p>
        <RecoveryKeyPanel value={value} doneLabel={t("recovery.continue")} onDone={onDone} />
      </div>
    </div>
  );
}

export function Unlock({ minChars, onUnlocked }: { minChars: number; onUnlocked: () => void }) {
  const { t } = useT();
  const [mode, setMode] = useState<"password" | "recover">("password");
  const [password, setPassword] = useState("");
  const [recoveryKey, setRecoveryKey] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const check = passwordProblems(newPassword, confirm, minChars);

  const switchMode = (next: "password" | "recover") => {
    setMode(next);
    setError(null);
  };

  const unlock = async (event: FormEvent) => {
    event.preventDefault();
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.unlock(password);
      setPassword("");
      onUnlocked();
    } catch (err) {
      setError(errorText(t, err));
      setBusy(false);
    }
  };

  const recover = async (event: FormEvent) => {
    event.preventDefault();
    if (!check.ready || !recoveryKey.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await api.recover(recoveryKey, newPassword);
      onUnlocked();
    } catch (err) {
      setError(errorText(t, err, { n: minChars }));
      setBusy(false);
    }
  };

  if (mode === "recover") {
    return (
      <div className="gate">
        <form className="gate-card" id="recover" onSubmit={recover}>
          <Brand />
          <h1>{t("recover.title")}</h1>
          <p className="lead">{t("recover.lead")}</p>
          <TextField
            id="recover-key"
            label={t("recover.key")}
            value={recoveryKey}
            onChange={setRecoveryKey}
            placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
            mono
            autoFocus
          />
          <SecretField
            id="recover-password"
            label={t("recover.newPassword")}
            value={newPassword}
            onChange={setNewPassword}
            mono={false}
          />
          <StrengthMeter password={newPassword} />
          <p className={`hint ${check.tooShort && newPassword ? "warn" : ""}`}>
            {t("setup.min", { n: minChars })}
          </p>
          <SecretField
            id="recover-confirm"
            label={t("recover.confirm")}
            value={confirm}
            onChange={setConfirm}
            mono={false}
          />
          {check.mismatch && <p className="hint warn">{t("setup.mismatch")}</p>}
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <div className="gate-actions">
            <Button onClick={() => switchMode("password")}>{t("common.back")}</Button>
            <Button
              type="submit"
              variant="primary"
              disabled={busy || !check.ready || !recoveryKey.trim()}
            >
              {t("recover.button")}
            </Button>
          </div>
        </form>
      </div>
    );
  }

  return (
    <div className="gate">
      <form className="gate-card" id="unlock" onSubmit={unlock}>
        <Brand />
        <h1>{t("unlock.title")}</h1>
        <SecretField
          id="unlock-password"
          label={t("unlock.password")}
          value={password}
          onChange={setPassword}
          mono={false}
          autoFocus
        />
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <Button type="submit" variant="primary" id="unlock-button" disabled={busy || !password}>
          {busy ? t("unlock.busy") : t("unlock.button")}
        </Button>
        <button type="button" className="link" id="forgot" onClick={() => switchMode("recover")}>
          {t("unlock.forgot")}
        </button>
      </form>
    </div>
  );
}

export function Problem({ message }: { message: string }) {
  const { t } = useT();
  return (
    <div className="gate">
      <div className="gate-card" id="problem">
        <Brand />
        <h1>
          <Icon name="warning" size={26} /> {t("problem.title")}
        </h1>
        <p className="lead">{message}</p>
      </div>
    </div>
  );
}
