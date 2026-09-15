import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../api";
import { errorText, useT } from "../i18n";
import { rulesMet } from "../rules";
import { RecoveryKeyPanel } from "../screens/Gate";
import type { Settings, Status } from "../types";
import {
  Button,
  ConfirmDialog,
  Modal,
  PasswordChecklist,
  SecretField,
  StrengthMeter,
} from "../ui";

const AUTO_LOCK = [1, 5, 15, 30, 60, 0];
const CLIPBOARD = [10, 30, 60, 120];

export function SettingsDialog({
  status,
  onStatus,
  onClose,
  onImport,
  onExport,
}: {
  status: Status;
  onStatus: (status: Status) => void;
  onClose: () => void;
  onImport: () => void;
  onExport: () => void;
}) {
  const { t } = useT();
  const settings = status.settings;
  const min = status.min_password_chars;
  const [error, setError] = useState<string | null>(null);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [passwordMessage, setPasswordMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [confirmRecovery, setConfirmRecovery] = useState(false);
  const [newKey, setNewKey] = useState<string | null>(null);

  const save = async (patch: Partial<Settings>) => {
    setError(null);
    try {
      const saved = await api.saveSettings({ ...settings, ...patch });
      onStatus({ ...status, settings: saved });
    } catch (err) {
      setError(errorText(t, err));
    }
  };

  const changePassword = async (event: FormEvent) => {
    event.preventDefault();
    setPasswordMessage(null);
    setBusy(true);
    try {
      await api.changePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      setPasswordMessage(t("settings.changed"));
    } catch (err) {
      setPasswordMessage(errorText(t, err, { n: min }));
    } finally {
      setBusy(false);
    }
  };

  const createRecoveryKey = async () => {
    setConfirmRecovery(false);
    setError(null);
    try {
      setNewKey(await api.newRecoveryKey());
    } catch (err) {
      setError(errorText(t, err));
    }
  };

  const ready = current.length > 0 && rulesMet(next, min) && next === confirm;

  return (
    <Modal
      title={t("settings.title")}
      onClose={() => {
        if (!confirmRecovery) onClose();
      }}
      wide
      id="settings"
    >
      <div className="editor-body settings">
        <section className="settings-section">
          <div className="section-label">{t("settings.general")}</div>
          <div className="grid-3">
            <div className="form-field">
              <label htmlFor="settings-language">{t("settings.language")}</label>
              <select
                id="settings-language"
                className="input"
                value={settings.language ?? ""}
                onChange={(event) =>
                  save({ language: (event.target.value || null) as Settings["language"] })
                }
              >
                <option value="">{t("settings.system")}</option>
                <option value="en">English</option>
                <option value="de">Deutsch</option>
              </select>
            </div>
            <div className="form-field">
              <label htmlFor="settings-autolock">{t("settings.autoLock")}</label>
              <select
                id="settings-autolock"
                className="input"
                value={settings.auto_lock_minutes}
                onChange={(event) => save({ auto_lock_minutes: Number(event.target.value) })}
              >
                {AUTO_LOCK.map((minutes) => (
                  <option key={minutes} value={minutes}>
                    {minutes === 0
                      ? t("settings.never")
                      : minutes === 1
                        ? t("settings.oneMinute")
                        : t("settings.minutes", { n: minutes })}
                  </option>
                ))}
              </select>
            </div>
            <div className="form-field">
              <label htmlFor="settings-clipboard">{t("settings.clipboard")}</label>
              <select
                id="settings-clipboard"
                className="input"
                value={settings.clipboard_clear_seconds}
                onChange={(event) => save({ clipboard_clear_seconds: Number(event.target.value) })}
              >
                {CLIPBOARD.map((seconds) => (
                  <option key={seconds} value={seconds}>
                    {t("settings.seconds", { n: seconds })}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <label className="check">
            <input
              type="checkbox"
              id="settings-lock-with-windows"
              checked={settings.lock_with_windows}
              onChange={(event) => save({ lock_with_windows: event.target.checked })}
            />
            <span>{t("settings.lockWithWindows")}</span>
          </label>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
        </section>

        <section className="settings-section">
          <div className="section-label">{t("settings.data")}</div>
          <div className="row-between">
            <p className="hint">{t("settings.dataLead")}</p>
            <div className="row-end">
              <Button icon="import" id="settings-import" onClick={onImport}>
                {t("settings.import")}
              </Button>
              <Button icon="export" id="settings-export" onClick={onExport}>
                {t("settings.export")}
              </Button>
            </div>
          </div>
        </section>

        <section className="settings-section">
          <div className="section-label">{t("settings.password")}</div>
          <form className="grid-3" onSubmit={changePassword}>
            <SecretField id="settings-current" label={t("settings.current")} value={current} onChange={setCurrent} mono={false} />
            <div>
              <SecretField id="settings-new" label={t("settings.new")} value={next} onChange={setNext} mono={false} />
              <StrengthMeter password={next} />
            </div>
            <SecretField id="settings-confirm" label={t("settings.confirm")} value={confirm} onChange={setConfirm} mono={false} />
            {next && (
              <div className="span-3">
                <PasswordChecklist id="settings-rules" password={next} minChars={min} />
              </div>
            )}
            <div className="span-3 row-end">
              {passwordMessage && <p className="hint">{passwordMessage}</p>}
              <Button type="submit" variant="primary" disabled={!ready || busy}>
                {t("settings.change")}
              </Button>
            </div>
          </form>
        </section>

        <section className="settings-section">
          <div className="section-label">{t("settings.recovery")}</div>
          {newKey ? (
            <RecoveryKeyPanel value={newKey} doneLabel={t("common.close")} onDone={() => setNewKey(null)} />
          ) : (
            <div className="row-between">
              <p className="hint">{t("settings.recoveryLead")}</p>
              <Button onClick={() => setConfirmRecovery(true)}>{t("settings.recoveryNew")}</Button>
            </div>
          )}
        </section>
      </div>
      {confirmRecovery && (
        <ConfirmDialog
          message={t("settings.recoveryConfirm")}
          confirmLabel={t("settings.replace")}
          onCancel={() => setConfirmRecovery(false)}
          onConfirm={createRecoveryKey}
        />
      )}
    </Modal>
  );
}
