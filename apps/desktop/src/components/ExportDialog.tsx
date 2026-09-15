import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../api";
import { errorText, useT } from "../i18n";
import { rulesMet } from "../rules";
import { Button, Modal, PasswordChecklist, SecretField, useToast } from "../ui";

export function ExportDialog({ minChars, onClose }: { minChars: number; onClose: () => void }) {
  const { t } = useT();
  const toast = useToast();
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const ready = rulesMet(password, minChars) && password === confirm;

  const close = () => {
    if (!busy) onClose();
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (!ready || busy) return;
    setBusy(true);
    setError(null);
    try {
      const file = await api.exportVault(password, t("export.dialogTitle"));
      if (file === null) {
        setBusy(false);
        return;
      }
      toast(t("export.done", { file }));
      onClose();
    } catch (err) {
      setError(errorText(t, err, { n: minChars }));
      setBusy(false);
    }
  };

  return (
    <Modal title={t("export.title")} onClose={close} id="export">
      <form className="editor" onSubmit={submit}>
        <div className="editor-body">
          <p className="dialog-lead">{t("export.lead")}</p>
          <SecretField
            id="export-password"
            label={t("export.password")}
            value={password}
            onChange={setPassword}
            mono={false}
            autoFocus
          />
          <PasswordChecklist id="export-rules" password={password} minChars={minChars} />
          <SecretField
            id="export-confirm"
            label={t("export.confirm")}
            value={confirm}
            onChange={setConfirm}
            mono={false}
          />
          {confirm && password !== confirm && <p className="hint warn">{t("setup.mismatch")}</p>}
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
        </div>
        <footer className="dialog-foot">
          <Button onClick={close} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button type="submit" variant="primary" icon="export" id="export-save" disabled={!ready || busy}>
            {busy ? t("export.busy") : t("export.button")}
          </Button>
        </footer>
      </form>
    </Modal>
  );
}
