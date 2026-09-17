import { useState } from "react";
import { api, errorCode } from "../api";
import { errorText, useT } from "../i18n";
import { Button, Modal } from "../ui";

/** Asked once after an unlock with the master password. */
export function HelloOffer({
  reminderDays,
  onDone,
}: {
  reminderDays: number;
  onDone: (enabled: boolean) => void;
}) {
  const { t } = useT();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const dismiss = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await api.helloDismiss();
    } catch {
      // Then Krypt simply asks again after the next unlock.
    }
    onDone(false);
  };

  const enable = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.helloEnable();
      onDone(true);
    } catch (err) {
      if (errorCode(err) !== "hello_canceled") setError(errorText(t, err));
      setBusy(false);
    }
  };

  return (
    <Modal title={t("hello.offerTitle")} onClose={dismiss} id="hello-offer">
      <div className="editor-body">
        <p className="dialog-lead">
          {reminderDays > 0
            ? t("hello.offerText", { n: reminderDays })
            : t("hello.offerTextNever")}
        </p>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
      </div>
      <footer className="dialog-foot">
        <Button id="hello-not-now" disabled={busy} onClick={dismiss}>
          {t("hello.notNow")}
        </Button>
        <Button variant="primary" icon="passkey" id="hello-enable" disabled={busy} onClick={enable}>
          {t("hello.enable")}
        </Button>
      </footer>
    </Modal>
  );
}
