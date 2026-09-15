import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../api";
import { errorText, useT } from "../i18n";
import type { Key } from "../i18n";
import type { ImportPreview, ImportResult } from "../types";
import { Button, Modal, SecretField } from "../ui";

const SHOWN_SERVICES = 12;

function ServiceList({ id, names }: { id: string; names: string[] }) {
  const { t } = useT();
  const shown = names.slice(0, SHOWN_SERVICES);
  const rest = names.length - shown.length;
  return (
    <p className="import-services" id={id}>
      {shown.map((name, index) => (
        <span className="chip" key={index}>
          {name}
        </span>
      ))}
      {rest > 0 && <span className="hint">{t("import.more", { n: rest })}</span>}
    </p>
  );
}

export function ImportDialog({
  onClose,
  onImported,
}: {
  onClose: () => void;
  onImported: (result: ImportResult) => void;
}) {
  const { t } = useT();
  const [preview, setPreview] = useState<ImportPreview | null>(null);
  const [password, setPassword] = useState("");
  const [deleteSource, setDeleteSource] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // The backend holds the read entries until the import is confirmed or dropped.
  const close = () => {
    if (busy) return;
    api.importCancel().catch(() => {});
    onClose();
  };

  const run = async (task: () => Promise<void>) => {
    setBusy(true);
    setError(null);
    try {
      await task();
    } catch (err) {
      setError(errorText(t, err));
    } finally {
      setBusy(false);
    }
  };

  const pick = () =>
    run(async () => {
      const next = await api.importPick(t("import.dialogTitle"));
      if (!next) return;
      setPreview(next);
      setPassword("");
      setDeleteSource(false);
    });

  const unlock = (event: FormEvent) => {
    event.preventDefault();
    if (!password || busy) return;
    void run(async () => {
      setPreview(await api.importUnlock(password));
      setPassword("");
    });
  };

  const commit = () =>
    run(async () => {
      onImported(await api.importCommit(deleteSource));
    });

  const errorBlock = error && (
    <p className="error" role="alert">
      {error}
    </p>
  );

  if (!preview) {
    return (
      <Modal title={t("import.title")} onClose={close} id="import">
        <div className="editor">
          <div className="editor-body">
            <p className="dialog-lead">{t("import.lead")}</p>
            <p className="hint">{t("import.sources")}</p>
            {errorBlock}
          </div>
          <footer className="dialog-foot">
            <Button onClick={close} disabled={busy}>
              {t("common.cancel")}
            </Button>
            <Button variant="primary" icon="import" id="import-pick" disabled={busy} onClick={pick}>
              {t("import.pick")}
            </Button>
          </footer>
        </div>
      </Modal>
    );
  }

  if (preview.needs_password) {
    return (
      <Modal title={t("import.title")} onClose={close} id="import">
        <form className="editor" onSubmit={unlock}>
          <div className="editor-body">
            <p className="dialog-lead">{t("import.passwordLead", { file: preview.file_name })}</p>
            <SecretField
              id="import-password"
              label={t("import.password")}
              value={password}
              onChange={setPassword}
              mono={false}
              autoFocus
            />
            {errorBlock}
          </div>
          <footer className="dialog-foot">
            <Button className="push-left" disabled={busy} onClick={pick}>
              {t("import.another")}
            </Button>
            <Button onClick={close} disabled={busy}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" variant="primary" id="import-unlock" disabled={busy || !password}>
              {t("import.unlock")}
            </Button>
          </footer>
        </form>
      </Modal>
    );
  }

  const source = preview.source ? t(`source.${preview.source}` as Key) : "";
  return (
    <Modal title={t("import.title")} onClose={close} wide id="import">
      <div className="editor" id="import-preview">
        <div className="editor-body">
          <p className="hint">{t("import.recognized", { file: preview.file_name, source })}</p>
          {preview.total > 0 ? (
            <div className="import-summary">
              <p className="import-total" id="import-total">
                {t("import.total", { n: preview.total })}
              </p>
              <div className="tags">
                {preview.counts.map((entry) => (
                  <span className="chip" key={entry.item_type}>
                    {t(`type.${entry.item_type}` as Key)} <strong>{entry.count}</strong>
                  </span>
                ))}
              </div>
            </div>
          ) : (
            <p className="import-total" id="import-nothing">
              {t("import.nothing")}
            </p>
          )}
          {preview.new_services.length > 0 && (
            <div className="detail-section">
              <div className="section-label">
                {t("import.newServices", { n: preview.new_services.length })}
              </div>
              <ServiceList id="import-new-services" names={preview.new_services} />
            </div>
          )}
          {preview.existing_services.length > 0 && (
            <div className="detail-section">
              <div className="section-label">{t("import.existingServices")}</div>
              <ServiceList id="import-existing-services" names={preview.existing_services} />
            </div>
          )}
          {preview.duplicates > 0 && (
            <p className="hint" id="import-duplicates">
              {t("import.duplicates", { n: preview.duplicates })}
            </p>
          )}
          {preview.skipped > 0 && (
            <p className="hint" id="import-skipped">
              {t("import.skipped", { n: preview.skipped })}
            </p>
          )}
          {preview.plaintext && preview.total > 0 && (
            <div className="subsection">
              <label className="check">
                <input
                  type="checkbox"
                  id="import-delete"
                  checked={deleteSource}
                  onChange={(event) => setDeleteSource(event.target.checked)}
                />
                <span>{t("import.delete")}</span>
              </label>
              <p className="hint">{t("import.deleteHint")}</p>
            </div>
          )}
          {errorBlock}
        </div>
        <footer className="dialog-foot">
          <Button className="push-left" id="import-another" disabled={busy} onClick={pick}>
            {t("import.another")}
          </Button>
          <Button onClick={close} disabled={busy}>
            {t("common.cancel")}
          </Button>
          <Button
            variant="primary"
            icon="import"
            id="import-commit"
            disabled={busy || preview.total === 0}
            onClick={commit}
          >
            {busy ? t("import.busy") : t("import.button", { n: preview.total })}
          </Button>
        </footer>
      </div>
    </Modal>
  );
}
