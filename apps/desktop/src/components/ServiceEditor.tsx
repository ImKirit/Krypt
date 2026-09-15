import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../api";
import { splitLines } from "../fields";
import { errorText, useT } from "../i18n";
import type { Service } from "../types";
import { Button, Modal, TextField } from "../ui";

export function ServiceEditor({
  service,
  onClose,
  onSaved,
  onDeleted,
}: {
  service: Service;
  onClose: () => void;
  onSaved: () => void;
  onDeleted: () => void;
}) {
  const { t } = useT();
  const [name, setName] = useState(service.name);
  const [domains, setDomains] = useState(service.domains.map((domain) => domain.host).join("\n"));
  const [favorite, setFavorite] = useState(service.favorite);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const hosts = splitLines(domains);
      await api.saveService({
        ...service,
        name,
        favorite,
        domains: hosts.map(
          (host) =>
            service.domains.find((domain) => domain.host === host) ?? {
              host,
              matching: "registrable_domain",
            },
        ),
      });
      onSaved();
    } catch (err) {
      setError(errorText(t, err));
      setBusy(false);
    }
  };

  const remove = async () => {
    setError(null);
    try {
      await api.trashService(service.id);
      onDeleted();
    } catch (err) {
      setError(errorText(t, err));
    }
  };

  return (
    <Modal title={t("service.title")} onClose={onClose} id="service-editor">
      <form className="editor" onSubmit={submit}>
        <div className="editor-body">
          <TextField id="service-name" label={t("editor.serviceName")} value={name} onChange={setName} autoFocus />
          <TextField
            id="service-domains"
            label={t("editor.domains")}
            value={domains}
            onChange={setDomains}
            placeholder="example.com"
            multiline
            rows={3}
            mono
          />
          <label className="check">
            <input type="checkbox" checked={favorite} onChange={(event) => setFavorite(event.target.checked)} />
            <span>{t("service.favorite")}</span>
          </label>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
        </div>
        <footer className="dialog-foot">
          <Button variant="danger" icon="trash" className="push-left" onClick={remove}>
            {t("service.delete")}
          </Button>
          <Button onClick={onClose}>{t("common.cancel")}</Button>
          <Button type="submit" variant="primary" disabled={busy}>
            {t("common.save")}
          </Button>
        </footer>
      </form>
    </Modal>
  );
}
