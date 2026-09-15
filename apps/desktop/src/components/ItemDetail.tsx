import { useEffect, useState } from "react";
import { api } from "../api";
import { ADDRESS_FIELDS, FIELDS, isSecret } from "../fields";
import type { FieldDef } from "../fields";
import { errorText, useT } from "../i18n";
import type { Key } from "../i18n";
import { Icon } from "../icons";
import { MASKED } from "../types";
import type { ItemView, TotpNow } from "../types";
import { Button, ConfirmDialog, IconButton, useToast } from "../ui";

const HIDDEN = "••••••••••••";

function FieldRow({
  def,
  label,
  value,
  revealed,
  onReveal,
  onCopy,
}: {
  def: FieldDef;
  label?: string;
  value: unknown;
  revealed: string | undefined;
  onReveal: () => void;
  onCopy: () => void;
}) {
  const { t, lang } = useT();
  if (value === null || value === undefined || value === "") return null;
  if (Array.isArray(value) && value.length === 0) return null;

  const masked = value === MASKED;
  let text: string;
  if (masked) text = revealed ?? HIDDEN;
  else if (Array.isArray(value)) text = value.join("\n");
  else if (def.kind === "dateMs") text = new Date(Number(value)).toLocaleDateString(lang);
  else text = String(value);

  const multiline = def.kind === "multiline" || def.kind === "secretMultiline" || def.kind === "lines";
  const copyable = def.kind === "text" || isSecret(def.kind) || def.kind === "multiline";
  const mono = def.monospace || isSecret(def.kind);

  return (
    <div className="field-row">
      <div className="field-label">{label ?? t(def.label)}</div>
      <div
        className={`field-value ${mono ? "mono" : ""} ${multiline ? "pre" : ""} ${
          masked && revealed === undefined ? "hidden-value" : ""
        }`}
      >
        {text}
      </div>
      <div className="field-actions">
        {masked && isSecret(def.kind) && (
          <IconButton
            icon={revealed === undefined ? "eye" : "eyeOff"}
            label={t(revealed === undefined ? "detail.show" : "detail.hide")}
            onClick={onReveal}
          />
        )}
        {copyable && <IconButton icon="copy" label={t("detail.copy")} onClick={onCopy} />}
      </div>
    </div>
  );
}

function TotpBlock({ id }: { id: string }) {
  const { t } = useT();
  const toast = useToast();
  const [now, setNow] = useState<TotpNow | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let alive = true;
    const tick = () =>
      api
        .totpNow(id)
        .then((value) => {
          if (alive) {
            setNow(value);
            setFailed(false);
          }
        })
        .catch(() => {
          if (alive) setFailed(true);
        });
    void tick();
    const timer = window.setInterval(tick, 1000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, [id]);

  if (failed) return <div className="totp-block problem">{t("err.invalid_totp")}</div>;
  if (!now) return <div className="totp-block" />;

  const half = Math.ceil(now.code.length / 2);
  const copy = async () => {
    try {
      toast(t("detail.copied", { n: await api.copyText(now.code) }));
    } catch (error) {
      toast(errorText(t, error));
    }
  };
  return (
    <div className="totp-block" id="totp">
      <div className="totp-main">
        <div className="label-mini">{t("detail.code")}</div>
        <div className="totp-code mono">
          {now.code.slice(0, half)}
          <span className="totp-gap" />
          {now.code.slice(half)}
        </div>
      </div>
      <div className="totp-timer" aria-hidden="true">
        <div className="totp-track">
          <div className="totp-fill" style={{ width: `${(now.remaining / now.period) * 100}%` }} />
        </div>
        <span>{now.remaining}s</span>
      </div>
      <IconButton icon="copy" label={t("detail.copy")} onClick={copy} />
    </div>
  );
}

export function ItemDetail({
  id,
  serviceName,
  inTrash,
  onEdit,
  onChanged,
}: {
  id: string;
  serviceName: string | null;
  inTrash: boolean;
  onEdit: (id: string) => void;
  onChanged: (select?: string | null) => void;
}) {
  const { t, lang } = useT();
  const toast = useToast();
  const [item, setItem] = useState<ItemView | null>(null);
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [confirmPurge, setConfirmPurge] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api
      .getItem(id)
      .then((view) => {
        if (!alive) return;
        setItem(view);
        // Custom fields not marked hidden are meant to be read at a glance.
        view.custom_fields.forEach((field, index) => {
          if (field.hidden || field.value !== MASKED) return;
          const pointer = `/custom_fields/${index}/value`;
          api
            .revealField(id, pointer)
            .then((value) => alive && setRevealed((current) => ({ ...current, [pointer]: value })))
            .catch(() => {});
        });
      })
      .catch((err) => alive && setError(errorText(t, err)));
    return () => {
      alive = false;
    };
  }, [id, t]);

  if (error) return <div className="detail-empty">{error}</div>;
  if (!item) return null;

  const toggle = async (pointer: string) => {
    if (pointer in revealed) {
      setRevealed(({ [pointer]: _, ...rest }) => rest);
      return;
    }
    try {
      const value = await api.revealField(id, pointer);
      setRevealed((current) => ({ ...current, [pointer]: value }));
    } catch (err) {
      toast(errorText(t, err));
    }
  };

  const copy = async (pointer: string) => {
    try {
      toast(t("detail.copied", { n: await api.copyField(id, pointer) }));
    } catch (err) {
      toast(errorText(t, err));
    }
  };

  const run = async (action: () => Promise<unknown>, select?: string | null) => {
    try {
      await action();
      onChanged(select);
    } catch (err) {
      toast(errorText(t, err));
    }
  };

  const toggleFavorite = () =>
    run(async () => {
      const full = await api.getItemForEdit(id);
      await api.saveItem({ ...full, favorite: !full.favorite });
    }, id);

  const row = (def: FieldDef, value: unknown, pointer: string, label?: string) => (
    <FieldRow
      key={pointer}
      def={def}
      label={label}
      value={value}
      revealed={revealed[pointer]}
      onReveal={() => toggle(pointer)}
      onCopy={() => copy(pointer)}
    />
  );

  const data = item.data;
  const values = data as unknown as Record<string, unknown>;
  const type = data.type;
  const hasTotp = type === "totp" || (type === "login" && data.totp !== null);
  const date = (ms: number) =>
    new Date(ms).toLocaleDateString(lang, { year: "numeric", month: "long", day: "numeric" });
  const secretDef: FieldDef = { key: "", label: "field.code", kind: "secret", monospace: true };
  const textDef: FieldDef = { key: "", label: "field.text", kind: "text" };

  return (
    <article className="detail" id="item-detail" data-id={id}>
      <header className="detail-head">
        <span className="type-badge">
          <Icon name={type} size={22} />
        </span>
        <div className="detail-title">
          <div className="label-mini">{t(`type.${type}` as Key)}</div>
          <h2>{serviceName ?? (item.label || t(`type.${type}` as Key))}</h2>
          {serviceName && item.label && <div className="detail-sub">{item.label}</div>}
        </div>
        <div className="detail-actions">
          {inTrash ? (
            <>
              <Button icon="restore" id="restore-item" onClick={() => run(() => api.restoreItem(id), id)}>
                {t("detail.restore")}
              </Button>
              <Button variant="danger" icon="trash" id="purge-item" onClick={() => setConfirmPurge(true)}>
                {t("detail.purge")}
              </Button>
            </>
          ) : (
            <>
              <IconButton
                icon="star"
                id="favorite-item"
                className={item.favorite ? "on" : ""}
                label={t(item.favorite ? "detail.unfavorite" : "detail.favorite")}
                onClick={toggleFavorite}
              />
              <IconButton
                icon="trash"
                id="trash-item"
                label={t("detail.trash")}
                onClick={() => run(() => api.trashItem(id), null)}
              />
              <Button icon="edit" id="edit-item" onClick={() => onEdit(id)}>
                {t("detail.edit")}
              </Button>
            </>
          )}
        </div>
      </header>

      {hasTotp && !inTrash && <TotpBlock id={id} />}

      <div className="field-list">
        {FIELDS[type].map((def) => row(def, values[def.key], `/data/${def.key}`))}
      </div>

      {type === "login" && data.password_history.length > 0 && (
        <details className="detail-section history" id="password-history">
          <summary className="section-label">
            {t("detail.history", { n: data.password_history.length })}
          </summary>
          <div className="field-list">
            {data.password_history.map((change, index) =>
              row(
                secretDef,
                change.password,
                `/data/password_history/${index}/password`,
                t("detail.replaced", { date: date(change.replaced_at) }),
              ),
            )}
          </div>
        </details>
      )}

      {type === "recovery_codes" && data.codes.length > 0 && (
        <section className="detail-section">
          <div className="section-label">
            {t("detail.codesLeft", {
              left: data.codes.filter((code) => !code.used).length,
              total: data.codes.length,
            })}
          </div>
          <div className="field-list">
            {data.codes.map((code, index) =>
              row(
                secretDef,
                code.code,
                `/data/codes/${index}/code`,
                `${index + 1}${code.used ? ` · ${t("detail.used")}` : ""}`,
              ),
            )}
          </div>
        </section>
      )}

      {type === "identity" && data.address && (
        <section className="detail-section">
          <div className="section-label">{t("detail.address")}</div>
          <div className="field-list">
            {ADDRESS_FIELDS.map((def) =>
              row(def, (data.address as unknown as Record<string, unknown>)[def.key], `/data/address/${def.key}`),
            )}
          </div>
        </section>
      )}

      {type === "identity" && data.documents.length > 0 && (
        <section className="detail-section">
          <div className="section-label">{t("detail.documents")}</div>
          <div className="field-list">
            {data.documents.map((doc, index) =>
              row(
                secretDef,
                doc.number,
                `/data/documents/${index}/number`,
                doc.expires ? `${doc.kind} · ${doc.expires}` : doc.kind,
              ),
            )}
          </div>
        </section>
      )}

      {item.custom_fields.length > 0 && (
        <section className="detail-section">
          <div className="section-label">{t("detail.custom")}</div>
          <div className="field-list">
            {item.custom_fields.map((field, index) =>
              row(
                field.hidden ? secretDef : textDef,
                field.value,
                `/custom_fields/${index}/value`,
                field.name || "?",
              ),
            )}
          </div>
        </section>
      )}

      {item.notes && (
        <section className="detail-section">
          <div className="field-list">
            {row({ key: "notes", label: "detail.notes", kind: "secretMultiline" }, item.notes, "/notes")}
          </div>
        </section>
      )}

      {item.tags.length > 0 && (
        <div className="tags">
          {item.tags.map((tag) => (
            <span className="chip" key={tag}>
              {tag}
            </span>
          ))}
        </div>
      )}

      <footer className="detail-foot">
        {inTrash && item.deleted_at
          ? t("detail.inTrash", { date: date(item.deleted_at) })
          : t("detail.changed", { date: date(item.updated) })}
      </footer>

      {confirmPurge && (
        <ConfirmDialog
          message={t("detail.purgeConfirm")}
          confirmLabel={t("detail.purge")}
          onCancel={() => setConfirmPurge(false)}
          onConfirm={() => {
            setConfirmPurge(false);
            void run(() => api.purgeItem(id), null);
          }}
        />
      )}
    </article>
  );
}
