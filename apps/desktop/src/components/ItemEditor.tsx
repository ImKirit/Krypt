import { useState } from "react";
import type { FormEvent } from "react";
import { api } from "../api";
import {
  ADDRESS_FIELDS,
  FIELDS,
  defaultTotp,
  isWide,
  normalizeData,
  parseOtpauth,
  splitLines,
} from "../fields";
import type { FieldDef } from "../fields";
import { errorText, useT } from "../i18n";
import type { Key } from "../i18n";
import { Icon } from "../icons";
import { ITEM_TYPES } from "../types";
import type {
  Address,
  CustomField,
  IdDocument,
  Item,
  ItemData,
  ItemType,
  RecoveryCode,
  ServiceSummary,
  TotpConfig,
} from "../types";
import { Button, ConfirmDialog, IconButton, Modal, SecretField, TextField } from "../ui";
import { GeneratorPanel } from "./Generator";

const NEW_SERVICE = "__new__";

type Patch = Record<string, unknown>;

function FieldInput({ def, value, onChange }: { def: FieldDef; value: unknown; onChange: (value: unknown) => void }) {
  const { t } = useT();
  const [generating, setGenerating] = useState(false);
  const id = `field-${def.key}`;
  const label = t(def.label);
  const asText = (v: unknown) => (v === null || v === undefined ? "" : String(v));
  const fromText = (text: string) => (def.nullable && text === "" ? null : text);
  const wrap = (node: React.ReactNode) => (isWide(def.kind) ? <div className="span-2">{node}</div> : node);

  switch (def.kind) {
    case "secret": {
      const field = (
        <SecretField
          id={id}
          label={label}
          value={asText(value)}
          mono={def.monospace}
          disabled={def.readOnly}
          onChange={(text) => onChange(fromText(text))}
          onGenerate={def.generate ? () => setGenerating((open) => !open) : undefined}
        />
      );
      if (!def.generate) return field;
      return (
        <div className="span-2 generated-field">
          {field}
          {generating && (
            <GeneratorPanel
              onUse={(text) => {
                onChange(text);
                setGenerating(false);
              }}
              onClose={() => setGenerating(false)}
            />
          )}
        </div>
      );
    }
    case "secretMultiline":
      return wrap(
        <SecretField id={id} label={label} value={asText(value)} multiline mono={def.monospace} onChange={(text) => onChange(fromText(text))} />,
      );
    case "multiline":
      return wrap(
        <TextField id={id} label={label} value={asText(value)} multiline mono={def.monospace} onChange={(text) => onChange(fromText(text))} />,
      );
    case "lines":
      return wrap(
        <TextField
          id={id}
          label={label}
          value={Array.isArray(value) ? value.join("\n") : ""}
          multiline
          rows={3}
          onChange={(text) => onChange(text.split("\n"))}
        />,
      );
    case "number":
      return (
        <TextField
          id={id}
          label={label}
          type="number"
          value={asText(value)}
          disabled={def.readOnly}
          onChange={(text) => onChange(text === "" ? (def.nullable ? null : 0) : Number(text))}
        />
      );
    case "dateMs":
      return (
        <TextField
          id={id}
          label={label}
          type="date"
          value={typeof value === "number" ? new Date(value).toISOString().slice(0, 10) : ""}
          onChange={(text) => onChange(text ? Date.parse(`${text}T00:00:00Z`) : null)}
        />
      );
    case "date":
      return <TextField id={id} label={label} type="date" value={asText(value)} onChange={(text) => onChange(text || null)} />;
    case "select":
      return (
        <div className="form-field">
          <label htmlFor={id}>{label}</label>
          <select id={id} className="input" value={asText(value)} onChange={(event) => onChange(event.target.value)}>
            {def.options?.map((option) => (
              <option key={option} value={option}>
                {option.toUpperCase()}
              </option>
            ))}
          </select>
        </div>
      );
    default:
      return (
        <TextField id={id} label={label} value={asText(value)} mono={def.monospace} disabled={def.readOnly} onChange={(text) => onChange(fromText(text))} />
      );
  }
}

function LoginTotp({ totp, onChange }: { totp: TotpConfig | null; onChange: (totp: TotpConfig | null) => void }) {
  const { t } = useT();
  if (!totp) {
    return (
      <div className="subsection">
        <Button icon="totp" id="add-totp" onClick={() => onChange(defaultTotp())}>
          {t("editor.addTotp")}
        </Button>
      </div>
    );
  }
  const advanced = FIELDS.totp.filter((def) => ["algorithm", "digits", "period"].includes(def.key));
  return (
    <div className="subsection">
      <div className="subsection-head">
        <div className="section-label">{t("editor.totp")}</div>
        <Button variant="ghost" icon="x" onClick={() => onChange(null)}>
          {t("common.remove")}
        </Button>
      </div>
      <div className="grid-2">
        <SecretField
          id="field-totp-secret"
          label={t("field.totp_secret")}
          value={totp.secret}
          hint={t("editor.totpHint")}
          onChange={(text) => onChange(parseOtpauth(text) ?? { ...totp, secret: text })}
        />
        <TextField
          id="field-totp-issuer"
          label={t("field.issuer")}
          value={totp.issuer ?? ""}
          onChange={(text) => onChange({ ...totp, issuer: text || null })}
        />
      </div>
      <details className="advanced">
        <summary>{t("editor.advanced")}</summary>
        <div className="grid-3">
          {advanced.map((def) => (
            <FieldInput
              key={def.key}
              def={def}
              value={(totp as unknown as Patch)[def.key]}
              onChange={(value) => onChange({ ...totp, [def.key]: value })}
            />
          ))}
        </div>
      </details>
    </div>
  );
}

function CodesEditor({ codes, onChange }: { codes: RecoveryCode[]; onChange: (codes: RecoveryCode[]) => void }) {
  const { t } = useT();
  const [paste, setPaste] = useState("");
  const update = (index: number, patch: Partial<RecoveryCode>) =>
    onChange(codes.map((code, i) => (i === index ? { ...code, ...patch } : code)));
  return (
    <div className="subsection">
      <div className="section-label">{t("editor.codes")}</div>
      {codes.map((code, index) => (
        <div className="repeat-row" key={index}>
          <input
            className="input mono"
            aria-label={`${t("field.code")} ${index + 1}`}
            value={code.code}
            spellCheck={false}
            onChange={(event) => update(index, { code: event.target.value })}
          />
          <label className="check">
            <input type="checkbox" checked={code.used} onChange={(event) => update(index, { used: event.target.checked })} />
            <span>{t("detail.used")}</span>
          </label>
          <IconButton icon="x" label={t("common.remove")} onClick={() => onChange(codes.filter((_, i) => i !== index))} />
        </div>
      ))}
      <TextField id="codes-paste" label={t("editor.pasteCodes")} value={paste} onChange={setPaste} multiline rows={3} mono />
      <Button
        icon="plus"
        id="codes-add"
        disabled={!paste.trim()}
        onClick={() => {
          onChange([...codes, ...splitLines(paste).map((code) => ({ code, used: false }))]);
          setPaste("");
        }}
      >
        {t("editor.addCodes")}
      </Button>
    </div>
  );
}

function AddressEditor({ address, onChange }: { address: Address | null; onChange: (address: Address | null) => void }) {
  const { t } = useT();
  const current: Address = address ?? { street: null, postal_code: null, city: null, region: null, country: null };
  return (
    <div className="subsection">
      <div className="section-label">{t("editor.address")}</div>
      <div className="grid-2">
        {ADDRESS_FIELDS.map((def) => (
          <TextField
            key={def.key}
            id={`field-address-${def.key}`}
            label={t(def.label)}
            value={(current as unknown as Record<string, string | null>)[def.key] ?? ""}
            onChange={(text) => {
              const next = { ...current, [def.key]: text || null };
              onChange(Object.values(next).some(Boolean) ? next : null);
            }}
          />
        ))}
      </div>
    </div>
  );
}

function DocumentsEditor({ documents, onChange }: { documents: IdDocument[]; onChange: (docs: IdDocument[]) => void }) {
  const { t } = useT();
  const update = (index: number, patch: Partial<IdDocument>) =>
    onChange(documents.map((doc, i) => (i === index ? { ...doc, ...patch } : doc)));
  return (
    <div className="subsection">
      <div className="section-label">{t("editor.documents")}</div>
      {documents.map((doc, index) => (
        <div className="repeat-row three" key={index}>
          <input className="input" aria-label={t("field.doc_kind")} placeholder={t("field.doc_kind")} value={doc.kind} onChange={(event) => update(index, { kind: event.target.value })} />
          <input className="input mono" aria-label={t("field.doc_number")} placeholder={t("field.doc_number")} value={doc.number} onChange={(event) => update(index, { number: event.target.value })} />
          <input className="input" type="date" aria-label={t("field.doc_expires")} value={doc.expires ?? ""} onChange={(event) => update(index, { expires: event.target.value || null })} />
          <IconButton icon="x" label={t("common.remove")} onClick={() => onChange(documents.filter((_, i) => i !== index))} />
        </div>
      ))}
      <Button icon="plus" onClick={() => onChange([...documents, { kind: "", number: "", expires: null }])}>
        {t("editor.addDocument")}
      </Button>
    </div>
  );
}

function CustomFieldsEditor({ fields, onChange }: { fields: CustomField[]; onChange: (fields: CustomField[]) => void }) {
  const { t } = useT();
  const update = (index: number, patch: Partial<CustomField>) =>
    onChange(fields.map((field, i) => (i === index ? { ...field, ...patch } : field)));
  return (
    <div className="subsection">
      <div className="section-label">{t("editor.custom")}</div>
      {fields.map((field, index) => (
        <div className="repeat-row three" key={index}>
          <input className="input" aria-label={t("editor.fieldName")} placeholder={t("editor.fieldName")} value={field.name} onChange={(event) => update(index, { name: event.target.value })} />
          <input
            className="input mono"
            type={field.hidden ? "password" : "text"}
            aria-label={t("editor.fieldValue")}
            placeholder={t("editor.fieldValue")}
            value={field.value}
            autoComplete="off"
            onChange={(event) => update(index, { value: event.target.value })}
          />
          <label className="check">
            <input type="checkbox" checked={field.hidden} onChange={(event) => update(index, { hidden: event.target.checked })} />
            <span>{t("editor.hidden")}</span>
          </label>
          <IconButton icon="x" label={t("common.remove")} onClick={() => onChange(fields.filter((_, i) => i !== index))} />
        </div>
      ))}
      <Button icon="plus" id="add-custom-field" onClick={() => onChange([...fields, { name: "", value: "", hidden: false }])}>
        {t("editor.addField")}
      </Button>
    </div>
  );
}

function DataFields({ data, onPatch }: { data: ItemData; onPatch: (patch: Patch) => void }) {
  const { t } = useT();
  const values = data as unknown as Patch;
  return (
    <>
      {data.type === "passkey" && <p className="hint">{t("editor.passkeyNote")}</p>}
      {FIELDS[data.type].length > 0 && (
        <div className="grid-2">
          {FIELDS[data.type].map((def) => (
            <FieldInput
              key={def.key}
              def={def}
              value={values[def.key]}
              onChange={(value) => {
                if (data.type === "totp" && def.key === "secret" && typeof value === "string") {
                  const parsed = parseOtpauth(value);
                  if (parsed) return onPatch({ ...parsed });
                }
                onPatch({ [def.key]: value });
              }}
            />
          ))}
        </div>
      )}
      {data.type === "login" && <LoginTotp totp={data.totp} onChange={(totp) => onPatch({ totp })} />}
      {data.type === "recovery_codes" && <CodesEditor codes={data.codes} onChange={(codes) => onPatch({ codes })} />}
      {data.type === "identity" && (
        <>
          <AddressEditor address={data.address} onChange={(address) => onPatch({ address })} />
          <DocumentsEditor documents={data.documents} onChange={(documents) => onPatch({ documents })} />
        </>
      )}
    </>
  );
}

export function ItemEditor({
  initial,
  isNew,
  services,
  onClose,
  onSaved,
}: {
  initial: Item;
  isNew: boolean;
  services: ServiceSummary[];
  onClose: () => void;
  onSaved: (id: string) => void;
}) {
  const { t } = useT();
  const [item, setItem] = useState<Item>(initial);
  // Fields typed under another type come back if the user switches back before saving.
  const [stash, setStash] = useState<Partial<Record<ItemType, ItemData>>>({});
  const [serviceChoice, setServiceChoice] = useState(initial.service_id ?? "");
  const [serviceName, setServiceName] = useState("");
  const [serviceDomains, setServiceDomains] = useState("");
  const [tags, setTags] = useState(initial.tags.join(", "));
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmDiscard, setConfirmDiscard] = useState(false);

  const snapshot = (value: Item, choice: string, name: string, domains: string, tagText: string) =>
    JSON.stringify([value, choice, name, domains, tagText]);
  const [pristine] = useState(() =>
    snapshot(initial, initial.service_id ?? "", "", "", initial.tags.join(", ")),
  );
  const dirty = snapshot(item, serviceChoice, serviceName, serviceDomains, tags) !== pristine;

  // Closing never throws typed data away without asking.
  const requestClose = () => {
    if (confirmDiscard) return;
    if (dirty) setConfirmDiscard(true);
    else onClose();
  };

  const type = item.data.type;
  const lockedType = !isNew && initial.data.type === "passkey";

  const switchType = async (next: ItemType) => {
    if (next === type || lockedType) return;
    try {
      const restored = stash[next] ?? (await api.emptyItem(next)).data;
      setStash((current) => ({ ...current, [type]: item.data }));
      setItem((current) => ({ ...current, data: restored }));
    } catch (err) {
      setError(errorText(t, err));
    }
  };

  const patchData = (patch: Patch) =>
    setItem((current) => ({ ...current, data: { ...current.data, ...patch } as ItemData }));

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (busy) return;
    setBusy(true);
    setError(null);
    try {
      let serviceId: string | null = serviceChoice || null;
      if (serviceChoice === NEW_SERVICE) {
        if (!serviceName.trim()) {
          setError(t("err.empty_name"));
          setBusy(false);
          return;
        }
        const service = await api.emptyService(serviceName);
        service.domains = splitLines(serviceDomains).map((host) => ({ host, matching: "registrable_domain" as const }));
        serviceId = await api.saveService(service);
      }
      const saved = await api.saveItem({
        ...item,
        service_id: serviceId,
        tags: tags.split(",").map((tag) => tag.trim()).filter(Boolean),
        custom_fields: item.custom_fields.filter((field) => field.name.trim() || field.value),
        data: normalizeData(item.data),
      });
      onSaved(saved);
    } catch (err) {
      setError(errorText(t, err));
      setBusy(false);
    }
  };

  return (
    <>
    <Modal title={t(isNew ? "editor.newTitle" : "editor.editTitle")} onClose={requestClose} wide id="item-editor">
      <form className="editor" onSubmit={submit}>
        <div className="editor-body">
          <div className="section-label">{t("editor.type")}</div>
          <div className="type-grid">
            {ITEM_TYPES.map((option) => (
              <button
                key={option}
                type="button"
                data-type={option}
                className={`type-tile ${type === option ? "active" : ""}`}
                disabled={lockedType && option !== type}
                onClick={() => switchType(option)}
              >
                <Icon name={option} size={18} />
                <span>{t(`type.${option}` as Key)}</span>
              </button>
            ))}
          </div>

          <div className="grid-2">
            <div className="form-field">
              <label htmlFor="editor-service">{t("editor.service")}</label>
              <select id="editor-service" className="input" value={serviceChoice} onChange={(event) => setServiceChoice(event.target.value)}>
                <option value="">{t("editor.noService")}</option>
                {services.map((service) => (
                  <option key={service.id} value={service.id}>
                    {service.name}
                  </option>
                ))}
                <option value={NEW_SERVICE}>{t("editor.newService")}</option>
              </select>
            </div>
            <TextField
              id="editor-label"
              label={t("editor.label")}
              value={item.label}
              hint={t("editor.labelHint")}
              onChange={(label) => setItem((current) => ({ ...current, label }))}
            />
          </div>

          {serviceChoice === NEW_SERVICE && (
            <div className="grid-2 inset">
              <TextField id="editor-service-name" label={t("editor.serviceName")} value={serviceName} onChange={setServiceName} autoFocus />
              <TextField
                id="editor-service-domains"
                label={t("editor.domains")}
                value={serviceDomains}
                onChange={setServiceDomains}
                placeholder="example.com"
                multiline
                rows={2}
              />
            </div>
          )}

          <DataFields data={item.data} onPatch={patchData} />

          <CustomFieldsEditor
            fields={item.custom_fields}
            onChange={(custom_fields) => setItem((current) => ({ ...current, custom_fields }))}
          />

          <div className="grid-2">
            <div className="span-2">
              <TextField
                id="editor-notes"
                label={t("editor.notes")}
                value={item.notes}
                multiline
                rows={3}
                onChange={(notes) => setItem((current) => ({ ...current, notes }))}
              />
            </div>
            <div className="span-2">
              <TextField id="editor-tags" label={t("editor.tags")} value={tags} onChange={setTags} />
            </div>
          </div>

          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
        </div>
        <footer className="dialog-foot">
          <Button onClick={requestClose}>{t("common.cancel")}</Button>
          <Button type="submit" variant="primary" id="editor-save" disabled={busy}>
            {t("common.save")}
          </Button>
        </footer>
      </form>
    </Modal>
    {confirmDiscard && (
      <ConfirmDialog
        message={t("editor.discardText")}
        confirmLabel={t("editor.discard")}
        onCancel={() => setConfirmDiscard(false)}
        onConfirm={onClose}
      />
    )}
    </>
  );
}
