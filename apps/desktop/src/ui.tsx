import { createContext, useContext, useEffect, useId, useState } from "react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { Icon, LogoMark } from "./icons";
import { useT } from "./i18n";
import type { Key } from "./i18n";
import { RULES, checkRules } from "./rules";
import { estimateStrength } from "./strength";

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "default" | "primary" | "danger" | "ghost";
  icon?: string;
};

export function Button({
  variant = "default",
  icon,
  children,
  className,
  type = "button",
  ...rest
}: ButtonProps) {
  return (
    <button type={type} className={`btn btn-${variant} ${className ?? ""}`} {...rest}>
      {icon && <Icon name={icon} size={16} />}
      {children && <span>{children}</span>}
    </button>
  );
}

export function IconButton({
  icon,
  label,
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { icon: string; label: string }) {
  return (
    <button
      type="button"
      className={`icon-btn ${className ?? ""}`}
      title={label}
      aria-label={label}
      {...rest}
    >
      <Icon name={icon} size={16} />
    </button>
  );
}

interface TextFieldProps {
  label: string;
  value: string;
  onChange: (value: string) => void;
  id?: string;
  hint?: string;
  placeholder?: string;
  multiline?: boolean;
  mono?: boolean;
  autoFocus?: boolean;
  disabled?: boolean;
  type?: string;
  rows?: number;
}

export function TextField({
  label,
  value,
  onChange,
  id,
  hint,
  placeholder,
  multiline,
  mono,
  autoFocus,
  disabled,
  type = "text",
  rows = 4,
}: TextFieldProps) {
  const autoId = useId();
  const inputId = id ?? autoId;
  const className = `input ${mono ? "mono" : ""}`;
  return (
    <div className="form-field">
      <label htmlFor={inputId}>{label}</label>
      {multiline ? (
        <textarea
          id={inputId}
          className={className}
          value={value}
          rows={rows}
          placeholder={placeholder}
          disabled={disabled}
          spellCheck={false}
          autoFocus={autoFocus}
          onChange={(event) => onChange(event.target.value)}
        />
      ) : (
        <input
          id={inputId}
          className={className}
          type={type}
          value={value}
          placeholder={placeholder}
          disabled={disabled}
          spellCheck={false}
          autoComplete="off"
          autoFocus={autoFocus}
          onChange={(event) => onChange(event.target.value)}
        />
      )}
      {hint && <p className="hint">{hint}</p>}
    </div>
  );
}

export function SecretField({
  label,
  value,
  onChange,
  id,
  hint,
  multiline,
  mono = true,
  autoFocus,
  disabled,
  onGenerate,
}: Omit<TextFieldProps, "type" | "placeholder" | "rows"> & { onGenerate?: () => void }) {
  const { t } = useT();
  const autoId = useId();
  const inputId = id ?? autoId;
  const [shown, setShown] = useState(false);
  const generate = onGenerate && !disabled && !multiline;
  const className = `input ${mono ? "mono" : ""} ${!shown && multiline ? "concealed" : ""}`;
  return (
    <div className="form-field">
      <label htmlFor={inputId}>{label}</label>
      <div className={`input-wrap ${multiline ? "multi" : ""} ${generate ? "with-generate" : ""}`}>
        {multiline ? (
          <textarea
            id={inputId}
            className={className}
            value={value}
            rows={5}
            disabled={disabled}
            spellCheck={false}
            autoFocus={autoFocus}
            onChange={(event) => onChange(event.target.value)}
          />
        ) : (
          <input
            id={inputId}
            className={className}
            type={shown ? "text" : "password"}
            value={value}
            disabled={disabled}
            spellCheck={false}
            autoComplete="off"
            autoFocus={autoFocus}
            onChange={(event) => onChange(event.target.value)}
          />
        )}
        {generate && (
          <IconButton
            id={`${inputId}-generate`}
            className="generate"
            icon="dice"
            label={t("generator.open")}
            onClick={onGenerate}
          />
        )}
        <IconButton
          icon={shown ? "eyeOff" : "eye"}
          label={t(shown ? "detail.hide" : "detail.show")}
          onClick={() => setShown(!shown)}
        />
      </div>
      {hint && <p className="hint">{hint}</p>}
    </div>
  );
}

export function StrengthMeter({ password }: { password: string }) {
  const { t } = useT();
  const score = estimateStrength(password);
  const filled = password ? Math.max(1, score) : 0;
  return (
    <div className="strength" aria-live="polite">
      <div className="strength-bars">
        {[0, 1, 2, 3].map((index) => (
          <span key={index} className={index < filled ? "on" : ""} />
        ))}
      </div>
      <span className="strength-text">{password ? t(`strength.${score}` as Key) : ""}</span>
    </div>
  );
}

/** The rules a new master or export password has to meet, ticked off while typing. */
export function PasswordChecklist({
  password,
  minChars,
  id,
}: {
  password: string;
  minChars: number;
  id?: string;
}) {
  const { t } = useT();
  const state = checkRules(password, minChars);
  return (
    <ul className="rules" id={id} aria-label={t("rules.title")}>
      {RULES.map((rule) => (
        <li key={rule} className={state[rule] ? "met" : ""} data-rule={rule}>
          <Icon name={state[rule] ? "check" : "circle"} size={14} />
          <span>{t(`rules.${rule}` as Key, { n: minChars })}</span>
        </li>
      ))}
    </ul>
  );
}

export function Modal({
  title,
  onClose,
  children,
  wide,
  id,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  wide?: boolean;
  id?: string;
}) {
  const { t } = useT();
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="overlay">
      <div className={`dialog ${wide ? "wide" : ""}`} role="dialog" aria-modal="true" aria-label={title} id={id}>
        <header className="dialog-head">
          <h2>{title}</h2>
          <IconButton icon="x" label={t("common.close")} onClick={onClose} />
        </header>
        {children}
      </div>
    </div>
  );
}

export function ConfirmDialog({
  message,
  confirmLabel,
  onConfirm,
  onCancel,
}: {
  message: string;
  confirmLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
}) {
  const { t } = useT();
  return (
    <Modal title={confirmLabel} onClose={onCancel} id="confirm">
      <p className="dialog-text">{message}</p>
      <footer className="dialog-foot">
        <Button onClick={onCancel}>{t("common.cancel")}</Button>
        <Button variant="danger" id="confirm-yes" onClick={onConfirm}>
          {confirmLabel}
        </Button>
      </footer>
    </Modal>
  );
}

export function Brand({ compact }: { compact?: boolean }) {
  return (
    <div className={`brand ${compact ? "compact" : ""}`}>
      <LogoMark size={compact ? 26 : 34} />
      <span className="brand-name">KRYPT</span>
    </div>
  );
}

export const ToastContext = createContext<(message: string) => void>(() => {});

export function useToast() {
  return useContext(ToastContext);
}
