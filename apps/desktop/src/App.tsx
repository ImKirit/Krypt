import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api } from "./api";
import { I18n, errorText, makeTranslate, systemLang } from "./i18n";
import type { Lang } from "./i18n";
import { Problem, RecoveryKeyScreen, Setup, Unlock } from "./screens/Gate";
import { Main } from "./screens/Main";
import type { Status } from "./types";
import { ToastContext } from "./ui";

const ACTIVITY_INTERVAL_MS = 20_000;

export function App() {
  const [status, setStatus] = useState<Status | null>(null);
  const [recoveryKey, setRecoveryKey] = useState<string | null>(null);
  const [fatal, setFatal] = useState<string | null>(null);
  const [toast, setToast] = useState<string | null>(null);
  const toastTimer = useRef<number | undefined>(undefined);

  const lang: Lang = status?.settings.language ?? systemLang();
  const t = useMemo(() => makeTranslate(lang), [lang]);

  const refresh = useCallback(async () => {
    try {
      setStatus(await api.status());
    } catch (error) {
      setFatal(errorText(makeTranslate(systemLang()), error));
    }
  }, []);

  const showToast = useCallback((message: string) => {
    setToast(message);
    window.clearTimeout(toastTimer.current);
    toastTimer.current = window.setTimeout(() => setToast(null), 3200);
  }, []);

  useEffect(() => {
    void refresh();
    const unlisten = api.onLocked(() => void refresh());
    return () => {
      void unlisten.then((stop) => stop());
    };
  }, [refresh]);

  // Auto-lock counts real use of the window, not the timers that update one-time codes.
  useEffect(() => {
    let last = 0;
    const onActivity = () => {
      const now = Date.now();
      if (now - last > ACTIVITY_INTERVAL_MS) {
        last = now;
        api.touch().catch(() => {});
      }
    };
    const events = ["pointerdown", "keydown", "pointermove", "wheel"] as const;
    events.forEach((name) => window.addEventListener(name, onActivity, { passive: true }));
    return () => events.forEach((name) => window.removeEventListener(name, onActivity));
  }, []);

  useEffect(() => {
    document.documentElement.lang = lang;
  }, [lang]);

  let screen;
  if (fatal) {
    screen = <Problem message={fatal} />;
  } else if (!status) {
    screen = <div className="gate" />;
  } else if (status.problem) {
    screen = <Problem message={errorText(t, status.problem)} />;
  } else if (recoveryKey) {
    screen = (
      <RecoveryKeyScreen
        value={recoveryKey}
        onDone={() => {
          setRecoveryKey(null);
          void refresh();
        }}
      />
    );
  } else if (!status.vault_exists) {
    screen = <Setup minChars={status.min_password_chars} onCreated={setRecoveryKey} />;
  } else if (!status.unlocked) {
    screen = <Unlock minChars={status.min_password_chars} onUnlocked={() => void refresh()} />;
  } else {
    screen = (
      <Main
        status={status}
        onStatus={setStatus}
        onLock={async () => {
          await api.lock();
          await refresh();
        }}
      />
    );
  }

  return (
    <I18n.Provider value={{ t, lang }}>
      <ToastContext.Provider value={showToast}>
        {screen}
        {toast && (
          <div className="toast" role="status" id="toast">
            {toast}
          </div>
        )}
      </ToastContext.Provider>
    </I18n.Provider>
  );
}
