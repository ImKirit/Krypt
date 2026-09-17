import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { ExportDialog } from "../components/ExportDialog";
import { HelloOffer } from "../components/HelloOffer";
import { ImportDialog } from "../components/ImportDialog";
import { ItemDetail } from "../components/ItemDetail";
import { ItemEditor } from "../components/ItemEditor";
import { ServiceEditor } from "../components/ServiceEditor";
import { SettingsDialog } from "../components/SettingsDialog";
import { errorText, useT } from "../i18n";
import type { Key } from "../i18n";
import { Icon, LogoMark } from "../icons";
import type { Item, ItemSummary, Service, ServiceSummary, Status } from "../types";
import { Brand, Button, ConfirmDialog, IconButton, useToast } from "../ui";

type View =
  | { kind: "all" }
  | { kind: "favorites" }
  | { kind: "trash" }
  | { kind: "service"; id: string };

function NavItem({
  icon,
  label,
  count,
  active,
  onClick,
  id,
}: {
  icon: string;
  label: string;
  count?: number;
  active?: boolean;
  onClick: () => void;
  id?: string;
}) {
  return (
    <button type="button" className={`nav-item ${active ? "active" : ""}`} onClick={onClick} id={id}>
      <Icon name={icon} size={16} />
      <span className="nav-text">{label}</span>
      {count !== undefined && <span className="nav-count">{count}</span>}
    </button>
  );
}

export function Main({
  status,
  onStatus,
  onLock,
}: {
  status: Status;
  onStatus: (status: Status) => void;
  onLock: () => void;
}) {
  const { t } = useT();
  const toast = useToast();
  const [view, setView] = useState<View>({ kind: "all" });
  const [services, setServices] = useState<ServiceSummary[]>([]);
  const [items, setItems] = useState<ItemSummary[]>([]);
  const [trash, setTrash] = useState<ItemSummary[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [editor, setEditor] = useState<{ item: Item; isNew: boolean } | null>(null);
  const [serviceEdit, setServiceEdit] = useState<Service | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [importOpen, setImportOpen] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [confirmEmpty, setConfirmEmpty] = useState(false);
  const [offerClosed, setOfferClosed] = useState(false);
  const [version, setVersion] = useState(0);

  const reload = useCallback(async () => {
    const [nextServices, nextItems, nextTrash] = await Promise.all([
      api.listServices(),
      api.listItems(),
      api.listTrash(),
    ]);
    setServices(nextServices);
    setItems(nextItems);
    setTrash(nextTrash);
    setVersion((v) => v + 1);
  }, []);

  const report = useCallback((error: unknown) => toast(errorText(t, error)), [toast, t]);

  useEffect(() => {
    reload().catch(report);
  }, [reload, report]);

  const go = (next: View) => {
    setView(next);
    setSelected(null);
  };

  const rows = useMemo(() => {
    let list = view.kind === "trash" ? trash : items;
    if (view.kind === "favorites") list = list.filter((row) => row.favorite);
    if (view.kind === "service") list = list.filter((row) => row.service_id === view.id);
    const needle = query.trim().toLowerCase();
    if (needle) {
      list = list.filter((row) =>
        [row.label, row.service_name, row.subtitle, t(`type.${row.item_type}` as Key), ...row.tags]
          .filter(Boolean)
          .some((value) => String(value).toLowerCase().includes(needle)),
      );
    }
    const title = (row: ItemSummary) => (row.service_name ?? row.label).toLowerCase();
    return [...list].sort(
      (a, b) => title(a).localeCompare(title(b)) || a.label.localeCompare(b.label),
    );
  }, [view, items, trash, query, t]);

  const current = selected ? [...items, ...trash].find((row) => row.id === selected) ?? null : null;

  const afterChange = async (next?: string | null) => {
    try {
      await reload();
      if (next !== undefined) setSelected(next);
    } catch (error) {
      report(error);
    }
  };

  const openNew = async () => {
    try {
      const item = await api.emptyItem("login");
      if (view.kind === "service") item.service_id = view.id;
      setEditor({ item, isNew: true });
    } catch (error) {
      report(error);
    }
  };

  const openEdit = async (id: string) => {
    try {
      setEditor({ item: await api.getItemForEdit(id), isNew: false });
    } catch (error) {
      report(error);
    }
  };

  const openServiceEdit = async (id: string) => {
    try {
      setServiceEdit(await api.getService(id));
    } catch (error) {
      report(error);
    }
  };

  const otherDialogOpen =
    editor !== null ||
    serviceEdit !== null ||
    settingsOpen ||
    importOpen ||
    exportOpen ||
    confirmEmpty;
  const offerOpen = status.hello.offer && !offerClosed && !otherDialogOpen;
  const dialogOpen = otherDialogOpen || offerOpen;

  // Ctrl+F search, Ctrl+N new entry, Ctrl+L lock. The web view's own meaning of these keys
  // (find bar, new window) is suppressed.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (!event.ctrlKey || event.altKey || event.metaKey || event.shiftKey) return;
      const key = event.key.toLowerCase();
      if (key !== "f" && key !== "n" && key !== "l") return;
      event.preventDefault();
      if (dialogOpen) return;
      if (key === "f") document.getElementById("search")?.focus();
      if (key === "n" && view.kind !== "trash") void openNew();
      if (key === "l") onLock();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  });

  const serviceName =
    view.kind === "service" ? services.find((service) => service.id === view.id)?.name : undefined;
  const title =
    view.kind === "all"
      ? t("nav.all")
      : view.kind === "favorites"
        ? t("nav.favorites")
        : view.kind === "trash"
          ? t("nav.trash")
          : (serviceName ?? "");

  return (
    <div className={`app ${status.backup_failed ? "with-banner" : ""}`}>
      {status.backup_failed && <div className="banner">{t("banner.backup")}</div>}
      <aside className="sidebar">
        <Brand compact />
        <nav className="nav">
          <NavItem
            id="nav-all"
            icon="layers"
            label={t("nav.all")}
            count={items.length}
            active={view.kind === "all"}
            onClick={() => go({ kind: "all" })}
          />
          <NavItem
            id="nav-favorites"
            icon="star"
            label={t("nav.favorites")}
            count={items.filter((row) => row.favorite).length}
            active={view.kind === "favorites"}
            onClick={() => go({ kind: "favorites" })}
          />
        </nav>
        <div className="nav-label">{t("nav.services")}</div>
        <nav className="nav nav-services" id="nav-services">
          {services.map((service) => (
            <NavItem
              key={service.id}
              icon="globe"
              label={service.name}
              count={service.item_count}
              active={view.kind === "service" && view.id === service.id}
              onClick={() => go({ kind: "service", id: service.id })}
            />
          ))}
          {services.length === 0 && <p className="nav-empty">{t("nav.noServices")}</p>}
        </nav>
        <nav className="nav nav-foot">
          <NavItem
            id="nav-trash"
            icon="trash"
            label={t("nav.trash")}
            count={trash.length}
            active={view.kind === "trash"}
            onClick={() => go({ kind: "trash" })}
          />
          <NavItem id="nav-settings" icon="settings" label={t("nav.settings")} onClick={() => setSettingsOpen(true)} />
          <NavItem id="nav-lock" icon="lock" label={t("nav.lock")} onClick={onLock} />
        </nav>
      </aside>

      <section className="list-pane">
        <div className="list-head">
          <label className="search">
            <Icon name="search" size={16} />
            <input
              id="search"
              title="Ctrl+F"
              value={query}
              placeholder={t("list.search")}
              spellCheck={false}
              autoComplete="off"
              onChange={(event) => setQuery(event.target.value)}
            />
          </label>
          {view.kind !== "trash" && (
            <Button variant="primary" icon="plus" id="new-item" title="Ctrl+N" onClick={openNew}>
              {t("list.new")}
            </Button>
          )}
        </div>
        <div className="list-title">
          <h3>{title}</h3>
          {view.kind === "service" && (
            <IconButton
              id="edit-service"
              icon="edit"
              label={t("list.editService")}
              onClick={() => openServiceEdit(view.id)}
            />
          )}
          {view.kind === "trash" && trash.length > 0 && (
            <Button variant="ghost" icon="trash" id="empty-trash" onClick={() => setConfirmEmpty(true)}>
              {t("list.emptyTrash")}
            </Button>
          )}
        </div>
        <ul className="rows" id="item-list">
          {rows.map((row) => (
            <li key={row.id}>
              <button
                type="button"
                className={`row ${row.id === selected ? "active" : ""}`}
                data-id={row.id}
                onClick={() => setSelected(row.id)}
              >
                <span className="row-icon">
                  <Icon name={row.item_type} />
                </span>
                <span className="row-text">
                  <span className="row-title">
                    <span className="row-name">
                      {row.service_name ?? (row.label || t(`type.${row.item_type}` as Key))}
                    </span>
                    {row.service_name && row.label && <span className="chip">{row.label}</span>}
                  </span>
                  <span className="row-sub">
                    {row.subtitle ?? t(`type.${row.item_type}` as Key)}
                  </span>
                </span>
                {row.favorite && (
                  <span className="row-star">
                    <Icon name="star" size={14} />
                  </span>
                )}
              </button>
            </li>
          ))}
        </ul>
        {rows.length === 0 && (
          <div className="list-empty">
            {view.kind === "trash" ? (
              <p>{t("list.trashEmpty")}</p>
            ) : query.trim() ? (
              <p>{t("list.noMatch")}</p>
            ) : (
              <>
                <p className="strong">{t("list.empty")}</p>
                <p>{t("list.emptyHint")}</p>
                {items.length === 0 && (
                  <Button
                    icon="import"
                    id="empty-import"
                    className="list-empty-action"
                    onClick={() => setImportOpen(true)}
                  >
                    {t("import.fromOther")}
                  </Button>
                )}
              </>
            )}
          </div>
        )}
      </section>

      <section className="detail-pane">
        {current ? (
          <ItemDetail
            key={`${current.id}-${version}`}
            id={current.id}
            serviceName={current.service_name}
            inTrash={current.deleted_at !== null}
            onEdit={openEdit}
            onChanged={afterChange}
          />
        ) : (
          <div className="detail-empty">
            <LogoMark size={44} />
            <p>{t("detail.none")}</p>
          </div>
        )}
      </section>

      {editor && (
        <ItemEditor
          initial={editor.item}
          isNew={editor.isNew}
          services={services}
          onClose={() => setEditor(null)}
          onSaved={async (id) => {
            setEditor(null);
            if (view.kind === "trash") setView({ kind: "all" });
            await afterChange(id);
          }}
        />
      )}
      {serviceEdit && (
        <ServiceEditor
          service={serviceEdit}
          onClose={() => setServiceEdit(null)}
          onSaved={async () => {
            setServiceEdit(null);
            await afterChange();
          }}
          onDeleted={async () => {
            setServiceEdit(null);
            go({ kind: "all" });
            await afterChange();
          }}
        />
      )}
      {settingsOpen && (
        <SettingsDialog
          status={status}
          onStatus={onStatus}
          onClose={() => setSettingsOpen(false)}
          onImport={() => {
            setSettingsOpen(false);
            setImportOpen(true);
          }}
          onExport={() => {
            setSettingsOpen(false);
            setExportOpen(true);
          }}
        />
      )}
      {importOpen && (
        <ImportDialog
          onClose={() => setImportOpen(false)}
          onImported={async (result) => {
            setImportOpen(false);
            const done = t("import.done", { n: result.items });
            toast(result.source_deleted ? `${done} ${t("import.deleted")}` : done);
            go({ kind: "all" });
            await afterChange();
          }}
        />
      )}
      {exportOpen && (
        <ExportDialog minChars={status.min_password_chars} onClose={() => setExportOpen(false)} />
      )}
      {offerOpen && (
        <HelloOffer
          reminderDays={status.settings.password_reminder_days}
          onDone={async (enabled) => {
            setOfferClosed(true);
            if (enabled) toast(t("hello.enabled"));
            try {
              onStatus(await api.status());
            } catch (error) {
              report(error);
            }
          }}
        />
      )}
      {confirmEmpty && (
        <ConfirmDialog
          message={t("trash.confirm")}
          confirmLabel={t("list.emptyTrash")}
          onCancel={() => setConfirmEmpty(false)}
          onConfirm={async () => {
            setConfirmEmpty(false);
            try {
              await api.emptyTrash();
              setSelected(null);
              await reload();
            } catch (error) {
              report(error);
            }
          }}
        />
      )}
    </div>
  );
}
