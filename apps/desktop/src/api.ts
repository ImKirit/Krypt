import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import type {
  Item,
  ItemSummary,
  ItemType,
  ItemView,
  Service,
  ServiceSummary,
  Settings,
  Status,
  TotpNow,
} from "./types";

export const api = {
  status: () => invoke<Status>("status"),
  createVault: (password: string) => invoke<string>("create_vault", { password }),
  unlock: (password: string) => invoke<void>("unlock", { password }),
  recover: (recoveryKey: string, newPassword: string) =>
    invoke<void>("recover", { recoveryKey, newPassword }),
  lock: () => invoke<void>("lock"),
  touch: () => invoke<void>("touch"),
  changePassword: (current: string, newPassword: string) =>
    invoke<void>("change_password", { current, newPassword }),
  newRecoveryKey: () => invoke<string>("new_recovery_key"),

  listServices: () => invoke<ServiceSummary[]>("list_services"),
  getService: (id: string) => invoke<Service>("get_service", { id }),
  emptyService: (name: string) => invoke<Service>("empty_service", { name }),
  saveService: (service: Service) => invoke<string>("save_service", { service }),
  trashService: (id: string) => invoke<void>("trash_service", { id }),

  listItems: () => invoke<ItemSummary[]>("list_items"),
  listTrash: () => invoke<ItemSummary[]>("list_trash"),
  getItem: (id: string) => invoke<ItemView>("get_item", { id }),
  getItemForEdit: (id: string) => invoke<Item>("get_item_for_edit", { id }),
  emptyItem: (itemType: ItemType) => invoke<Item>("empty_item", { itemType }),
  saveItem: (item: Item) => invoke<string>("save_item", { item }),
  trashItem: (id: string) => invoke<void>("trash_item", { id }),
  restoreItem: (id: string) => invoke<void>("restore_item", { id }),
  purgeItem: (id: string) => invoke<void>("purge_item", { id }),
  emptyTrash: () => invoke<number>("empty_trash"),

  revealField: (id: string, pointer: string) =>
    invoke<string>("reveal_field", { id, pointer }),
  /** Resolves to the seconds until the clipboard is cleared. */
  copyField: (id: string, pointer: string) => invoke<number>("copy_field", { id, pointer }),
  copyText: (text: string) => invoke<number>("copy_text", { text }),
  totpNow: (id: string) => invoke<TotpNow>("totp_now", { id }),

  saveSettings: (settings: Settings) => invoke<Settings>("save_settings", { settings }),

  onLocked: (handler: () => void) => listen("vault-locked", handler),
};
