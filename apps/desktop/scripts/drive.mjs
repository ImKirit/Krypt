// Drives a debug build of Krypt through the DevTools protocol of WebView2: creates a vault,
// adds entries, checks copying, search, trash, the generator, export, import and locking, and
// saves screenshots to scripts/out. Uses a throwaway data folder, so a real vault is never
// touched.
//
//   npm run tauri build -- --debug --no-bundle
//   node scripts/drive.mjs <path to krypt.exe> [--auto-lock] [--theme=light|dark]

import { spawn, spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const exe = process.argv[2];
const checkAutoLock = process.argv.includes("--auto-lock");
const theme = process.argv.find((arg) => arg.startsWith("--theme="))?.slice("--theme=".length);
if (!exe) {
  console.error("usage: node scripts/drive.mjs <path to krypt.exe> [--auto-lock]");
  process.exit(2);
}

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "out");
mkdirSync(outDir, { recursive: true });
const dataDir = mkdtempSync(join(tmpdir(), "krypt-drive-"));
const exportPath = join(dataDir, "export.json");
const importPath = join(dataDir, "Chrome Passwords.csv");
const port = 9333;
const PASSWORD = "Correct-horse-battery-7";
const EXPORT_PASSWORD = "Export-pass-2026";
const results = [];

const app = spawn(exe, [], {
  env: {
    ...process.env,
    KRYPT_DATA_DIR: dataDir,
    // Native file dialogs cannot be clicked through; debug builds take these paths instead.
    KRYPT_TEST_SAVE_PATH: exportPath,
    KRYPT_TEST_OPEN_PATH: importPath,
    // Keep going if the screen of this machine locks during the run.
    KRYPT_IGNORE_SESSION_LOCK: "1",
    WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS: `--remote-debugging-port=${port}`,
  },
  stdio: "inherit",
});

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function check(name, ok, detail = "") {
  results.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "ok  " : "FAIL"} ${name}${detail ? ` (${detail})` : ""}`);
}

async function findPage() {
  for (let attempt = 0; attempt < 150; attempt++) {
    try {
      const targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json();
      const page = targets.find((target) => target.type === "page");
      if (page) return page;
    } catch {
      // not listening yet
    }
    await sleep(200);
  }
  throw new Error("WebView2 did not open a debugging target");
}

function connect(url) {
  return new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    const pending = new Map();
    let nextId = 0;
    socket.onmessage = (event) => {
      const message = JSON.parse(event.data);
      const waiter = message.id && pending.get(message.id);
      if (!waiter) return;
      pending.delete(message.id);
      if (message.error) waiter.reject(new Error(message.error.message));
      else waiter.resolve(message.result);
    };
    socket.onerror = reject;
    socket.onopen = () =>
      resolve({
        send: (method, params = {}) =>
          new Promise((ok, fail) => {
            nextId += 1;
            pending.set(nextId, { resolve: ok, reject: fail });
            socket.send(JSON.stringify({ id: nextId, method, params }));
          }),
        close: () => socket.close(),
      });
  });
}

let cdp;

async function js(expression) {
  const reply = await cdp.send("Runtime.evaluate", {
    expression,
    awaitPromise: true,
    returnByValue: true,
  });
  if (reply.exceptionDetails) {
    throw new Error(reply.exceptionDetails.exception?.description ?? reply.exceptionDetails.text);
  }
  return reply.result.value;
}

const q = (selector) => JSON.stringify(selector);

async function waitFor(selector, timeout = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (await js(`!!document.querySelector(${q(selector)})`)) return;
    await sleep(80);
  }
  throw new Error(`timed out waiting for ${selector}`);
}

async function waitGone(selector, timeout = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeout) {
    if (!(await js(`!!document.querySelector(${q(selector)})`))) return;
    await sleep(80);
  }
  throw new Error(`timed out waiting for ${selector} to close`);
}

/** Re-evaluates `expression` until `ok` accepts its value; returns the last value either way. */
async function waitUntil(expression, ok, timeout = 10000) {
  const start = Date.now();
  let value;
  do {
    value = await js(expression);
    if (ok(value)) return value;
    await sleep(100);
  } while (Date.now() - start < timeout);
  return value;
}

async function fill(selector, value) {
  await waitFor(selector);
  await js(`(() => {
    const el = document.querySelector(${q(selector)});
    const proto = el instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype
      : el instanceof HTMLSelectElement ? HTMLSelectElement.prototype : HTMLInputElement.prototype;
    Object.getOwnPropertyDescriptor(proto, "value").set.call(el, ${JSON.stringify(value)});
    el.dispatchEvent(new Event(el instanceof HTMLSelectElement ? "change" : "input", { bubbles: true }));
  })()`);
  await sleep(60);
}

async function click(selector) {
  await waitFor(selector);
  await js(`document.querySelector(${q(selector)}).click()`);
  await sleep(120);
}

const text = (selector) => js(`document.querySelector(${q(selector)})?.textContent ?? ""`);
const rowCount = () => js(`document.querySelectorAll("#item-list .row").length`);

async function clickRow(...texts) {
  await js(`[...document.querySelectorAll("#item-list .row")]
    .find((row) => ${JSON.stringify(texts)}.every((text) => row.textContent.includes(text)))
    .click()`);
  await waitFor("#item-detail");
  await sleep(250);
}

async function shot(name) {
  await sleep(450);
  const { data } = await cdp.send("Page.captureScreenshot", { format: "png" });
  writeFileSync(join(outDir, `${name}.png`), Buffer.from(data, "base64"));
  console.log(`     saved ${name}.png`);
}

function clipboard() {
  const reply = spawnSync("powershell", ["-NoProfile", "-Command", "Get-Clipboard -Raw"], {
    encoding: "utf8",
  });
  return (reply.stdout ?? "").replace(/\r?\n$/, "");
}

async function addEntry({ type, service, newService, label, fields = {}, totp, codes }) {
  await click("#new-item");
  await waitFor("#item-editor");
  await click(`#item-editor [data-type="${type}"]`);
  await sleep(250);
  if (newService) {
    await fill("#editor-service", "__new__");
    await fill("#editor-service-name", newService.name);
    await fill("#editor-service-domains", newService.domains);
  } else if (service) {
    const value = await js(`[...document.querySelectorAll("#editor-service option")]
      .find((option) => option.textContent === ${JSON.stringify(service)})?.value`);
    await fill("#editor-service", value);
  }
  if (label) await fill("#editor-label", label);
  for (const [selector, value] of Object.entries(fields)) await fill(selector, value);
  if (totp) {
    await click("#add-totp");
    await fill("#field-totp-secret", totp);
  }
  if (codes) {
    await fill("#codes-paste", codes);
    await click("#codes-add");
  }
  await click("#editor-save");
  await waitGone("#item-editor");
}

async function openFromSettings(button, dialog) {
  await click("#nav-settings");
  await click(button);
  await waitGone("#settings");
  await waitFor(dialog);
}

try {
  cdp = await connect((await findPage()).webSocketDebuggerUrl);
  await cdp.send("Runtime.enable");
  if (theme) {
    await cdp.send("Emulation.setEmulatedMedia", {
      features: [{ name: "prefers-color-scheme", value: theme }],
    });
  }

  // Setup
  await waitFor("#setup");
  check("a fresh start shows the setup", true);
  await fill("#setup-password", "short");
  await fill("#setup-confirm", "short");
  check(
    "a short password cannot create a vault",
    await js(`document.querySelector("#setup-create").disabled`),
  );
  await fill("#setup-password", "longpassword");
  await fill("#setup-confirm", "longpassword");
  const metForLong = await js(`document.querySelectorAll("#setup-rules li.met").length`);
  check(
    "a long password without the other rules cannot create a vault either",
    metForLong === 2 && (await js(`document.querySelector("#setup-create").disabled`)),
    `${metForLong} of 5 rules met`,
  );
  await fill("#setup-password", PASSWORD);
  await fill("#setup-confirm", PASSWORD);
  check(
    "the checklist ticks every rule for a good password",
    (await js(`document.querySelectorAll("#setup-rules li.met").length`)) === 5,
  );
  await shot("tour-1-setup");
  await click("#setup-create");
  await waitFor("#recovery-screen", 30000);
  const recoveryKey = await js(
    `[...document.querySelectorAll("#recovery-key-value span")].map((s) => s.textContent).join("-")`,
  );
  check("the recovery key has eight groups", recoveryKey.split("-").length === 8, recoveryKey.length + " chars");
  await shot("tour-2-recovery-key");
  check("continuing needs the checkbox", await js(`document.querySelector("#recovery-done").disabled`));
  await click("#recovery-saved");
  await click("#recovery-done");
  await waitFor("#new-item");
  check("an empty vault offers to import", await js(`!!document.querySelector("#empty-import")`));

  // English screenshots, short clipboard timer for the copy check
  await click("#nav-settings");
  await fill("#settings-language", "en");
  await fill("#settings-clipboard", "10");
  await click("#settings .dialog-head .icon-btn");
  await waitGone("#settings");

  // Entries
  await addEntry({
    type: "login",
    newService: { name: "Anthropic", domains: "https://console.anthropic.com/settings\nanthropic.com" },
    label: "Personal",
    fields: { "#field-email": "you@example.com", "#field-password": "hunter2-correct-horse" },
    totp: "otpauth://totp/Anthropic:you@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Anthropic",
  });
  await addEntry({
    type: "api_key",
    service: "Anthropic",
    label: "Production",
    fields: { "#field-key": "sk-ant-api03-example-production-key", "#field-key_id": "key_01_production" },
  });
  await addEntry({
    type: "api_key",
    service: "Anthropic",
    label: "Staging",
    fields: { "#field-key": "sk-ant-api03-example-staging-key", "#field-key_id": "key_02_staging" },
  });
  await addEntry({
    type: "api_key",
    newService: { name: "Groq", domains: "console.groq.com" },
    label: "Personal",
    fields: { "#field-key": "gsk_example_personal_key" },
  });
  await addEntry({ type: "api_key", service: "Groq", label: "Test", fields: { "#field-key": "gsk_example_test_key" } });
  await addEntry({
    type: "login",
    newService: { name: "GitHub", domains: "github.com" },
    label: "Personal",
    fields: { "#field-username": "octo-example", "#field-password": "a-long-github-password" },
  });
  await addEntry({
    type: "recovery_codes",
    service: "GitHub",
    label: "Personal",
    codes: "3f9a-21bc\n77de-0c41\n9b12-e8f0\n5c3d-aa07",
  });
  await addEntry({
    type: "ssh_key",
    label: "Laptop",
    fields: { "#field-comment": "laptop@home", "#field-private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nexample\n-----END OPENSSH PRIVATE KEY-----" },
  });

  const listed = await rowCount();
  check("eight entries are listed", listed === 8, `${listed} rows`);
  const services = await js(`[...document.querySelectorAll("#nav-services .nav-item")].map((b) => b.textContent)`);
  check("three services with counts", services.join("|") === "Anthropic3|GitHub2|Groq2", services.join("|"));

  // The account: masked, one-time code, reveal, copy
  await clickRow("Anthropic", "Personal", "you@example.com");
  await waitFor("#totp");
  const code = await js(`document.querySelector("#totp .totp-code").textContent.replace(/\\s/g, "")`);
  check("the account shows a six digit code", /^\d{6}$/.test(code), code);
  const html = await js(`document.querySelector("#item-detail").innerHTML`);
  check("the password is not in the page before it is revealed", !html.includes("hunter2-correct-horse"));
  await shot("main-account");

  const passwordRow = `[...document.querySelectorAll("#item-detail .field-row")].find((row) => row.textContent.startsWith("Password"))`;
  await js(`${passwordRow}.querySelector('[aria-label="Show"]').click()`);
  await sleep(300);
  check(
    "revealing shows the password",
    await js(`${passwordRow}.textContent.includes("hunter2-correct-horse")`),
  );
  await js(`${passwordRow}.querySelector('[aria-label="Copy"]').click()`);
  await waitFor("#toast");
  await sleep(300);
  check("copying puts the password on the clipboard", clipboard() === "hunter2-correct-horse");

  // A new password keeps the old one in the history
  await click("#edit-item");
  await waitFor("#item-editor");
  await fill("#field-password", "hunter2-new-password");
  await click("#editor-save");
  await waitGone("#item-editor");
  await waitFor("#password-history");
  await js(`document.querySelector("#password-history summary").click()`);
  const historyRow = `document.querySelector("#password-history .field-row")`;
  await js(`${historyRow}.querySelector('[aria-label="Show"]').click()`);
  await sleep(300);
  check(
    "the replaced password is kept in the history",
    await js(`${historyRow}.textContent.includes("hunter2-correct-horse")`),
  );

  // Service view and search
  await js(`[...document.querySelectorAll("#nav-services .nav-item")].find((b) => b.textContent.startsWith("Anthropic")).click()`);
  await sleep(300);
  await clickRow("Production");
  await shot("main-service");
  await click("#nav-all");
  await fill("#search", "groq");
  const found = await rowCount();
  check("search finds the two Groq keys", found === 2, `${found} rows`);
  await fill("#search", "");

  // Keyboard
  const press = (key) =>
    js(`window.dispatchEvent(new KeyboardEvent("keydown", { key: "${key}", ctrlKey: true, cancelable: true }))`);
  await js(`document.activeElement?.blur()`);
  await press("f");
  check("Ctrl+F focuses the search", await js(`document.activeElement?.id === "search"`));
  await press("n");
  await waitFor("#item-editor");
  check("Ctrl+N opens a new entry", true);
  await click("#item-editor .dialog-head .icon-btn");
  await sleep(300);
  check("an untouched entry closes without asking", !(await js(`!!document.querySelector("#confirm")`)));
  await waitGone("#item-editor");

  // Editor
  await click("#new-item");
  await click('#item-editor [data-type="api_key"]');
  await sleep(300);
  await shot("tour-3-editor");
  await click("#item-editor .dialog-head .icon-btn");
  await waitFor("#confirm");
  check("closing a changed entry asks before discarding", true);
  await click("#confirm-yes");
  await waitGone("#item-editor");

  // Generator. Its settings survive between runs in the web view's storage, so set them first.
  await click("#new-item");
  await waitFor("#item-editor");
  await click("#field-password-generate");
  await waitFor("#generator");
  await click("#generator-kind-password");
  await fill("#generator-length", "20");
  const generatedPassword = await waitUntil(
    `document.querySelector("#generator-value")?.textContent ?? ""`,
    (value) => value.length === 20,
  );
  check("the generator makes a password of the chosen length", generatedPassword.length === 20, `${generatedPassword.length} chars`);
  await click("#generator-kind-passphrase");
  const phrase = await waitUntil(
    `document.querySelector("#generator-value")?.textContent ?? ""`,
    (value) => value !== generatedPassword && /^[A-Z]/.test(value) && /\d/.test(value),
  );
  check("the generator switches to a passphrase", /^[A-Z]/.test(phrase) && /\d/.test(phrase), phrase.replace(/[a-z]/g, "x"));
  await js(`document.querySelector("#generator").scrollIntoView({ block: "end" })`);
  await shot("generator");
  await click("#generator-use");
  await waitGone("#generator");
  check(
    "using a generated passphrase fills the password field",
    (await js(`document.querySelector("#field-password").value`)) === phrase,
  );
  await click("#item-editor .dialog-head .icon-btn");
  await waitFor("#confirm");
  await click("#confirm-yes");
  await waitGone("#item-editor");

  // Trash
  await clickRow("Laptop", "laptop@home");
  await click("#trash-item");
  await sleep(300);
  check("trashing removes the entry from the list", (await rowCount()) === 7);
  await click("#nav-trash");
  await clickRow("laptop@home");
  await click("#restore-item");
  await sleep(300);
  await click("#nav-all");
  check("restoring brings it back", (await rowCount()) === 8);

  // Settings screenshot
  await click("#nav-settings");
  check(
    "settings offer locking together with Windows, on by default",
    await js(`document.querySelector("#settings-lock-with-windows")?.checked === true`),
  );
  await shot("main-settings");
  await click("#settings .dialog-head .icon-btn");
  await waitGone("#settings");

  // The clipboard clears itself
  await sleep(11000);
  check("the clipboard is cleared after the timer", clipboard() === "");

  // Lock and unlock
  await press("l");
  await waitFor("#unlock");
  check("Ctrl+L locks the vault", true);
  await fill("#unlock-password", "not the password");
  await click("#unlock-button");
  await waitFor("#unlock .error");
  check("a wrong password is refused", true);
  await shot("tour-4-unlock");
  await fill("#unlock-password", PASSWORD);
  await click("#unlock-button");
  await waitFor("#new-item", 30000);
  const rowsAfterUnlock = await waitUntil(`document.querySelectorAll("#item-list .row").length`, (count) => count === 8);
  check("the right password opens the vault again", rowsAfterUnlock === 8, `${rowsAfterUnlock} rows`);
  if (rowsAfterUnlock !== 8) await shot("failure-after-unlock");

  // Encrypted export
  await openFromSettings("#settings-export", "#export");
  await fill("#export-password", "weakpassword");
  await fill("#export-confirm", "weakpassword");
  check("a weak export password is refused", await js(`document.querySelector("#export-save").disabled`));
  await fill("#export-password", EXPORT_PASSWORD);
  await fill("#export-confirm", EXPORT_PASSWORD);
  await shot("export");
  await click("#export-save");
  await waitGone("#export", 30000);
  const exported = existsSync(exportPath) ? readFileSync(exportPath, "utf8") : "";
  check(
    "the export is written and nothing in it is readable",
    exported.includes('"krypt-export"') && !exported.includes("hunter2") && !exported.includes("Anthropic"),
    `${exported.length} bytes`,
  );

  // Import of a browser CSV: one duplicate, one entry for an existing service, one new service
  writeFileSync(
    importPath,
    [
      "name,url,username,password,note",
      "github.com,https://github.com/,octo-example,a-long-github-password,",
      "Example,https://login.example.org/,demo,demo-password,",
      "console.anthropic.com,https://console.anthropic.com/,work@example.com,another-anthropic-password,",
    ].join("\n") + "\n",
  );
  // The export's toast would end up in the screenshot.
  await waitGone("#toast", 8000);
  await openFromSettings("#settings-import", "#import");
  await click("#import-pick");
  await waitFor("#import-preview", 30000);
  const total = await text("#import-total");
  const duplicates = await text("#import-duplicates");
  check("the import preview counts new entries and duplicates", total.includes("2") && duplicates.includes("1"), `${total} / ${duplicates}`);
  check("the preview names the new service", (await text("#import-new-services")).includes("Example"));
  check("the preview names the existing service", (await text("#import-existing-services")).includes("Anthropic"));
  await shot("import-preview");
  await click("#import-delete");
  await click("#import-commit");
  await waitGone("#import", 30000);
  const afterImport = await waitUntil(`document.querySelectorAll("#item-list .row").length`, (count) => count === 10);
  check("importing adds the two new entries", afterImport === 10, `${afterImport} rows`);
  check("the plain text export file is deleted when asked", !existsSync(importPath));

  // Importing the encrypted export back into the same vault finds nothing new
  copyFileSync(exportPath, importPath);
  await openFromSettings("#settings-import", "#import");
  await click("#import-pick");
  await waitFor("#import-password", 30000);
  await fill("#import-password", "Wrong-password-1");
  await click("#import-unlock");
  await waitFor("#import .error", 30000);
  check("a wrong export password is refused on import", true);
  await fill("#import-password", EXPORT_PASSWORD);
  await click("#import-unlock");
  await waitFor("#import-nothing", 30000);
  check("importing the export again finds nothing new", true);
  await click("#import .dialog-head .icon-btn");
  await waitGone("#import");

  if (checkAutoLock) {
    await click("#nav-settings");
    await fill("#settings-autolock", "1");
    await click("#settings .dialog-head .icon-btn");
    const start = Date.now();
    await waitFor("#unlock", 90000);
    check("auto-lock locks after one idle minute", true, `${Math.round((Date.now() - start) / 1000)} s`);
  }
} catch (error) {
  check("driver finished without an exception", false, error.message);
  try {
    await shot("failure");
  } catch {
    // no page to capture
  }
} finally {
  cdp?.close();
  app.kill();
  await sleep(800);
  rmSync(dataDir, { recursive: true, force: true });
  const failed = results.filter((result) => !result.ok);
  console.log(`\n${results.length - failed.length} of ${results.length} checks passed`);
  process.exit(failed.length ? 1 : 0);
}
