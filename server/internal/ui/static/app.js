"use strict";

// The console's whole brain. It knows nothing the API does not hand it, and
// the API hands it nothing that needs a key to read — which is the point.

const TOKEN_KEY = "syncbox-token";
const $ = (id) => document.getElementById(id);

function token() {
  return sessionStorage.getItem(TOKEN_KEY);
}

// api is fetch with the bearer token attached, and one rule on top: a 401
// while signed in means the token aged out mid-session, so we say so and
// return to the door rather than failing every panel in silence.
async function api(method, path, body) {
  const headers = {};
  if (token()) headers["Authorization"] = "Bearer " + token();
  if (body !== undefined) headers["Content-Type"] = "application/json";
  const response = await fetch(path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (response.status === 401 && token()) {
    sessionStorage.removeItem(TOKEN_KEY);
    showLogin("The session ended. Sign in again.");
    throw new Error("signed out");
  }
  return response;
}

async function reason(response) {
  try {
    const body = await response.json();
    return body.reason || body.code || ("request failed with " + response.status);
  } catch {
    return "request failed with " + response.status;
  }
}

function showLogin(message) {
  $("console").hidden = true;
  $("setup").hidden = true;
  $("login").hidden = false;
  $("login-error").textContent = message || "";
  $("session").textContent = "";
  stopLiveStats();
}

// showSetup reveals the first-run screen: a server with no password yet, which the
// login form cannot sign into because there is nothing to sign in with.
function showSetup() {
  $("console").hidden = true;
  $("login").hidden = true;
  $("setup").hidden = false;
  $("setup-error").textContent = "";
  $("session").textContent = "";
  stopLiveStats();
  $("setup-password").focus();
}

function showConsole() {
  $("login").hidden = true;
  $("setup").hidden = true;
  $("console").hidden = false;
  $("session").textContent = "";
  startLiveStats();
  const signOut = document.createElement("button");
  signOut.type = "button";
  signOut.textContent = "Sign out";
  signOut.addEventListener("click", () => {
    sessionStorage.removeItem(TOKEN_KEY);
    showLogin("");
  });
  $("session").appendChild(signOut);
}

// fetchAuthStatus asks which screen the door wants: a server with no password yet
// must show first-run, not a sign-in form it can never satisfy. Anything other
// than an explicit "not initialized" — a fetch failure, a surprising reply — falls
// back to the ordinary sign-in, which is the safe default.
async function fetchAuthStatus() {
  try {
    const response = await fetch("/api/v1/auth/status");
    if (!response.ok) return { initialized: true };
    return await response.json();
  } catch {
    return { initialized: true };
  }
}

// issueToken exchanges a password for a session token, translating the server's
// refusals into the one line of human text each deserves. It stores the token on
// success; callers own moving to the console.
async function issueToken(password) {
  let response;
  try {
    response = await fetch("/api/v1/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
  } catch {
    return { ok: false, message: "The server is unreachable." };
  }
  if (response.status === 429) {
    return { ok: false, message: "Too many attempts — wait a moment and try again." };
  }
  if (response.status === 401) {
    return { ok: false, message: "That password was refused." };
  }
  if (!response.ok) {
    return { ok: false, message: "Could not sign in (server said " + response.status + ")." };
  }
  const issued = await response.json();
  sessionStorage.setItem(TOKEN_KEY, issued.token);
  return { ok: true };
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("login-error").textContent = "";
  const result = await issueToken($("password").value);
  if (!result.ok) {
    $("login-error").textContent = result.message;
    $("password").select();
    return;
  }
  $("password").value = "";
  showConsole();
  refresh();
});

// The first run validates on the client for the usual reasons — an empty or short
// password, or the two fields disagreeing — so the operator is not bounced to the
// server for a mistake they can see, then hands off to issueToken to sign straight
// in with the password just chosen. If the server already has a password (another
// caller won the race, or the tab is stale), it falls back to plain sign-in.
$("setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("setup-error").textContent = "";
  const password = $("setup-password").value;
  const confirm = $("setup-confirm").value;
  if (password === "") {
    $("setup-error").textContent = "Choose a password.";
    $("setup-password").focus();
    return;
  }
  if (password.length < 8) {
    $("setup-error").textContent = "Use at least 8 characters.";
    $("setup-password").focus();
    return;
  }
  if (password !== confirm) {
    $("setup-error").textContent = "The two passwords don't match.";
    $("setup-confirm").focus();
    return;
  }

  const submit = $("setup-form").querySelector("button");
  submit.disabled = true;
  try {
    const response = await fetch("/api/v1/auth/setup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password }),
    });
    if (response.status === 429) {
      $("setup-error").textContent = "Too many attempts — wait a moment and try again.";
      return;
    }
    if (response.status === 409) {
      $("setup-password").value = "";
      $("setup-confirm").value = "";
      showLogin("This server already has a password. Sign in with it.");
      return;
    }
    if (!response.ok) {
      const body = await response.json().catch(() => ({}));
      $("setup-error").textContent = body.reason || ("The server refused the password (" + response.status + ").");
      return;
    }
    $("setup-password").value = "";
    $("setup-confirm").value = "";
    const signed = await issueToken(password);
    if (!signed.ok) {
      showLogin("The password is set, but sign-in did not take. Sign in again: " + signed.message);
      return;
    }
    showConsole();
    refresh();
  } catch {
    $("setup-error").textContent = "The server is unreachable.";
  } finally {
    submit.disabled = false;
  }
});

function fmtBytes(n) {
  const units = ["B", "KiB", "MiB", "GiB", "TiB"];
  let value = n;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return (unit === 0 ? value : value.toFixed(1)) + " " + units[unit];
}

function fmtTime(unix) {
  return unix ? new Date(unix * 1000).toLocaleString() : "never";
}

// copyText puts text on the clipboard when the browser lets it, and says so when
// it will not. The console often runs over a plain http tailscale address, which
// is not a secure context, so the clipboard API is unavailable there; the
// fallback selects the text so the operator can copy it themselves.
async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const area = document.createElement("textarea");
    area.value = text;
    document.body.appendChild(area);
    area.select();
    let copied = false;
    try { copied = document.execCommand("copy"); } catch { copied = false; }
    area.remove();
    return copied;
  }
}

// flashCopy relabels a button for a moment to confirm what the operator just put
// on their clipboard, then hands the button back.
function flashCopy(button, label, copied) {
  const original = button.textContent;
  button.textContent = copied ? label : "Select and copy";
  setTimeout(() => { button.textContent = original; }, 1600);
}

async function refresh() {
  const [vaultsResponse, snapshotsResponse, scheduleResponse, health, card] = await Promise.all([
    api("GET", "/admin/vaults"),
    api("GET", "/admin/backups"),
    api("GET", "/admin/backups/config"),
    fetch("/healthz").then((r) => (r.ok ? r.json() : null)),
    fetch("/", { headers: { Accept: "application/json" } }).then((r) => (r.ok ? r.json() : null)),
  ]);
  $("version").textContent = card ? "syncbox " + card.version : "";
  if (health) renderStats(health);
  await renderSnapshots(snapshotsResponse);
  renderSchedule(scheduleResponse);
  if (!vaultsResponse.ok) {
    $("vault-error").textContent = await reason(vaultsResponse);
    return;
  }
  $("vault-error").textContent = "";
  const body = await vaultsResponse.json();
  renderVaults(body.vaults);
}

function definitionList(pairs) {
  const host = document.createElement("dl");
  for (const [label, value] of pairs) {
    const dt = document.createElement("dt");
    dt.textContent = label;
    const dd = document.createElement("dd");
    dd.textContent = value;
    host.append(dt, dd);
  }
  return host;
}

function renderStats(health) {
  const storage = health.storage || {};
  const host = $("stats");
  host.replaceWith(
    Object.assign(definitionList([
      ["Chunks", String(storage.chunks ?? 0)],
      ["Chunk bytes", fmtBytes(storage.chunk_bytes ?? 0)],
      ["Revisions", String(storage.revisions ?? 0)],
      ["Largest chunk", fmtBytes(storage.largest_chunk ?? 0)],
    ]), { id: "stats" })
  );
}

// The folder a client will use. The server stores it relative to each client's
// home ("Syncbox/Photos"); a `~`-prefixed or absolute value is used as typed.
// An empty location means the operator left it to each client, so the plain
// default is shown — and the field is editable on the card either way.
function resolvedFolder(location) {
  if (!location) return "~/Syncbox";
  if (location.startsWith("~") || location.startsWith("/")) return location;
  return "~/" + location;
}

function pairingCommand(vault) {
  return [
    "syncbox sync once",
    "  --server " + location.origin,
    "  --vault-id " + vault.id,
    "  --folder " + resolvedFolder(vault.location),
    "  --password <server password>",
  ].join(" \\\n");
}

function vaultCard(vault) {
  const card = document.createElement("article");
  card.className = vault.archived ? "vault-card archived" : "vault-card";

  const title = document.createElement("h3");
  title.textContent = vault.name || "(unnamed)";
  if (vault.archived) {
    const badge = document.createElement("span");
    badge.className = "badge";
    badge.textContent = "archived";
    title.appendChild(badge);
  }
  card.appendChild(title);

  card.appendChild(definitionList([
    ["Vault id", vault.id],
    ["Mode", vault.mode === "vault" ? "vault — end-to-end encrypted" : "sync — stored in the clear"],
    ["Folder", resolvedFolder(vault.location)],
    ["Revisions", String(vault.revisions)],
    ["Live files", String(vault.live_files)],
    ["Live bytes", fmtBytes(vault.bytes)],
    ["Last write", fmtTime(vault.last_write_at)],
    ["Created", fmtTime(vault.created_at)],
  ]));

  const command = pairingCommand(vault);
  const pre = document.createElement("pre");
  pre.textContent = command;
  card.appendChild(pre);

  const copy = document.createElement("button");
  copy.type = "button";
  copy.textContent = "Copy command";
  copy.addEventListener("click", async () => {
    flashCopy(copy, "Copied", await copyText(command));
  });
  card.appendChild(copy);

  const actions = document.createElement("div");
  actions.className = "actions";

  const rename = document.createElement("button");
  rename.type = "button";
  rename.textContent = "Rename";
  rename.addEventListener("click", async () => {
    const name = window.prompt("Vault name", vault.name);
    if (name === null || name.trim() === "") return;
    const response = await api("PATCH", "/admin/vaults/" + encodeURIComponent(vault.id), { name });
    if (!response.ok) $("vault-error").textContent = await reason(response);
    refresh();
  });

  const locate = document.createElement("button");
  locate.type = "button";
  locate.textContent = "Set folder";
  locate.addEventListener("click", async () => {
    const current = vault.location || "";
    const location = window.prompt(
      "Folder for this vault, relative to each client's home\n" +
        "(for example Syncbox/Photos; ~/Photos or /srv/photos are used as typed; empty means clients choose)",
      current);
    if (location === null) return;
    const response = await api("PATCH", "/admin/vaults/" + encodeURIComponent(vault.id),
      { location: location.trim() });
    if (!response.ok) $("vault-error").textContent = await reason(response);
    refresh();
  });

  const retire = document.createElement("button");
  retire.type = "button";
  retire.textContent = vault.archived ? "Restore" : "Archive";
  retire.addEventListener("click", async () => {
    const response = await api("POST", "/admin/vaults/" + encodeURIComponent(vault.id) + "/archive",
      { archived: !vault.archived });
    if (!response.ok) $("vault-error").textContent = await reason(response);
    refresh();
  });

  actions.append(rename, locate, retire);

  // A sync space is one the server can read, so its files are browsable,
  // shareable and recoverable from the bin right here. A vault is not: the
  // server holds only ciphertext, so the honest answer is to say so rather than
  // offer a button the server would refuse.
  if (vault.mode === "vault") {
    card.appendChild(actions);
    const note = document.createElement("p");
    note.className = "hint vault-note";
    note.textContent = "Encrypted end to end: the server keeps only ciphertext, " +
      "so it cannot browse, share, or recycle this space's files.";
    card.appendChild(note);
    return card;
  }

  const panel = spacePanel(vault);
  const browse = document.createElement("button");
  browse.type = "button";
  browse.textContent = "Browse files";
  browse.setAttribute("aria-expanded", "false");
  browse.addEventListener("click", () => {
    const open = panel.el.hidden;
    panel.el.hidden = !open;
    browse.textContent = open ? "Hide files" : "Browse files";
    browse.setAttribute("aria-expanded", String(open));
    if (open) panel.reload();
  });
  actions.insertBefore(browse, rename);

  card.appendChild(actions);
  card.appendChild(panel.el);
  return card;
}

function renderVaults(vaults) {
  const host = $("vault-list");
  host.textContent = "";
  $("vaults-empty").hidden = vaults.length > 0;
  for (const vault of vaults) host.appendChild(vaultCard(vault));
}

// revealLink swaps a file row's action for a copyable share link and when it
// dies. The server hands back a relative URL; the console shows the absolute one
// so the operator sends something a recipient can actually open.
function revealLink(container, view) {
  container.textContent = "";
  const url = location.origin + view.url;

  const box = document.createElement("span");
  box.className = "share-link";

  const input = document.createElement("input");
  input.type = "text";
  input.readOnly = true;
  input.value = url;
  input.setAttribute("aria-label", "Share link for " + view.path);

  const copy = document.createElement("button");
  copy.type = "button";
  copy.textContent = "Copy link";
  copy.addEventListener("click", async () => {
    flashCopy(copy, "Copied", await copyText(url));
  });

  const when = document.createElement("span");
  when.className = "share-expiry";
  when.textContent = "expires " + fmtTime(view.expires_unix);

  box.append(input, copy, when);
  container.appendChild(box);
}

// spacePanel is a sync space's readable surfaces (M11 S4): browse, share, and
// the recycle bin. They are reads of what the space stores in the clear, so the
// console offers them for a sync space and must not for a vault — the server
// refuses a vault on each with a code, because it holds only ciphertext and so
// has nothing to show. Every call here hits the same endpoint an operator would
// curl; nothing here decrypts anything, which is why the console may offer it.
function spacePanel(vault) {
  const base = "/api/v1/vaults/" + encodeURIComponent(vault.id);

  const el = document.createElement("div");
  el.className = "space-panel";
  el.hidden = true; // stays folded until the operator clicks Browse files

  const filesTab = document.createElement("button");
  filesTab.type = "button";
  filesTab.className = "space-tab active";
  filesTab.textContent = "Files";
  const binTab = document.createElement("button");
  binTab.type = "button";
  binTab.className = "space-tab";
  binTab.textContent = "Recycle bin";

  const tabs = document.createElement("div");
  tabs.className = "space-tabs";
  tabs.append(filesTab, binTab);

  const note = document.createElement("p");
  note.className = "hint";
  note.textContent = "These files are stored in the clear, so a share link in " +
    "anyone's hands downloads them. A deleted file stays here until the " +
    "server's recycle window passes.";

  const status = document.createElement("p");
  status.className = "ok";
  status.setAttribute("role", "status");

  const error = document.createElement("p");
  error.className = "error";
  error.setAttribute("role", "alert");

  const filesHost = document.createElement("div");
  filesHost.className = "file-list";
  const binHost = document.createElement("div");
  binHost.className = "file-list";
  binHost.hidden = true;

  let shown = "files";

  function emptyRow(text) {
    const row = document.createElement("p");
    row.className = "file-empty";
    row.textContent = text;
    return row;
  }

  function fileRow(file) {
    const row = document.createElement("div");
    row.className = "file-row";

    const name = document.createElement("span");
    name.className = "file-name";
    name.textContent = file.path;

    const meta = document.createElement("span");
    meta.className = "file-meta";
    meta.textContent = fmtBytes(file.size) + " · " + fmtTime(file.modified_unix);

    const action = document.createElement("span");
    action.className = "file-action";

    const share = document.createElement("button");
    share.type = "button";
    share.textContent = "Share";
    share.addEventListener("click", async () => {
      status.textContent = "";
      error.textContent = "";
      share.disabled = true;
      share.textContent = "Sharing…";
      const response = await api("POST", base + "/shares", {
        dir_id: file.dir_id, cipher_name: file.cipher_name,
      });
      if (!response.ok) {
        error.textContent = await reason(response);
        share.disabled = false;
        share.textContent = "Share";
        return;
      }
      revealLink(action, await response.json());
    });

    action.appendChild(share);
    row.append(name, meta, action);
    return row;
  }

  function binRow(entry) {
    const row = document.createElement("div");
    row.className = "file-row";

    const name = document.createElement("span");
    name.className = "file-name";
    name.textContent = entry.path;

    const meta = document.createElement("span");
    meta.className = "file-meta";
    meta.textContent = fmtBytes(entry.size) + " · deleted " + fmtTime(entry.deleted_unix);

    const action = document.createElement("span");
    action.className = "file-action";

    const restore = document.createElement("button");
    restore.type = "button";
    restore.textContent = "Restore";
    restore.addEventListener("click", async () => {
      status.textContent = "";
      error.textContent = "";
      restore.disabled = true;
      restore.textContent = "Restoring…";
      const response = await api("POST", base + "/recycle/restore", {
        dir_id: entry.dir_id, cipher_name: entry.cipher_name,
      });
      if (!response.ok) {
        error.textContent = await reason(response);
        restore.disabled = false;
        restore.textContent = "Restore";
        return;
      }
      status.textContent = entry.path + " is back. Peers pull it on their next sync.";
      await loadBin();
    });

    action.appendChild(restore);
    row.append(name, meta, action);
    return row;
  }

  async function loadFiles() {
    filesHost.textContent = "";
    const response = await api("GET", base + "/files");
    if (!response.ok) {
      error.textContent = await reason(response);
      return;
    }
    const body = await response.json();
    const files = (body.files || []).slice().sort((a, b) => a.path.localeCompare(b.path));
    if (files.length === 0) {
      filesHost.appendChild(emptyRow("This space has no files yet."));
      return;
    }
    for (const file of files) filesHost.appendChild(fileRow(file));
  }

  async function loadBin() {
    binHost.textContent = "";
    const response = await api("GET", base + "/recycle");
    if (!response.ok) {
      error.textContent = await reason(response);
      return;
    }
    const body = await response.json();
    const deleted = body.deleted || [];
    if (deleted.length === 0) {
      binHost.appendChild(emptyRow("The recycle bin is empty."));
      return;
    }
    for (const entry of deleted) binHost.appendChild(binRow(entry));
  }

  function show(which) {
    shown = which;
    status.textContent = "";
    error.textContent = "";
    filesTab.classList.toggle("active", which === "files");
    binTab.classList.toggle("active", which === "bin");
    filesHost.hidden = which !== "files";
    binHost.hidden = which !== "bin";
    (which === "files" ? loadFiles : loadBin)();
  }

  filesTab.addEventListener("click", () => show("files"));
  binTab.addEventListener("click", () => show("bin"));
  el.append(tabs, note, status, error, filesHost, binHost);

  return { el, reload: () => show(shown) };
}

// Snapshots are whole-server, and the panel drives the same admin routes the
// CLI does. Taking and listing are ordinary; verify re-reads every stored
// object to prove it survived; restore writes ciphertext back into a directory
// the server can reach, so it is gated twice — the bearer token, and typing the
// snapshot id — because a mis-typed restore would be a real overwrite. Nothing
// here decrypts anything, which is why the console may offer it at all.
function fmtDate(value) {
  return value ? new Date(value).toLocaleString() : "unknown";
}

function snapshotCard(snapshot) {
  const manifest = snapshot.Manifest || {};
  const card = document.createElement("article");
  card.className = "vault-card";

  const title = document.createElement("h3");
  title.textContent = snapshot.ID;
  card.appendChild(title);

  card.appendChild(definitionList([
    ["Taken", fmtDate(snapshot.CreatedAt)],
    ["Chunks", String((manifest.chunks || []).length)],
    ["Chunk bytes", fmtBytes(manifest.chunk_bytes ?? 0)],
    ["Server", manifest.server_version || "unknown"],
  ]));

  const actions = document.createElement("div");
  actions.className = "actions";

  const verify = document.createElement("button");
  verify.type = "button";
  verify.textContent = "Verify";
  verify.addEventListener("click", async () => {
    $("snapshot-error").textContent = "";
    $("snapshot-note").textContent = "";
    verify.disabled = true;
    try {
      const response = await api(
        "POST", "/admin/backups/" + encodeURIComponent(snapshot.ID) + "/verify");
      if (!response.ok) {
        $("snapshot-error").textContent = await reason(response);
        return;
      }
      const report = await response.json();
      $("snapshot-note").textContent =
        snapshot.ID + " verified: " + report.chunks + " chunks, " +
        fmtBytes(report.chunk_bytes || 0) + " re-read byte for byte.";
    } finally {
      verify.disabled = false;
    }
  });

  const restore = document.createElement("button");
  restore.type = "button";
  restore.textContent = "Restore";
  restore.addEventListener("click", async () => {
    $("snapshot-error").textContent = "";
    $("snapshot-note").textContent = "";
    const dest = window.prompt(
      "Restore " + snapshot.ID + " into which directory on the server?\n" +
        "(the server writes it there, and refuses a directory that already holds a metadata.json)",
      "");
    if (dest === null || dest.trim() === "") return;
    const typed = window.prompt(
      "This copies the snapshot's contents into that directory.\n" +
        "Type the snapshot id to confirm:\n" + snapshot.ID);
    if (typed !== snapshot.ID) {
      $("snapshot-error").textContent = "Restore cancelled — the id did not match.";
      return;
    }
    const response = await api(
      "POST", "/admin/backups/" + encodeURIComponent(snapshot.ID) + "/restore",
      { dest_dir: dest.trim() });
    if (!response.ok) {
      $("snapshot-error").textContent = await reason(response);
      return;
    }
    const report = await response.json();
    $("snapshot-note").textContent =
      "Restored " + report.id + " into " + report.dest_dir + " (" +
      report.chunks + " chunks, " + fmtBytes(report.chunk_bytes || 0) + ").";
  });

  actions.append(verify, restore);
  card.appendChild(actions);
  return card;
}

async function renderSnapshots(response) {
  if (response.status === 501) {
    // No target configured: say so plainly rather than showing an empty list
    // that reads as "no snapshots yet".
    $("take-snapshot").disabled = true;
    $("snapshot-list").textContent = "";
    $("snapshot-note").textContent = "";
    $("snapshots-empty").hidden = false;
    $("snapshots-empty").textContent =
      "No backup target is configured, so there is nowhere to write a snapshot.";
    return;
  }
  $("take-snapshot").disabled = false;
  if (!response.ok) {
    $("snapshot-error").textContent = await reason(response);
    return;
  }
  $("snapshot-error").textContent = "";
  const snapshots = await response.json();
  const host = $("snapshot-list");
  host.textContent = "";
  $("snapshots-empty").hidden = snapshots.length > 0;
  if (snapshots.length === 0) {
    $("snapshots-empty").textContent = "No snapshots yet. Take one before you need it.";
  }
  for (const snapshot of snapshots) host.appendChild(snapshotCard(snapshot));
}

// renderSchedule fills the schedule select from the server's live cadence. With
// no backup target there is nothing to schedule, so the control is disabled and
// says why rather than sitting there applying nothing.
function renderSchedule(response) {
  const select = $("schedule-select");
  const button = $("schedule-form").querySelector("button");
  $("schedule-note").textContent = "";
  if (!response.ok) {
    select.disabled = true;
    button.disabled = true;
    return;
  }
  response.json().then((cfg) => {
    if (!cfg.configured) {
      select.disabled = true;
      button.disabled = true;
      $("schedule-note").textContent = "Scheduled snapshots need a backup target first.";
      return;
    }
    select.disabled = false;
    button.disabled = false;
    const preset = Array.from(select.options).some((o) => Number(o.value) === cfg.interval_seconds);
    if (preset) {
      select.value = String(cfg.interval_seconds);
    } else {
      // A cadence from the environment that is not one of the presets: leave the
      // select unselected and say what is actually running.
      select.selectedIndex = -1;
      $("schedule-note").textContent = "Current schedule: " + (cfg.schedule || "off") + ".";
    }
  });
}

$("schedule-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("schedule-note").textContent = "";
  const button = $("schedule-form").querySelector("button");
  const seconds = Number($("schedule-select").value);
  const label = $("schedule-select").selectedOptions[0].textContent;
  button.disabled = true;
  try {
    const response = await api("PUT", "/admin/backups/config", { interval_seconds: seconds });
    if (!response.ok) {
      $("snapshot-error").textContent = await reason(response);
      return;
    }
    $("snapshot-error").textContent = "";
    const cfg = await response.json();
    $("schedule-note").textContent = cfg.interval_seconds === 0
      ? "Scheduled snapshots are off."
      : "Scheduled snapshots: " + label.toLowerCase() + ".";
  } finally {
    button.disabled = false;
  }
});

$("take-snapshot").addEventListener("click", async () => {
  const button = $("take-snapshot");
  $("snapshot-error").textContent = "";
  $("snapshot-note").textContent = "";
  button.disabled = true;
  button.textContent = "Taking…";
  try {
    const response = await api("POST", "/admin/backups");
    if (!response.ok) {
      $("snapshot-error").textContent = await reason(response);
      return;
    }
    const snapshot = await response.json();
    $("snapshot-note").textContent = "Took " + snapshot.ID + ".";
  } finally {
    button.textContent = "Take snapshot";
    button.disabled = false;
    refresh();
  }
});

$("create-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("vault-error").textContent = "";
  const name = $("vault-name").value.trim();
  const location = $("vault-location").value.trim();
  const mode = $("vault-mode").value;
  const body = location ? { name, location, mode } : { name, mode };
  const response = await api("POST", "/admin/vaults", body);
  if (!response.ok) {
    $("vault-error").textContent = await reason(response);
    return;
  }
  $("vault-name").value = "";
  $("vault-location").value = "";
  $("vault-mode").value = "sync";
  refresh();
});

// Rotating the server password. The client mirrors the server's floor (>= 8) and
// the match rule so an obvious mistake never round-trips, but the server is the
// authority: it re-checks the current password against the Argon2id seal, so a
// wrong current password is refused there. It answers 403 (not 401) for that, so
// api() leaves the session alone and the operator stays signed in to try again.
$("password-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("password-error").textContent = "";
  $("password-note").textContent = "";
  const current = $("pw-current").value;
  const next = $("pw-next").value;
  const confirm = $("pw-confirm").value;
  if (current === "") {
    $("password-error").textContent = "Enter your current password.";
    $("pw-current").focus();
    return;
  }
  if (next === "") {
    $("password-error").textContent = "Choose a new password.";
    $("pw-next").focus();
    return;
  }
  if (next.length < 8) {
    $("password-error").textContent = "Use at least 8 characters.";
    $("pw-next").focus();
    return;
  }
  if (next !== confirm) {
    $("password-error").textContent = "The two new passwords don't match.";
    $("pw-confirm").focus();
    return;
  }

  const button = $("password-form").querySelector("button");
  button.disabled = true;
  try {
    const response = await api("POST", "/api/v1/auth/password", { current, password: next });
    if (!response.ok) {
      $("password-error").textContent = await reason(response);
      return;
    }
    $("pw-current").value = "";
    $("pw-next").value = "";
    $("pw-confirm").value = "";
    $("password-note").textContent =
      "Password changed. It stays in force until the next restart only if " +
      "SYNCBOX_PASSWORD is set in the environment; otherwise it is sealed to the " +
      "data directory and permanent. Update any clients that sync against this server.";
  } finally {
    button.disabled = false;
  }
});

// The console follows the operator's own light/dark setting; this button pins
// it either way for this browser, and "system" hands the decision back. The
// palette itself lives in `color-scheme` plus `light-dark()` in the stylesheet.
const THEME_KEY = "syncbox-theme";
const THEMES = ["system", "light", "dark"];

function storedTheme() {
  const stored = localStorage.getItem(THEME_KEY);
  return THEMES.includes(stored) ? stored : "system";
}

function applyTheme(mode) {
  const root = document.documentElement;
  if (mode === "light" || mode === "dark") {
    root.dataset.theme = mode;
  } else {
    delete root.dataset.theme;
  }
  $("theme").textContent = "Theme: " + mode;
}

$("theme").addEventListener("click", () => {
  const next = THEMES[(THEMES.indexOf(storedTheme()) + 1) % THEMES.length];
  localStorage.setItem(THEME_KEY, next);
  applyTheme(next);
});

applyTheme(storedTheme());

// The overview strip is the one panel with a "now" to it, so it re-reads the
// health endpoint while the console is open: an active client or a backup in
// flight shows up as the counts move, without a reload.
let liveStats = null;

function startLiveStats() {
  stopLiveStats();
  liveStats = setInterval(async () => {
    if (document.hidden) return;
    const response = await fetch("/healthz");
    if (response.ok) renderStats(await response.json());
  }, 5000);
}

function stopLiveStats() {
  if (liveStats !== null) {
    clearInterval(liveStats);
    liveStats = null;
  }
}

// Boot: a stored token goes straight to the console (the first 401 returns to the
// door); no token means we ask the server whether it even has a password yet — if
// not, first-run setup is the front page; otherwise the sign-in form is.
(async function boot() {
  if (token()) {
    showConsole();
    refresh();
    return;
  }
  const status = await fetchAuthStatus();
  if (status.initialized === false) showSetup();
  else showLogin("");
})();
