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
  $("login").hidden = false;
  $("login-error").textContent = message || "";
  $("session").textContent = "";
}

function showConsole() {
  $("login").hidden = true;
  $("console").hidden = false;
  $("session").textContent = "";
  const signOut = document.createElement("button");
  signOut.type = "button";
  signOut.textContent = "Sign out";
  signOut.addEventListener("click", () => {
    sessionStorage.removeItem(TOKEN_KEY);
    showLogin("");
  });
  $("session").appendChild(signOut);
}

$("login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  $("login-error").textContent = "";
  let response;
  try {
    response = await fetch("/api/v1/auth/token", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: $("password").value }),
    });
  } catch {
    $("login-error").textContent = "The server is unreachable.";
    return;
  }
  if (response.status === 429) {
    $("login-error").textContent = "Too many attempts — wait a moment and try again.";
    return;
  }
  if (!response.ok) {
    $("login-error").textContent = "That password was refused.";
    $("password").select();
    return;
  }
  const issued = await response.json();
  sessionStorage.setItem(TOKEN_KEY, issued.token);
  $("password").value = "";
  showConsole();
  refresh();
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

async function refresh() {
  const [vaultsResponse, snapshotsResponse, health, card] = await Promise.all([
    api("GET", "/admin/vaults"),
    api("GET", "/admin/backups"),
    fetch("/healthz").then((r) => (r.ok ? r.json() : null)),
    fetch("/", { headers: { Accept: "application/json" } }).then((r) => (r.ok ? r.json() : null)),
  ]);
  $("version").textContent = card ? "syncbox " + card.version : "";
  if (health) renderStats(health);
  await renderSnapshots(snapshotsResponse);
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
    let copied = false;
    try {
      await navigator.clipboard.writeText(command);
      copied = true;
    } catch {
      // Clipboard needs a secure context; a tailscale-http console does not
      // have one, so fall back to selecting the command for Ctrl+C.
      const area = document.createElement("textarea");
      area.value = command;
      document.body.appendChild(area);
      area.select();
      try { copied = document.execCommand("copy"); } catch { copied = false; }
      area.remove();
    }
    copy.textContent = copied ? "Copied" : "Select and copy";
    setTimeout(() => { copy.textContent = "Copy command"; }, 1600);
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
  card.appendChild(actions);
  return card;
}

function renderVaults(vaults) {
  const host = $("vault-list");
  host.textContent = "";
  $("vaults-empty").hidden = vaults.length > 0;
  for (const vault of vaults) host.appendChild(vaultCard(vault));
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
  const response = await api("POST", "/admin/vaults", location ? { name, location } : { name });
  if (!response.ok) {
    $("vault-error").textContent = await reason(response);
    return;
  }
  $("vault-name").value = "";
  $("vault-location").value = "";
  refresh();
});

// Boot: a stored token gets the console and the first 401 returns to the
// door; no token means the login form is the front page, honestly labelled.
if (token()) {
  showConsole();
  refresh();
} else {
  showLogin("");
}
