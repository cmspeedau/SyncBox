# Syncbox agent settings window — design reference

Version 1. The settings window of the desktop agent, designed against the
**new OneDrive sync app** settings as a baseline. The interactive mockup is
[`reference-agent-settings.html`](reference-agent-settings.html) — open it in
a browser; the page nav, folder tree, pause durations and *Apply settings*
all work.

Status: design reference only. Controls are badged `today` (backed by an
existing agent command) or `new` (needs a new backend concept); the `new`
list at the bottom is the settings slice of the agent roadmap.

## Window

One top-level Tauri window (~640 × 560, resizable), opened by the gear
button in the main window. Three regions:

| Region | Contents |
|---|---|
| Rail (200 px) | vault card (lock + name, storage bar, "1.8 GB of 50 GB · 412 files") over the page list |
| Page area | Sync Files · Account · Notifications · About |
| Footer bar | *Run at login* and **Show hidden features** toggles, right-aligned (app-wide, so not page items) |

### Show hidden features

App-wide toggle in the footer bar. Until this window ships, the switch lives
in the main window's footer bar (M16 S1) and the pref it writes already
exists. **Off (default):** the out-of-the-box
flow — the client picks vaults from the server, the sync folder is the
server-derived one, ids are never typed, no vault is created from here.
**On:** reveals the three advanced controls designed in
[`reference-agent-ui.md`](reference-agent-ui.md) — the `+ New vault` row in
the picker, the *Enter id by hand* segment, and extra sync folders. It
gates controls that exist, so unlike the `new`-badged controls below it is
honest from its first ship.

## Pages

### Sync Files

- **Sync folder** — path + `Open` / `Change…` (both inside the card).
- **Choose folders** `new` — `Sync everything` master checkbox on top of a
  folder tree derived from the server index. Master off ⇒ tree enables;
  ticking a folder ticks its subtree; parents show a partial dash when
  children are mixed; carets collapse. Unchecked folders never download to
  this machine.
- **Pause syncing** `new` — durations (`1h / 8h / 24h / Until I resume`)
  plus a resume strip; same control as the main window.
- **Apply settings** — bottom-right; disabled until something on the page
  changed ("Unsaved changes" → "Settings applied"). Folder selection means
  disk work, so it is deliberate, not instant-save.

### Account

- **Server** — read-only host + `Change…`, which re-runs first run.
- **Vault** — read-only name; switching a vault = re-run first run (picker
  from `list_vaults`). Folder-level choice lives under Sync Files.
- **Vault auto-lock** `new` — inactivity timer (15 min … Never) driving
  `lock`; OneDrive Personal Vault's auto-lock applied to the whole vault.
- **Remove vault from this computer** — destructive; forgets local config +
  encrypted cache, server untouched.

### Notifications `new`

Per-event toggles: sync errors (on), conflicts (on), pass finished (off),
vault locked/unlocked (off). Events come from `SyncEvent`, so toasts and
the activity feed share one source.

### About

Device ID (support handle), agent version, server version, `Open logs…`,
`Check for updates` `new`.

## Backend mapping

| Control | Source |
|---|---|
| Rail storage card | `Index::files()`, `referenced_bytes()` (+ quota when the server reports one) |
| Run at login | `get_autostart` / `set_autostart` |
| Show hidden features | new agent pref; gates UI only, stores nothing else |
| Sync folder Open | open-folder command |
| Change… (server), vault re-pick | first-run flow + `list_vaults` |
| Choose folders | folder set from `Index::files()` paths; selection = new per-device rule the agent applies when downloading (server untouched) |
| Pause syncing | new paused flag + resume-at timestamp |
| Auto-lock | new inactivity timer driving `lock` |
| Notifications | new prefs filtering `SyncEvent` for toasts |
| Remove vault | new command: forget config + cache; never deletes remotely |

## New agent concepts (roadmap slice)

1. `Paused` state with durations (pause + resume-at).
2. Selective folder sync — per-device subtree selection.
3. Vault auto-lock after inactivity.
4. Notification preferences.
5. Update checker.
6. Hidden-tier pref (`Show hidden`) gating client-side vault creation,
   by-hand vault id, and extra sync folders.

## Dropped from the OneDrive baseline on purpose

Multi-account (one server, one vault per sync root), Files On Demand
(everything syncs), Personal Vault (the whole vault locks), Insider rings,
in-window storage management (that is the web Files UI), pause-on-battery-
saver and bandwidth limits (deferred, not rejected).

## Design tokens

Same as [`reference-web-ui.md`](reference-web-ui.md) plus: rail gradient
`#F1F8FD → #DCEBFA`, card border `#E2ECF3`, footer bar `#F6FAFD`, primary
button `#006AA3`, tree checkbox accent `#0082C9`.

## Design source

- **OneDrive — new sync app settings** — storage card, page split,
  choose-folders tree with "Sync everything", pause durations, auto-lock
  time, device-ID About.
  [Microsoft Support](https://support.microsoft.com/en-us/onedrive/how-to-access-onedrive-settings)
- **ownCloud desktop 7.1** — cross-check for how small an agent settings
  window may stay.
