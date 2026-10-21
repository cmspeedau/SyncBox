# Syncbox agent settings window — design reference

Version 1. The settings window of the desktop agent, designed against the
**new OneDrive sync app** settings as a baseline. The interactive mockup is
[`reference-agent-settings.html`](reference-agent-settings.html) — open it in
a browser; the page nav, folder tree, pause durations and *Apply settings*
all work.

Status: **the `today`-badged subset shipped in M16 S4** —
`client/apps/desktop/src/settings.html` is a real top-level window (640 × 560,
resizable), opened by the gear's *Settings…* item, with the rail, the footer bar
and the three pages whose controls a command already answers to: **Sync Files**
(the synced folders, each with `Open`, *Change…* which re-runs first run, and
the pause as a switch), **Account** (the server and the space, read-only, with
*Change…*) and **About** (agent version, platform, licence, and the space's
state folder with `Open`). The footer's two app-wide switches — *Run at login*
and *Show hidden features* — are here, which is where this reference always
put them: the main window's temporary footer bar is gone and that window now
follows the pref instead of owning it.

Everything badged `new` is **left out rather than drawn dead**, and the pages
that would be all-`new` are not in the nav at all: no Notifications page, no
choose-folders tree, no pause durations, no auto-lock timer, no device id, no
server version, no logs folder, no update checker, and no *Apply settings*
button (every shipped control takes effect as it is touched, so a button to
commit them would do nothing). The `new` list at the bottom is still the
settings slice of the agent roadmap; `6` (the hidden-tier pref) is the one item
of it that shipped, in M16 S1. The rail's storage **bar** is absent too: the
agent has no quota to measure against, so the rail prints
`1.8 GB · 412 files on this machine` and no proportion.

## Window

One top-level Tauri window (~640 × 560, resizable), opened by the gear
button in the main window. Three regions:

| Region | Contents |
|---|---|
| Rail (200 px) | vault card (lock + name, storage bar, "1.8 GB of 50 GB · 412 files") over the page list |
| Page area | Sync Files · Account · Notifications · About |
| Footer bar | *Run at login* and **Show hidden features** toggles, right-aligned (app-wide, so not page items) |

### Show hidden features

App-wide toggle in the footer bar — and since M16 S4 that footer bar is its
only home: the main window's temporary switch (M16 S1) is gone, and that window
re-reads the pref on its 2-second poll, so revealing a control here shows it in
the first-run card without a restart. The pref it writes already
existed. **Off (default):** the out-of-the-box
flow — the client picks vaults from the server, the sync folder is the
server-derived one, ids are never typed, no vault is created from here.
**On:** reveals the three advanced controls designed in
[`reference-agent-ui.md`](reference-agent-ui.md) — the `+ New vault` row in
the picker, the *Enter id by hand* segment, and extra sync folders. It
gates controls that exist, so unlike the `new`-badged controls below it is
honest from its first ship. Because what it reveals is in the other window, the
footer says in words what turning it on does.

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

### As shipped (M16 S4)

The window draws the pages whose controls answer to a command, and nothing
else:

| Reference control | Shipped? |
|---|---|
| Rail name + usage line | ✅ from `settings_info` (the space's name) and `usage` (files, referenced bytes) — no storage **bar**, because nothing reports a quota to divide by |
| Sync folder rows + `Open` | ✅ `open_folder`, one row per synced folder from `status.folders` |
| *Change…* (Sync Files and Account) | ✅ both rows run `lock` then `close_settings`: the main window's rows are where a space is chosen again (the locked rows, or *Add a space…*), so the settings window closes itself and hands focus back |
| Pause syncing | ✅ the switch only — `set_paused`, the loop's flag, no durations (a duration is a resume-at timestamp, which the agent has nowhere to keep) |
| Server, Vault rows | ✅ read-only from `settings_info`; the mode rides as a chip (`encrypted vault` / `sync space`), the same word the picker uses |
| Footer: Run at login | ✅ `get_autostart` / `set_autostart` |
| Footer: Show hidden features | ✅ `get_prefs` / `set_prefs` |
| About: version, platform, licence | ✅ `settings_info` — the build's own facts, so the window needs no new endpoint |
| About: state folder + `Open` | ✅ `settings_info.vaultDir` through `open_folder`; support asks where the state lives |
| Choose folders | ❌ `new` (a per-device selection rule the loop must honor) |
| Pause durations | ❌ `new` (needs a resume-at) |
| Vault auto-lock | ❌ `new` (an inactivity timer) |
| Remove vault from this computer | ❌ the shell now remembers spaces (metadata only) for the locked rows, so there is config to forget; the row waits on a `forget_space` command, and it must never delete the sync folders |
| Notifications page | ❌ the whole page is `new`; its four toggles would be four dead switches, so the page is not in the nav. The main window's Recent activity disclosure stays until this page exists |
| Apply settings | ❌ every shipped control writes at once; the button returns with choose-folders, whose folder work is deliberate |
| Device id, server version, logs, updates | ❌ `new`; the About page says so in one line rather than showing rows that answer nothing. The update half is scoped now (M16's list in the README), so the row has something to arrive with |

While nothing is unlocked the window says so and hides the session's rows — the
two app-wide switches stay live, because they belong to the app and not to a
session. It is reachable from the gear, which only appears over a running
session, so the locked window is what a lock from the main window leaves behind,
not where the window normally opens.

## Backend mapping

| Control | Source |
|---|---|
| Rail storage card | `Index::files()`, `referenced_bytes()` over IPC as `usage` (+ quota when the server reports one — until then there is no bar, only the line) |
| Rail and About facts | `settings_info`: the space's name, server, mode and state folder from the running session, plus this build's version, platform and licence. No password in it — the window that asks for this must not be handed a secret with it |
| Run at login | `get_autostart` / `set_autostart` |
| Show hidden features | `get_prefs` / `set_prefs` (`prefs.json`); gates UI only, stores nothing else |
| Sync folder Open | `open_folder` |
| Change… (server), vault re-pick | `lock` + `close_settings`, then the first-run flow with `list_vaults` |
| Choose folders | folder set from `Index::files()` paths; selection = new per-device rule the agent applies when downloading (server untouched) |
| Pause syncing | `set_paused` — the loop's flag, shipped in M16 S2; the durations still need their resume-at timestamp |
| Auto-lock | new inactivity timer driving `lock` |
| Notifications | new prefs filtering `SyncEvent` for toasts |
| Remove vault | new command: forget config + cache; never deletes remotely |

## New agent concepts (roadmap slice)

1. `Paused` state with durations (pause + resume-at). The flag itself shipped in
   M16 S2; the durations are what is missing.
2. Selective folder sync — per-device subtree selection.
3. Vault auto-lock after inactivity.
4. Notification preferences.
5. Update checker — tracked as M16 work, and the missing half is publishing rather than
   checking: `tauri-plugin-updater` already ships the client side for this window's About
   row (`deb`, `rpm` and AppImage on Linux, `.app` replacement on macOS), but it has
   nothing to fetch until a CI job signs the bundles, cuts a Release with an immutable URL
   and writes the `update.json` manifest. The row stays unwritten until that exists, so it
   never announces a version it cannot install.
6. Files On Demand / placeholder files — also tracked as M16 work (the README's *The M16
   slices*): a hydrate path in the folder loop, and FileProvider / CFAPI for a plain folder
   rather than the FUSE mount. This is what would grow a *Free up space* affordance in the
   Sync Files page.
7. ~~Hidden-tier pref (`Show hidden`)~~ — **shipped** (M16 S1: the pref and the
   controls it gates; M16 S4: its switch, in this window's footer bar).

## Dropped from the OneDrive baseline on purpose

Multi-account (one server, one vault per sync root), Personal Vault (the whole
vault locks), Insider rings, in-window storage management (that is the web Files
UI), pause-on-battery-saver and bandwidth limits (deferred, not rejected). Files
On Demand left this list once placeholder files became M16 work: everything
syncing is a stage this client is at, not a reason never to do it.

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
