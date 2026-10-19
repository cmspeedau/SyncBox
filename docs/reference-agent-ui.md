# Syncbox agent client — design reference

Version 2. This is the visual reference the desktop agent (sync client) is
built toward: window anatomy, first-run flow, everyday states, and how each
element maps to `syncbox-agent`. The interactive mockup is
[`reference-agent-ui.html`](reference-agent-ui.html) — open it in a browser;
the demo buttons switch states, locked vault rows open the unlock window, and
the gear opens the gear menu (Settings… · Pause syncing · Quit). Version 2
adopts the web UI's design language
([`reference-web-ui.md`](reference-web-ui.md)): light tinted headers instead
of the blue gradient bar, no drawn window chrome, 22 px pills.

Status: the **main window and the pause are shipped** — M16 S1 rebuilt
`client/apps/desktop/src/index.html` on this design: tinted bar, gear click
menu, first-run card (connect → pick from server → auto folder → unlock),
per-folder rows with state chips, usage line. M16 S2 added the one new agent
concept: a paused flag the loop honors (`set_paused` over IPC; edits made
while held wait on disk and the resume pass uploads them at once), drawn as
the amber dot, the amber banner and the gear's Pause ⇄ Resume item, whose
label follows the state. Four honest deviations: the list shows the one
space's folders (the client is single-space today, not the multi-vault mock);
the gear carries only what exists (Sync now, Pause syncing, Lock vault, Quit —
Sync now greys out while paused, Settings… joins in S4); the hidden tier's
creation row writes a header on this machine (`create_vault`) — the mock's
name-only-on-server version needs an endpoint the console still owns alone;
and a Recent activity disclosure sits under the list until the settings
window's Notifications page inherits it. Still pending: the separate Unlock
and Settings windows (S3/S4 — the main window hosts the unlock form itself
today, and the one password serves server and vault as the backend has always
done), the tray ([`reference-agent-tray.md`](reference-agent-tray.md), S5,
gated on `libappindicator`), and the drafted dark palette. The
settings window is **not part of this mock** — its design lives in
[`reference-agent-settings.md`](reference-agent-settings.md); the gear in the
main window's bar and the tray menu are its entry points.

## Windows

Two top-level windows in this reference (each its own Tauri
`WebviewWindow`), not overlays — plus the settings window, documented in its
own reference:

| Window | Size | Role |
|---|---|---|
| Main | 420 × 600 | status bar, vault list, usage line |
| Unlock | 340 auto | password entry; the only webview that ever sees the password |

On top of these two windows, the always-present **tray icon** carries a
small native menu — see [`reference-agent-tray.md`](reference-agent-tray.md).

Windows are **content only** — no drawn chrome, no fake title bars. The OS
draws the real one, exactly as the web UI has none.

### Main window anatomy

```text
┌──────────────────────────────┐
│ ● Syncbox    up to date    ⚙ │ status bar (light tint #F1F8FD→#DCEBFA)
├──────────────────────────────┤
│ banners: error / paused      │
│ VAULTS                  pass │
│  ⊙ Files synced 412f·1.8GB   │ vault list — one row per vault:
│    [synced]                  │ icon, name, meta, state chip;
│  ⊙ Photos 12.4k·64GB         │ locked rows dim the icon and add
│    [locked]  [Unlock]        │ an Unlock button
│  ⊙ Studio archive            │
│    [locked]  [Unlock]        │
├──────────────────────────────┤
│ 1.5 GB · 3 vaults     pass 57│ usage line
└──────────────────────────────┘
```

First run replaces everything below the bar with a setup card and the bar
shows only "Syncbox" (no dot, no state, no gear).

### Gear menu

Clicking the gear opens a small dropdown anchored under it — the main
window's only command surface:

| Item | Behaviour |
|---|---|
| Settings… | opens the settings window ([`reference-agent-settings.md`](reference-agent-settings.md)) |
| Pause syncing ⇄ Resume syncing | toggles the paused state (amber dot + banner); label follows the state |
| — divider — | |
| Quit (red `#B3413F`) | exits the agent; tray presence ends |

Menu: white, 1 px `#E6EEF4`, radius 10 px, soft blue shadow, min-width
160 px, rows 8 × 12 px with `#F3F9FD` hover. Closes on any outside click.
The shipped window also carries *Sync now* above the pause and *Lock vault*
below it — real commands the mock's fixture has no use for; *Sync now* greys
out while the loop is paused, since a control that visibly does nothing is
worse than one that says it cannot.
(The tray menu carries the same pause/quit pair natively — see
[`reference-agent-tray.md`](reference-agent-tray.md); this is the window-side
equivalents.)

## First run

1. **Server address + password** — two fields; *Connect* pings the address
   and exchanges the password for a token (`POST /api/v1/auth/token`). It is
   the same secret the web login asks for
   ([`reference-web-login.md`](reference-web-login.md)) — distinct from the
   *vault* password, which only ever appears in the unlock window.
2. **Vault picker** — rows from `list_vaults` (`VaultChoice`: name, size,
   file count; archived hidden). By default this is the **only** way a
   client gets a vault: the out-of-the-box client never creates one, never
   types an id, never picks a folder.
3. **Sync folder — automatic, read-only** — the server's location for the
   space: its **name** under the client's sync root (`~/Syncbox/<vault>`),
   derived by the server at registration and shown as a locked line, nothing
   to type or pick. Renaming the space does not move it.
4. **Save & unlock** → the main window shows the vault list, and the unlock
   window opens for the chosen vault.

### Hidden tier — `Show hidden` in settings

Three advanced behaviours belong to this design but are **absent from every
default screen** until the *Show hidden features* switch is on — a stored
pref; its switch sits in the main window's footer bar until the settings
window's footer inherits it (M16 S4), and the advanced controls it reveals
are designed in
[`reference-agent-settings.md`](reference-agent-settings.md):

| Revealed control | Behaviour |
|---|---|
| `+ New vault` row under the picker rows | creates the space on the server — **name only**, the location derives from the name (same rule as the console) |
| `Enter id by hand` segment on the picker | escape hatch when `list_vaults` cannot reach the server or list what the user knows exists |
| Folder list with *Add another folder* | extra sync folders beside the automatic one; each folder is a copy of the space, changes in any sync to all |

The switch gates controls that really exist, so it is never decorative in
either state. Out of the box the flow draws none of these: *sign in → pick
from server → auto folder → unlock*.

Unlock window: padlock title naming the vault, password field, *Cancel* /
*Unlock & sync* → `unlock` command; the window closes, the row flips to
`synced`, and that vault's sync pass starts. It opens from a locked vault
row (click the row or its *Unlock* button). Closing the main window never
destroys tray presence; closing unlock cancels the attempt.

## Everyday states

| State | Dot | Bar text | Extras |
|---|---|---|---|
| Idle | green | up to date | — |
| Syncing | yellow, pulsing | syncing… | the syncing vault's row carries a progress bar + % |
| Error | red | sync error | red banner with `last_error` + retry countdown |
| Paused | amber | paused | amber banner; edits wait on disk and the resume pass uploads them at once |

Locking is **per-vault**, not a window state: a locked vault dims its icon
(0.55) and shows a grey `locked` chip + **Unlock** in its row; clicking the
row opens the unlock window. The dot tracks the sync engine, never the lock.
Clicking a synced vault's row opens its local folder.

## Backend mapping

| UI element | Source |
|---|---|
| Dot + bar text | `SyncState` (+ `AgentStatus.paused`, which outranks it — an error still outranks the pause) |
| Error banner | `AgentStatus.last_error`, `last_report` |
| Vault list rows | `list_vaults` (`VaultChoice`) + a per-vault lock flag; row click on a synced vault opens the local folder |
| Usage line | `Index::files()`, `Index::referenced_bytes()` — over IPC as the `usage` command since M16 S1 |
| Pass counter | `AgentStatus.passes` |
| First run: server password | `POST /api/v1/auth/token` → bearer token (same secret as the web login) |
| Unlock window → | `unlock` command; main window never touches the password |
| Settings window (gear menu, tray) | its own reference: [`reference-agent-settings.md`](reference-agent-settings.md) |
| Gear menu: pause / resume | the `set_paused` command — the loop's flag, not `SyncState` |
| Gear menu: quit | process exit (no IPC round-trip needed) |

## Design tokens

Shared with [`reference-web-ui.md`](reference-web-ui.md): brand `#0082C9`,
brand-dark `#006AA3` (CTA pills), header tint gradient 160°
`#F1F8FD → #DCEBFA` (the web sidebar's gradient), text `#272833`, muted
`#7A8694`, row hover `#F3F9FD`, focus ring `rgba(0,130,201,.2)`. State dot:
idle `#16A34A`, syncing `#F59E0B` (pulsing), error `#DC2626`, paused
`#D97706`. Chips (the web vault-card chips): synced `#E8F3FB` on `#006AA3`
text, locked `#EEF1F4` on `#66727E` text.

Geometry: window radius 12 px (OS title bar sits above — the design has no
chrome), pills 22 px, vault rows 8 px radius; state dot 9 px with a 3 px
white halo; locked row icon dim 0.55.

Dark mode follows the **drafted dark palette** in
[`reference-web-ui.md`](reference-web-ui.md) — drafted, not shippable until
a build renders it.

## Design sources

- **Syncthing** — state-first header, per-item activity rows.
  [Commons, MPL-2.0](https://commons.wikimedia.org/wiki/File:Syncthing-screenshot-dark.png)
- **ownCloud desktop 7.1** — settings as its own window, server-first setup.
  [doc.owncloud.com](https://doc.owncloud.com/desktop/7.1/using.html)
- **OneDrive (new sync app)** — settings window baseline (storage header,
  Sync-and-back-up / Account / Notifications / About pages).
  [Microsoft Support](https://support.microsoft.com/en-us/onedrive/how-to-access-onedrive-settings)
