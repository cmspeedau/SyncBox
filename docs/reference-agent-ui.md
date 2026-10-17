# Syncbox agent client — design reference

Version 1. This is the visual reference the desktop agent (sync client) is
built toward: window anatomy, first-run flow, everyday states, and how each
element maps to `syncbox-agent`. The interactive mockup is
[`reference-agent-ui.html`](reference-agent-ui.html) — open it in a browser;
the demo buttons switch states, the gear and *Unlock vault* open their
windows.

Status: design reference only. Nothing in `client/` implements it yet. The
settings window shown here is a placeholder — its real design lives in
[`reference-agent-settings.md`](reference-agent-settings.md).

## Windows

Three separate top-level windows (each its own Tauri `WebviewWindow`), not
overlays:

| Window | Size | Role |
|---|---|---|
| Main | 420 × 600 | status bar, activity feed, vault button |
| Unlock | 340 auto | password entry; the only webview that ever sees the password |
| Settings | 340 auto | server/folder/autostart/pause — superseded by [`reference-agent-settings.md`](reference-agent-settings.md) |

On top of these three windows, the always-present **tray icon** carries a
small native menu — see [`reference-agent-tray.md`](reference-agent-tray.md).

### Main window anatomy

```text
┌──────────────────────────────┐
│ ● Files synced   locked    ⚙ │ status bar (gradient #006AA3→#0B8BD2)
├──────────────────────────────┤
│ banners: error / paused      │
│ LAST SYNCED                  │
│  ↑ sunrise.jpg    2 min ago  │ activity feed
│  ↓ budget.xlsx    2 min ago  │
│  ! notes.md conflict yest.   │
├──────────────────────────────┤
│ 1.8 GB · 412 files    pass 57│ usage line
│ [ 🔒 Unlock vault ]          │ vault button (full-width pill)
└──────────────────────────────┘
```

First run replaces everything below the bar with a setup card and the bar
shows only "Syncbox" (no dot, no state, no gear).

## First run

1. **Server address** — one field; *Connect* pings it.
2. **Vault picker** — rows from `list_vaults` (`VaultChoice`: name, size,
   file count; archived hidden).
3. **Sync folder** — defaults to `~/Syncbox/<vault>`.
4. **Save & unlock** → main window in Locked state, unlock window opens.

Unlock window: padlock title, password field, *Cancel* / *Unlock & sync* →
`unlock` command, window closes, sync pass starts. Closing the main window
never destroys tray presence; closing unlock cancels the attempt.

## Everyday states

| State | Dot | Bar text | Extras |
|---|---|---|---|
| Idle | green | up to date | — |
| Syncing | yellow, pulsing | syncing… | live feed rows with per-file progress bars |
| Error | red | sync error | red banner with `last_error` + retry countdown |
| Paused | amber | paused | amber banner; local edits queue |
| Locked | grey | locked | feed stays visible (opacity .72), heading reads "Last synced", button becomes *Unlock vault* |

## Backend mapping

| UI element | Source |
|---|---|
| Dot + bar text | `SyncState` (+ a Paused flag — the one new agent concept) |
| Error banner | `AgentStatus.last_error`, `last_report` |
| Activity feed | `SyncEvent` / `history()`; per-file progress rows are a later step |
| Usage line | `Index::files()`, `Index::referenced_bytes()` (not over IPC yet) |
| Pass counter | `AgentStatus.passes` |
| Unlock window → | `unlock` command; main window never touches the password |
| Settings: autostart | `get_autostart` / `set_autostart` |
| Settings: vault switch | reopens the first-run picker |

## Design tokens

Shared with [`reference-web-ui.md`](reference-web-ui.md): brand `#0082C9`,
brand-dark `#006AA3` (also the gradient start, end `#0B8BD2`), text
`#272833`, muted `#7A8694`, row hover `#F3F9FD`, focus ring
`rgba(0,130,201,.2)`.

Geometry: window radius 12 px, OS title bar 30 px (`#E9EEF3`), pills 20–24
px, feed rows 8 px; state dot 9 px with a 3 px white halo. Locked feed dim
factor 0.72.

## Design sources

- **Syncthing** — state-first header, per-item activity rows.
  [Commons, MPL-2.0](https://commons.wikimedia.org/wiki/File:Syncthing-screenshot-dark.png)
- **ownCloud desktop 7.1** — settings as its own window, server-first setup.
  [doc.owncloud.com](https://doc.owncloud.com/desktop/7.1/using.html)
- **OneDrive (new sync app)** — settings window baseline (storage header,
  Sync-and-back-up / Account / Notifications / About pages).
  [Microsoft Support](https://support.microsoft.com/en-us/onedrive/how-to-access-onedrive-settings)
