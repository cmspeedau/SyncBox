# Syncbox tray menu — design reference

Version 1. The system tray / menu bar presence of the desktop agent: the
icon click behavior and the right-click menu. The interactive mockup is
[`reference-agent-tray.html`](reference-agent-tray.html) — clicking
*Lock vault* / *Unlock vault…* flips the demo state, and the unlock path
shows the client password window.

Status: design reference only. Nothing in `client/` implements it yet.

## Behavior rules

1. **Plain icon click opens the agent UI** (show + focus the main window —
   same action as *Open Syncbox*). Right-click opens the menu; on macOS any
   click on the menu bar item opens it. ownCloud uses exactly this split.
2. **Tray actions never ask for a password; only the client asks, and only
   to unlock.** Locking just clears the derived keys, so *Lock vault* acts
   directly from the menu; when the vault *is locked*, the item becomes
   *Unlock vault…* and raises the client with the password window.

## Menu (top to bottom)

| Item | State | Action |
|---|---|---|
| status header (disabled) | always | dot + text mirroring `SyncState` |
| Open Syncbox | always | show + focus main window (= icon click) |
| Open sync folder | always | reveal `~/Syncbox/<vault>` in the OS file manager |
| Lock vault | unlocked | direct `lock`; sync stops until unlock |
| Unlock vault… | locked | focus client + open the unlock window (`unlock` + start sync) |
| Settings… | always | open the Settings window |
| Quit | always | exit the agent process |

Five rows on purpose — OneDrive keeps pause-with-durations in its tray
menu; here pausing lives in Settings (with durations) and the main window.

`Quit` ≠ closing the window: closing keeps sync and tray running, Quit
exits the process. Local files and server data are untouched either way.

## Icon

The Syncbox glyph with a status badge mirroring `SyncState`: green idle,
yellow pulsing syncing, red error, grey locked. The disabled header row
spells the same state out in text.

## Implementation notes

Tauri `TrayIcon` with a native `Menu`: build once, relabel/re-enable the
lock item as `SyncState` changes. The password field lives only in the
client's own webview — never in the native menu.

## Design sources

- **ownCloud desktop 7.1** — systray menu shape, left-click/right-click
  split. [doc.owncloud.com](https://doc.owncloud.com/desktop/7.1/using.html#the-systray)
- **OneDrive (new sync app)** — its tray menu carries pause durations;
  deliberately not copied.
