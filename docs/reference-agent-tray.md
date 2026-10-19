# Syncbox tray menu — design reference

Version 1. The system tray / menu bar presence of the desktop agent: the
icon click behavior and the right-click menu. The interactive mockup is
[`reference-agent-tray.html`](reference-agent-tray.html) — clicking
*Lock vault* / *Unlock vault…* flips the demo state, and the unlock path
shows the client password window.

Status: **shipped in M16 S5** —
`client/apps/desktop/src-tauri/src/tray.rs` builds one Tauri `TrayIcon` with a
native menu, relabels its rows as the session changes, and paints the glyph's
corner badge from the same state the window reads. It exists where the desktop
provides an indicator host: the backend `dlopen`s libayatana-appindicator *at
runtime* (the build needs no package, so CI builds the tray like everything
else), and where the library is missing the tray is skipped with one line on
stderr and the three windows stay the whole UI — closing the window quits again
in that case, because a hidden window nothing can raise is a window the human
cannot get back.

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

### As shipped (M16 S5)

| Reference row | Shipped? |
|---|---|
| status header (disabled) | ✅ the state in words — *Locked* / *Sync error* / *Paused* / *Syncing…* / *Up to date*, in the window's own order of outranking. No **dot**: a native menu draws no CSS dot, so the dot lives on the icon instead |
| Open Syncbox | ✅ show + unminimise + focus the main window — the same action as a plain icon click, which the tray reports as a `TrayIconEvent::Click` |
| Open sync folder | ✅ the **first** synced folder through `open_folder`, and greyed while nothing is unlocked. This agent syncs the folders a person chose, not a fixed `~/Syncbox/<vault>`, so the row names the one it can name honestly rather than promising the home directory |
| Lock vault | ✅ direct `AppState::lock_vault` — no password, as the rule says |
| Unlock vault… | ✅ raises the unlock window when a session is already waiting on one, the main window's card otherwise. The tray holds no session and asks no password, so it can only take the human to where the asking happens |
| Settings… | ✅ `open_settings_window` — the settings window's second entry point |
| Quit | ✅ `app.exit(0)`, the same exit the gear menu's *Quit* asks for |
| icon badge | ✅ the dot, painted at runtime over the shipped glyph — green idle, yellow syncing, red error, amber paused, grey locked — with a white halo, since the real panel's colour is the desktop's, not ours. It does not **pulse**: a StatusNotifier icon is drawn once per change, so the tray says *Syncing…* in the header row instead |
| `Quit` ≠ closing | ✅ `CloseRequested` on the main window hides it and the loops keep running — **when a tray exists** to raise it again. Without one the close quits, which is what it did before the tray |

Three honest deviations, then: the header carries no dot; *Open sync folder*
names the first chosen folder rather than a fixed path, and greys out with
nothing unlocked; and the syncing badge is steady rather than pulsing. The
menu still has no pause row — OneDrive's durations stayed out on purpose.

## Implementation notes

Tauri `TrayIcon` with a native `Menu`: build once, relabel/re-enable the
lock item as `SyncState` changes. The password field lives only in the
client's own webview — never in the native menu.

That is what `tray.rs` does: nothing in the native menu is a text field, and the
two windows it can raise are the only places a password is ever typed.

## Backend mapping

| Tray element | Code |
|---|---|
| the icon and its menu | `tauri::TrayIconBuilder` with id `main`, `MenuBuilder` rows built once, then `set_text` / `set_enabled` |
| the state it mirrors | `commands::current_status` — the same `Status` the main window's `status` poll answers with, read on the same 2 s rhythm by `tray::watch`, applied with `run_on_main_thread` because menus belong to the event loop's thread |
| the badge | `tray::badge` over `include_image!("icons/32x32.png")`; `dot` picks the colour from `word`, so the text and the colour can never disagree |
| lock / unlock rows | `AppState::lock_vault`; the S3 windows (`unlock`, else `main`) |
| folder row | the running session's first worker's folder, through `open_folder` |
| Settings… / Quit | `open_settings_window`; `app.exit(0)` |
| close-hides-window | `WindowEvent::CloseRequested` in `main.rs`, gated on `tray::Presence` |
| "is a tray even possible" | `tray::indicator_library_present` — the same two sonames, `dlopen`ed the same way `libappindicator-sys` opens them |

## Design sources

- **ownCloud desktop 7.1** — systray menu shape, left-click/right-click
  split. [doc.owncloud.com](https://doc.owncloud.com/desktop/7.1/using.html#the-systray)
- **OneDrive (new sync app)** — its tray menu carries pause durations;
  deliberately not copied.
