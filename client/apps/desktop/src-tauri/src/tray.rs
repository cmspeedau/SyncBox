//! The tray: the agent's presence when no window is open, built to
//! `docs/reference-agent-tray.md`.
//!
//! Two rules shape it. **A plain click opens the agent UI** and the menu comes
//! from a right-click, so the icon is a handle on the window, not a second status
//! display. And **`Quit` is not closing the window**: closing hides the main
//! window and sync keeps running, while `Quit` ends the process. That second rule
//! is why [`install`] reports whether it succeeded — the shell hides a window only
//! when it can bring it back, so on a machine with no indicator host closing
//! quits, exactly as it did before the tray existed.
//!
//! The menu is built once and relabelled as the session changes, which is what the
//! reference asks for and what a native menu can do without flicker: the status
//! row's text, the lock row's label, the folder row's grey-out, the tooltip and
//! the icon's badge all follow the same [`Status`] the main window polls, read on
//! the same two-second rhythm by [`watch`]. No tray action asks for a password —
//! the reference lets only the client ask, and only to unlock — so the row that
//! reads *Unlock vault…* raises whichever window does the asking.
//!
//! ## Why the library is probed, not assumed
//!
//! `tauri`'s `tray-icon` feature builds with no system package at all: the binding
//! opens `libayatana-appindicator3.so.1` (or the legacy `libappindicator3.so.1`)
//! with `dlopen` the first time a tray is made, and panics if neither is there.
//! The build therefore works everywhere and the *runtime* is the question, which
//! is what [`indicator_library_present`] answers — with the same two names opened
//! the same way, so the answer cannot disagree with the crate's own.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tauri::image::Image;
use tauri::menu::{MenuBuilder, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager as _, Wry};

use crate::commands::current_status;
use crate::dto::Status;
use crate::state::Shared;

/// The tray's id, so the watch thread can find the icon again through the handle.
const TRAY_ID: &str = "main";

/// Menu row ids, in the reference's order: a status header, then the window and
/// its folder, then the session's actions, then quitting.
const ID_STATUS: &str = "status";
const ID_OPEN: &str = "open";
const ID_FOLDER: &str = "folder";
const ID_LOCK: &str = "lock";
const ID_SETTINGS: &str = "settings";
const ID_QUIT: &str = "quit";

/// How often the tray re-reads the session. The main window polls on the same
/// interval, so the two never disagree by more than a tick.
const WATCH_INTERVAL: Duration = Duration::from_secs(2);

/// The glyph the badge is painted onto, at the size the tray asks for.
const ICON: Image<'static> = tauri::include_image!("icons/32x32.png");

/// Whether the tray was built. The main window hides itself on close only while
/// this is set: a trayless machine keeps the old behaviour, where closing the
/// window ends the app, rather than ending up with a window nothing can raise.
#[derive(Clone, Default)]
pub struct Presence(Arc<AtomicBool>);

impl Presence {
    #[must_use]
    pub fn hiding_on_close(&self) -> bool {
        self.0.load(Ordering::Relaxed)
    }

    fn set_present(&self) {
        self.0.store(true, Ordering::Relaxed);
    }
}

/// Builds the tray, or says why it could not be built.
///
/// On success the presence flag goes up and the watch thread starts. On failure —
/// no indicator library on this machine, or a panel that refuses the icon — the
/// flag stays down and the three windows remain the whole UI, which is the honest
/// fallback rather than a half-present icon.
pub fn install(app: &AppHandle, shared: &Shared, presence: &Presence) {
    if !indicator_library_present() {
        eprintln!(
            "tray: no app-indicator library found — install libayatana-appindicator \
             and restart Syncbox to get the tray"
        );
        return;
    }

    // Built up front so a failure is a failure before anything is on screen.
    let rows = (|| -> tauri::Result<[MenuItem<Wry>; 6]> {
        Ok([
            MenuItem::<Wry>::with_id(app, ID_STATUS, "Locked", false, None::<&str>)?,
            MenuItem::<Wry>::with_id(app, ID_OPEN, "Open Syncbox", true, None::<&str>)?,
            MenuItem::<Wry>::with_id(app, ID_FOLDER, "Open sync folder", false, None::<&str>)?,
            MenuItem::<Wry>::with_id(app, ID_LOCK, "Unlock vault…", true, None::<&str>)?,
            MenuItem::<Wry>::with_id(app, ID_SETTINGS, "Settings…", true, None::<&str>)?,
            MenuItem::<Wry>::with_id(app, ID_QUIT, "Quit", true, None::<&str>)?,
        ])
    })();
    let [status_row, open_row, folder_row, lock_row, settings_row, quit_row] = match rows {
        Ok(rows) => rows,
        Err(err) => {
            eprintln!("tray: could not build the menu: {err}");
            return;
        }
    };

    let built = (|| -> tauri::Result<()> {
        let menu = MenuBuilder::new(app)
            .items(&[&status_row])
            .separator()
            .items(&[&open_row, &folder_row])
            .separator()
            .items(&[&lock_row, &settings_row])
            .separator()
            .items(&[&quit_row])
            .build()?;

        TrayIconBuilder::with_id(TRAY_ID)
            .menu(&menu)
            // Left click is the reference's "open the agent UI"; the menu is what
            // a right-click (or the panel's own menu affordance) brings up.
            .show_menu_on_left_click(false)
            .icon(badge(&locked_status()))
            .tooltip("Syncbox — locked")
            .on_tray_icon_event(|tray, event| {
                // A plain (left) click is the reference's "open the agent UI".
                // The button and state are checked because a right-click, which
                // is the menu's own gesture, arrives through the same variant on
                // some backends — and raising the window behind a menu the human
                // is reading is not what the split means.
                if matches!(
                    event,
                    TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    }
                ) {
                    show_main(tray.app_handle());
                }
            })
            .on_menu_event({
                let shared = Arc::clone(shared);
                move |app, event| match event.id().as_ref() {
                    ID_OPEN => show_main(app),
                    ID_FOLDER => open_sync_folder(app, &shared),
                    ID_LOCK => lock_or_raise(app, &shared),
                    ID_SETTINGS => {
                        let _ = crate::commands::open_settings_window(app.clone());
                    }
                    ID_QUIT => app.exit(0),
                    _ => {}
                }
            })
            .build(app)?;
        Ok(())
    })();

    if built.is_err() {
        // A panel that takes the icon and then refuses it is rare but real; the
        // windows carry on regardless.
        eprintln!("tray: this desktop took no icon; the windows are the UI");
        return;
    }

    presence.set_present();
    watch(
        app.clone(),
        Arc::clone(shared),
        status_row,
        folder_row,
        lock_row,
    );
}

/// The window the tray exists to reach: show it, wake it, focus it.
fn show_main(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// The reference's *Open sync folder*. This agent syncs whole folders the human
/// chose, so "the sync folder" is the first of them. While nothing is unlocked
/// there is no folder to name, and the row is greyed rather than promising the
/// home directory — see [`watch`], which keeps the grey-out honest.
fn open_sync_folder(app: &AppHandle, shared: &Shared) {
    let folder = shared.lock().ok().and_then(|state| {
        state
            .workers()
            .first()
            .map(|worker| worker.folder().to_path_buf())
    });
    let Some(folder) = folder else {
        eprintln!("tray: no sync folder to open — no space is unlocked");
        return;
    };
    if let Err(err) = crate::commands::open_folder(app.clone(), folder.display().to_string()) {
        eprintln!("tray: {err}");
    }
}

/// *Lock vault* stops the loops straight from the menu, because locking only
/// clears the derived keys. *Unlock vault…* asks for nothing here: it raises the
/// unlock window when a session is waiting on one, and the main window's card —
/// which is where a space is chosen and unlocked — otherwise.
fn lock_or_raise(app: &AppHandle, shared: &Shared) {
    match shared.lock() {
        // Locking clears the derived keys and stops the loops: no password, no
        // confirmation, exactly as the window's gear menu does it. And nothing
        // else — a lock raises no window.
        Ok(mut state) if !state.workers().is_empty() => {
            state.lock_vault();
            return;
        }
        Ok(_) => {}
        // A poisoned lock: raising the window is the one thing still worth doing.
        Err(_) => return show_main(app),
    }
    // A session waiting on its vault password has that window open already; the
    // human is answering it, and raising it is the whole action.
    let label = if app.get_webview_window("unlock").is_some() {
        "unlock"
    } else {
        "main"
    };
    if let Some(window) = app.get_webview_window(label) {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    } else {
        show_main(app);
    }
}

/// Every two seconds, mirror the session onto the icon: the badge's colour, the
/// tooltip, the status row's word, the lock row's label, and whether the folder
/// row has a folder behind it. Native menus relabel rather than rebuild, so this
/// reads as the state changing rather than the menu changing.
fn watch(
    app: AppHandle,
    shared: Shared,
    status_row: MenuItem<Wry>,
    folder_row: MenuItem<Wry>,
    lock_row: MenuItem<Wry>,
) {
    std::thread::spawn(move || loop {
        std::thread::sleep(WATCH_INTERVAL);
        let status = match shared.lock() {
            Ok(state) => current_status(&state),
            // A poisoned lock means a loop already panicked; the window's own
            // poll will surface that. Saying nothing here beats saying it twice.
            Err(_) => return,
        };
        let (status_row, folder_row, lock_row) =
            (status_row.clone(), folder_row.clone(), lock_row.clone());
        // Reading the session is cheap from any thread; relabelling a menu and
        // swapping an icon belong to the event loop's thread, so this thread
        // posts what it found rather than touching the desktop itself.
        let for_main_thread = app.clone();
        let posted = app.run_on_main_thread(move || {
            let word = word(&status);
            let _ = status_row.set_text(word);
            let _ = lock_row.set_text(if status.unlocked {
                "Lock vault"
            } else {
                "Unlock vault…"
            });
            let _ = folder_row.set_enabled(!status.folders.is_empty());
            if let Some(tray) = for_main_thread.tray_by_id(TRAY_ID) {
                let _ = tray.set_tooltip(Some(format!("Syncbox — {word}")));
                let _ = tray.set_icon(Some(badge(&status)));
            }
        });
        if posted.is_err() {
            // The event loop is gone, so the app is on its way out.
            return;
        }
    });
}

/// The state in the words the main window uses, in its order of outranking: an
/// error beats a pause, a pause beats the state underneath it.
fn word(status: &Status) -> &'static str {
    if !status.unlocked {
        "Locked"
    } else if status.last_error.is_some() {
        "Sync error"
    } else if status.paused {
        "Paused"
    } else if status.state == "syncing" {
        "Syncing…"
    } else {
        "Up to date"
    }
}

/// The badge the reference draws: the glyph with a dot in the corner, coloured as
/// the window colours its state dot.
fn badge(status: &Status) -> Image<'static> {
    let (rgba, width, height) = badge_pixels(
        ICON.rgba().to_vec(),
        ICON.width(),
        ICON.height(),
        dot(status),
    );
    Image::new_owned(rgba, width, height)
}

/// The dot's colour for a status: idle green, syncing yellow, error red, paused
/// amber, locked grey — the window's own tokens, so the tray and the bar agree.
fn dot(status: &Status) -> [u8; 3] {
    match word(status) {
        "Locked" => [0x97, 0xa3, 0xaf],
        "Sync error" => [0xdc, 0x26, 0x26],
        "Paused" => [0xd9, 0x77, 0x06],
        "Syncing…" => [0xf5, 0x9e, 0x0b],
        _ => [0x16, 0xa3, 0x4a],
    }
}

/// Paints `color` as a ringed dot in the bottom-right corner of an RGBA buffer: a
/// disc a fifth of the icon across, with a one-pixel white halo so it reads
/// against the glyph's own tint — the same halo the window's dot has.
///
/// Pure, so the drawing is checkable with no display on.
fn badge_pixels(mut rgba: Vec<u8>, width: u32, height: u32, color: [u8; 3]) -> (Vec<u8>, u32, u32) {
    let radius = i32::try_from(width / 8).unwrap_or(3).max(3);
    let centre_x = i32::try_from(width).unwrap_or(1) - radius - 1;
    let centre_y = i32::try_from(height).unwrap_or(1) - radius - 1;
    let outer = radius + 1; // the halo's edge
    for y in 0..height {
        for x in 0..width {
            let dx = i32::try_from(x).unwrap_or(0) - centre_x;
            let dy = i32::try_from(y).unwrap_or(0) - centre_y;
            let squared = dx * dx + dy * dy;
            let inside = squared <= radius * radius;
            let in_halo = !inside && squared <= outer * outer;
            if !inside && !in_halo {
                continue;
            }
            let Some(pixel) =
                rgba.get_mut(((y * width + x) * 4) as usize..((y * width + x) * 4 + 4) as usize)
            else {
                continue;
            };
            let [r, g, b] = if inside { color } else { [0xff, 0xff, 0xff] };
            pixel[0] = r;
            pixel[1] = g;
            pixel[2] = b;
            pixel[3] = 0xff;
        }
    }
    (rgba, width, height)
}

/// A status that reads as "nothing running", for the icon before the first poll.
fn locked_status() -> Status {
    Status {
        state: "locked",
        paused: false,
        unlocked: false,
        vault_id: None,
        last_sync_unix: None,
        last_error: None,
        passes: 0,
        folders: Vec::new(),
    }
}

/// Whether the indicator library the tray backend opens is actually there.
///
/// The names and the mechanism match `libappindicator-sys` exactly: it tries the
/// versioned ayatana soname, then the legacy one, and panics past both. So this is
/// not a guess about what a tray needs — it is the same question, asked first.
fn indicator_library_present() -> bool {
    ["libayatana-appindicator3.so.1", "libappindicator3.so.1"]
        .iter()
        .any(|name| unsafe { libloading::Library::new(name).is_ok() })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(unlocked: bool, error: Option<&str>, paused: bool, state: &'static str) -> Status {
        Status {
            state,
            paused,
            unlocked,
            vault_id: None,
            last_sync_unix: None,
            last_error: error.map(str::to_string),
            passes: 0,
            folders: Vec::new(),
        }
    }

    #[test]
    fn the_word_follows_the_window_s_order_of_outranking() {
        assert_eq!(word(&status(false, None, false, "locked")), "Locked");
        assert_eq!(
            word(&status(true, Some("boom"), true, "idle")),
            "Sync error"
        );
        assert_eq!(word(&status(true, None, true, "idle")), "Paused");
        assert_eq!(word(&status(true, None, false, "syncing")), "Syncing…");
        assert_eq!(word(&status(true, None, false, "idle")), "Up to date");
    }

    #[test]
    fn each_colour_follows_its_word() {
        // Otherwise the badge and the text would be lying about different things.
        assert_eq!(
            dot(&status(false, None, false, "locked")),
            [0x97, 0xa3, 0xaf]
        );
        assert_eq!(
            dot(&status(true, Some("boom"), false, "idle")),
            [0xdc, 0x26, 0x26]
        );
        assert_eq!(dot(&status(true, None, true, "idle")), [0xd9, 0x77, 0x06]);
        assert_eq!(
            dot(&status(true, None, false, "syncing")),
            [0xf5, 0x9e, 0x0b]
        );
        assert_eq!(dot(&status(true, None, false, "idle")), [0x16, 0xa3, 0x4a]);
    }

    #[test]
    fn the_badge_paints_a_ringed_dot_and_leaves_the_glyph_alone() {
        let width = 32;
        let height = 32;
        let base = vec![0u8; (width * height * 4) as usize];
        let (painted, w, h) = badge_pixels(base, width, height, [0x16, 0xa3, 0x4a]);
        assert_eq!((w, h), (32, 32));

        let pixel = |x: u32, y: u32| {
            let i = ((y * width + x) * 4) as usize;
            [painted[i], painted[i + 1], painted[i + 2], painted[i + 3]]
        };
        // The dot's centre takes the state colour, fully opaque. At 32 px the
        // disc is 4 px in radius centred at (27, 27): four steps out is still
        // the dot, five is the white halo, six is the untouched glyph again.
        assert_eq!(pixel(27, 27), [0x16, 0xa3, 0x4a, 0xff]);
        assert_eq!(pixel(23, 27), [0x16, 0xa3, 0x4a, 0xff]);
        assert_eq!(pixel(22, 27), [0xff, 0xff, 0xff, 0xff]);
        assert_eq!(pixel(21, 27), [0, 0, 0, 0]);
        // The far corners are untouched: a badge is a corner, not a band.
        assert_eq!(pixel(0, 0), [0, 0, 0, 0]);
        assert_eq!(pixel(16, 0), [0, 0, 0, 0]);
    }

    #[test]
    fn the_shipped_glyph_is_the_size_the_badge_assumes() {
        assert_eq!(ICON.width(), 32);
        assert_eq!(ICON.height(), 32);
    }
}
