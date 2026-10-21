//! The `#[tauri::command]` surface. Each command is thin: read the shared state (a
//! cheap lock) or, for anything that blocks — unlocking (Argon2id), the network —
//! hand the work to a blocking thread so the webview never stalls.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tauri::{command, AppHandle, Manager as _, State};

use tauri_plugin_autostart::ManagerExt as _;
use tauri_plugin_opener::OpenerExt as _;

use syncbox_agent::{index_path_for, SyncEvent};
use syncbox_index::{Index as _, SqliteIndex};
use syncbox_transport::{Client, UreqHttp};

use crate::dto::{self, Activity, FolderSnapshot, Status, VaultChoice, VaultSettings};
use crate::prefs::{self, Prefs};
use crate::spaces::{self, Space};
use crate::state::{AppState, Shared};

/// The current sync status (state, last pass, any error), aggregated across the
/// folder workers.
#[command]
pub fn status(shared: State<'_, Shared>) -> Result<Status, String> {
    let state = shared.lock().map_err(|e| e.to_string())?;
    Ok(current_status(&state))
}

/// The spaces this machine has opened before, newest first, with the running one
/// marked. Metadata only — nothing here is a credential — so the main window can
/// draw a locked row for each and ask for the server password only when one is
/// clicked.
#[command]
pub fn saved_spaces(shared: State<'_, Shared>) -> Result<Vec<dto::SavedSpace>, String> {
    let state = shared.lock().map_err(|e| e.to_string())?;
    Ok(dto::saved_spaces(state.known(), state.running()))
}

/// The recent sync activity feed across folders, oldest first.
#[command]
pub fn activity(shared: State<'_, Shared>) -> Result<Vec<Activity>, String> {
    let state = shared.lock().map_err(|e| e.to_string())?;
    let mut entries: Vec<(String, SyncEvent)> = Vec::new();
    for worker in state.workers() {
        let folder = worker.folder().display().to_string();
        for event in worker.history() {
            entries.push((folder.clone(), event));
        }
    }
    // One feed for the vault: merge the folders' histories by time, newest last,
    // and cap so a long-running app does not grow an unbounded list.
    entries.sort_by_key(|(_, event)| match event {
        SyncEvent::Done { at_unix, .. } | SyncEvent::Failed { at_unix, .. } => *at_unix,
    });
    if entries.len() > HISTORY_LIMIT {
        entries.drain(..entries.len() - HISTORY_LIMIT);
    }
    Ok(dto::activity(&entries))
}

/// How many activity rows the merged feed keeps.
const HISTORY_LIMIT: usize = 50;

/// Unlocks the space and starts a background loop per folder, with the vault
/// password the caller collected. The main window only calls this for a sync
/// space, whose password it does not have and which has no header to unlock;
/// a vault goes through [`open_unlock_window`] instead, so its password never
/// reaches the main window's webview.
///
/// Blocks on key derivation, so it runs off the main thread.
#[command]
pub async fn unlock(
    app: AppHandle,
    shared: State<'_, Shared>,
    settings: VaultSettings,
    vault_password: String,
) -> Result<Status, String> {
    let shared = Arc::clone(shared.inner());
    let (session, name) = settings.into_parts();
    let path = spaces_path(&app);
    tauri::async_runtime::spawn_blocking(move || {
        let mut state = shared.lock().map_err(|e| e.to_string())?;
        let remembered = Space::from_session(&session, &name);
        state.unlock_vault(session, name, vault_password)?;
        // The session works whether or not the registry can be written, so a
        // failed save costs the next launch's locked row, never this unlock.
        state.remember(remembered);
        if let Ok(path) = path {
            let _ = spaces::save(&path, state.known());
        }
        Ok(current_status(&state))
    })
    .await
    .map_err(|e| format!("unlock task failed: {e}"))?
}

/// Opens the space's unlock window: a top-level window whose own webview is the
/// only place the vault password is typed.
///
/// The session it will unlock is held in this process, not in the window, and
/// the window learns nothing but the space's name — so nothing secret crosses
/// the IPC boundary until the human types it. A sync space has no header to
/// unlock and is refused here: its caller unlocks directly.
#[command]
pub fn open_unlock_window(
    app: AppHandle,
    shared: State<'_, Shared>,
    settings: VaultSettings,
) -> Result<(), String> {
    let (session, name) = settings.into_parts();
    if session.folders.is_empty() {
        return Err("add at least one folder to keep in sync".into());
    }
    if !session.mode.is_encrypted() {
        return Err("a sync space has no vault password to ask for".into());
    }
    shared
        .lock()
        .map_err(|e| e.to_string())?
        .set_pending(session, name.clone());
    show_unlock_window(&app, &Arc::clone(shared.inner()), &name)
}

/// Unlocks the pending session with the password the unlock window collected,
/// then closes that window. Blocks on key derivation, so off the main thread.
///
/// A failed attempt puts the session back, so the window's retry works; a
/// successful one leaves no pending state behind.
#[command]
pub async fn unlock_pending(
    app: AppHandle,
    shared: State<'_, Shared>,
    password: String,
) -> Result<Status, String> {
    let shared = Arc::clone(shared.inner());
    let path = spaces_path(&app);
    let outcome = tauri::async_runtime::spawn_blocking(move || {
        let mut state = shared.lock().map_err(|e| e.to_string())?;
        let Some((session, name)) = state.take_pending() else {
            return Err("nothing is waiting to be unlocked".to_string());
        };
        let remembered = Space::from_session(&session, &name);
        match state.unlock_vault(session.clone(), name.clone(), password) {
            Ok(()) => {
                state.remember(remembered);
                // Best effort: see `unlock`.
                if let Ok(path) = path {
                    let _ = spaces::save(&path, state.known());
                }
                Ok(current_status(&state))
            }
            Err(err) => {
                // Hand it back: the human is still looking at the window.
                state.set_pending(session, name);
                Err(err)
            }
        }
    })
    .await
    .map_err(|e| format!("unlock task failed: {e}"))?;
    if outcome.is_ok() {
        close_unlock_window(&app);
    }
    outcome
}

/// The pending unlock, or `null`: which space the open window is for. Carries
/// no secret, so the unlock window may title itself with it and the main window
/// may tell "waiting for the password" from "ready to go".
#[command]
pub fn pending_unlock(shared: State<'_, Shared>) -> Result<Option<dto::PendingInfo>, String> {
    let state = shared.lock().map_err(|e| e.to_string())?;
    Ok(state.pending_info().map(|(name, mode)| dto::PendingInfo {
        name: name.to_owned(),
        mode: dto::mode_str(mode),
    }))
}

/// Drops a pending unlock and closes its window: the unlock window's Cancel,
/// and the main window's way back to the setup card.
#[command]
pub fn cancel_unlock(app: AppHandle, shared: State<'_, Shared>) -> Result<(), String> {
    shared.lock().map_err(|e| e.to_string())?.clear_pending();
    close_unlock_window(&app);
    Ok(())
}

/// The unlock window's label. One window, reused: the pending session behind it
/// is a single slot, so a second window would have nothing to unlock.
const UNLOCK_WINDOW: &str = "unlock";

/// The window's title, in the mock's wording: the space's name in quotes.
fn unlock_title(name: &str) -> String {
    format!("Unlock “{name}”")
}

/// Shows the unlock window, focusing the one already open rather than opening a
/// second.
fn show_unlock_window(app: &AppHandle, shared: &Shared, name: &str) -> Result<(), String> {
    if let Some(window) = app.get_webview_window(UNLOCK_WINDOW) {
        window
            .set_title(&unlock_title(name))
            .map_err(|e| e.to_string())?;
        window.show().map_err(|e| e.to_string())?;
        return window.set_focus().map_err(|e| e.to_string());
    }
    let window = tauri::WebviewWindowBuilder::new(
        app,
        UNLOCK_WINDOW,
        tauri::WebviewUrl::App("unlock.html".into()),
    )
    .title(unlock_title(name))
    .inner_size(340.0, 258.0)
    .resizable(false)
    .minimizable(false)
    .maximizable(false)
    .center()
    .build()
    .map_err(|e| format!("could not open the unlock window: {e}"))?;

    // Closing the window — its title bar's X, not only the Cancel button —
    // gives the attempt up. The pending session carries the server password and
    // must not outlive the window that was going to use it.
    let shared = Arc::clone(shared);
    window.on_window_event(move |event| {
        if matches!(event, tauri::WindowEvent::Destroyed) {
            if let Ok(mut state) = shared.lock() {
                state.clear_pending();
            }
        }
    });
    Ok(())
}

/// Closes the unlock window if it is open. Its absence is not an error: the
/// human may have closed it themselves.
fn close_unlock_window(app: &AppHandle) {
    if let Some(window) = app.get_webview_window(UNLOCK_WINDOW) {
        let _ = window.close();
    }
}

/// The settings window's label — one window, reused.
const SETTINGS_WINDOW: &str = "settings";

/// The settings window's one read: what this build is, and which space the
/// shell is running. Nothing in it is a secret — a window that can ask for this
/// must not be handed a password with it.
#[command]
pub fn settings_info(shared: State<'_, Shared>) -> Result<dto::SettingsInfo, String> {
    let state = shared.lock().map_err(|e| e.to_string())?;
    Ok(dto::settings_info(state.running()))
}

/// Opens the settings window from the gear menu. The reference gives it a window
/// of its own rather than a page in the main one, so it is a second top-level
/// window with its own webview, sized as the mock does.
#[command]
pub fn open_settings_window(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window(SETTINGS_WINDOW) {
        window.show().map_err(|e| e.to_string())?;
        return window.set_focus().map_err(|e| e.to_string());
    }
    tauri::WebviewWindowBuilder::new(
        &app,
        SETTINGS_WINDOW,
        tauri::WebviewUrl::App("settings.html".into()),
    )
    .title("Syncbox — Settings")
    .inner_size(640.0, 560.0)
    .min_inner_size(520.0, 420.0)
    .center()
    .build()
    .map_err(|e| format!("could not open the settings window: {e}"))?;
    Ok(())
}

/// Closes the settings window and hands focus back to the main window. The
/// window's *Change…* controls run it after `lock`: the main window's card is
/// where a space is chosen again, so the window that started it steps aside.
#[command]
pub fn close_settings(app: AppHandle) -> Result<(), String> {
    if let Some(window) = app.get_webview_window(SETTINGS_WINDOW) {
        window.close().map_err(|e| e.to_string())?;
    }
    if let Some(main) = app.get_webview_window("main") {
        main.set_focus().map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Locks the vault: stops the loops and drops the keys.
#[command]
pub fn lock(shared: State<'_, Shared>) -> Result<Status, String> {
    let mut state = shared.lock().map_err(|e| e.to_string())?;
    state.lock_vault();
    Ok(dto::locked())
}

/// Asks every loop to run a pass now (non-blocking) and returns the current
/// status. Refused while the loops are held: a "sync now" that visibly did
/// nothing would be a dead control, so the window offers resume instead.
#[command]
pub fn sync_now(shared: State<'_, Shared>) -> Result<Status, String> {
    let state = shared.lock().map_err(|e| e.to_string())?;
    if state.workers().is_empty() {
        return Err("the vault is locked — unlock it first".into());
    }
    if state.is_paused() {
        return Err("syncing is paused — resume it first".into());
    }
    for worker in state.workers() {
        worker.request_sync();
    }
    Ok(current_status(&state))
}

/// Holds or releases every loop's passes. Nothing on disk changes: edits made
/// while held wait in the folders until the resume pass reads them.
#[command]
pub fn set_paused(shared: State<'_, Shared>, paused: bool) -> Result<Status, String> {
    let mut state = shared.lock().map_err(|e| e.to_string())?;
    if state.workers().is_empty() {
        return Err("the vault is locked — unlock it first".into());
    }
    state.set_paused(paused);
    Ok(current_status(&state))
}

/// The aggregated status of a state's workers, or the locked shape when none run.
pub(crate) fn current_status(state: &AppState) -> Status {
    let workers = state.workers();
    let Some(first) = workers.first() else {
        return dto::locked();
    };
    let folders: Vec<FolderSnapshot> = workers
        .iter()
        .map(|worker| FolderSnapshot {
            folder: worker.folder().display().to_string(),
            status: worker.status(),
        })
        .collect();
    dto::status(Some(first.vault_id().to_owned()), &folders)
}

/// Creates a vault header at `dir` and returns its root directory id. Runs off the
/// main thread (Argon2id).
#[command]
pub async fn create_vault(dir: String, password: String) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let keys = syncbox_vault::create(
            Path::new(&dir),
            &password,
            &syncbox_crypto::kdf::Params::default(),
        )
        .map_err(|e| format!("could not create the vault: {e}"))?;
        let root = syncbox_crypto::names::DirId::root(&keys.hmac)
            .map_err(|e| format!("could not derive the root id: {e}"))?;
        Ok(root.to_string())
    })
    .await
    .map_err(|e| format!("create task failed: {e}"))?
}

/// The server's vaults, for the welcome form's picker. Pairing means an
/// operator named the vault on the server; the human picks the name, the app
/// keeps the id. It runs before anything is unlocked — the credentials are
/// the same ones unlock will use — and answers with the same small shape the
/// CLI's `--vault-name` resolves against.
#[command]
pub async fn list_vaults(server: String, password: String) -> Result<Vec<VaultChoice>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let mut client = dial(&server, &password);
        let listing = client
            .token(&password)
            .and_then(|_| client.vaults())
            .map_err(|e| format!("could not read the server's vaults: {e}"))?;
        let home = std::env::var_os("HOME").map(PathBuf::from);
        let home = home.as_deref();
        Ok(listing
            .vaults
            .iter()
            .map(|vault| VaultChoice {
                id: vault.id.clone(),
                name: vault.name.clone(),
                mode: dto::mode_str(vault.mode),
                location: vault.location.clone(),
                default_folder: dto::resolve_location(&vault.location, home)
                    .map(|path| path.display().to_string()),
                header_dir: dto::default_header_dir(home, &vault.id)
                    .map(|path| path.display().to_string()),
                archived: vault.archived,
            })
            .collect())
    })
    .await
    .map_err(|e| format!("vault-list task failed: {e}"))?
}

/// An authenticated client aimed at `server` (password already exchanged).
fn dial(server: &str, password: &str) -> Client<UreqHttp> {
    let mut client = Client::new(server, UreqHttp::new(server));
    // The call below re-checks the token result; authenticating here means the
    // request itself carries the bearer token.
    let _ = client.token(password);
    client
}

/// Whether the app registers itself when the desktop session starts.
#[command]
pub fn get_autostart(app: AppHandle) -> Result<bool, String> {
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}

/// Switch start-at-login: writes or removes the session's autostart entry for
/// this exact binary (the plugin points it at `current_exe`).
#[command]
pub fn set_autostart(app: AppHandle, enabled: bool) -> Result<(), String> {
    let autolaunch = app.autolaunch();
    if enabled {
        autolaunch.enable()
    } else {
        autolaunch.disable()
    }
    .map_err(|e| e.to_string())
}

/// What the synced folders hold — per folder for the row meta, summed for the
/// usage line. Reads each folder's local index; a session that has not synced
/// yet simply reports zeros rather than failing.
#[command]
pub fn usage(shared: State<'_, Shared>) -> Result<dto::Usage, String> {
    let state = shared.lock().map_err(|e| e.to_string())?;
    let mut counts = Vec::new();
    if let Some(vault_dir) = state.vault_dir() {
        for worker in state.workers() {
            let path = index_path_for(vault_dir, worker.folder());
            // An unreadable index (not created yet, or held by a first pass
            // mid-write) reads as an empty folder — the row, not the app.
            let (files, bytes) = match SqliteIndex::open(&path) {
                Ok(index) => (index.files().len() as u64, index.referenced_bytes()),
                Err(_) => (0, 0),
            };
            counts.push((worker.folder().display().to_string(), files, bytes));
        }
    }
    Ok(dto::usage(&counts))
}

/// Reveals a folder in the OS file manager — the synced vault row's click.
/// Only directories that exist are opened; anything else is the frontend's
/// imagination, and a desktop app should not spawn a file manager on a guess.
#[command]
pub fn open_folder(app: AppHandle, path: String) -> Result<(), String> {
    let path = Path::new(&path);
    if !path.is_dir() {
        return Err("that folder does not exist".into());
    }
    app.opener()
        .open_path(path.display().to_string(), None::<&str>)
        .map_err(|e| format!("could not open the folder: {e}"))
}

/// Exits the agent — the gear menu's Quit, and the tray's later. Not closing a
/// window: quit ends the process, and every worker stops with it.
#[command]
pub fn quit(app: AppHandle) {
    app.exit(0);
}

/// The stored switches, read fresh on each ask.
#[command]
pub fn get_prefs(app: AppHandle) -> Result<Prefs, String> {
    let path = prefs_path(&app)?;
    Ok(prefs::load(&path))
}

/// Stores the switches (see [`prefs`]).
#[command]
pub fn set_prefs(app: AppHandle, settings: Prefs) -> Result<(), String> {
    let path = prefs_path(&app)?;
    prefs::save(&path, &settings)
}

/// Where the switches live: `prefs.json` in the app's config directory.
fn prefs_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|dir| dir.join("prefs.json"))
        .map_err(|e| e.to_string())
}

/// Where the remembered spaces live: `spaces.json`, beside `prefs.json`.
fn spaces_path(app: &AppHandle) -> Result<PathBuf, String> {
    app.path()
        .app_config_dir()
        .map(|dir| dir.join("spaces.json"))
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same autostart wiring `main` installs, driven headlessly through the
    /// mock runtime: enabling must write an autostart entry somewhere under
    /// HOME/.config/autostart, disabling must remove it, and `is_enabled` must
    /// track both. The real home dir is kept out of it by pointing HOME at a
    /// throwaway sandbox for the duration of the test — the underlying
    /// `auto-launch` crate hardcodes `$HOME/.config/autostart`, so HOME is the
    /// only honest way to sandbox it.
    #[test]
    fn autostart_round_trip_through_the_plugin() {
        fn files_under(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
            let mut out = Vec::new();
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir() {
                        out.extend(files_under(&path));
                    } else {
                        out.push(path);
                    }
                }
            }
            out
        }

        let sandbox =
            std::env::temp_dir().join(format!("syncbox-autostart-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&sandbox);
        let previous = std::env::var("HOME").ok();
        std::env::set_var("HOME", &sandbox);

        let outcome = (|| -> Result<(), String> {
            let app = tauri::test::mock_builder()
                .plugin(tauri_plugin_autostart::init(
                    tauri_plugin_autostart::MacosLauncher::LaunchAgent,
                    None,
                ))
                .build(tauri::test::mock_context(tauri::test::noop_assets()))
                .map_err(|e| e.to_string())?;

            if app.autolaunch().is_enabled().map_err(|e| e.to_string())? {
                return Err("fresh sandbox already enabled".into());
            }

            app.autolaunch().enable().map_err(|e| e.to_string())?;
            if !app.autolaunch().is_enabled().map_err(|e| e.to_string())? {
                return Err("enable() did not stick".into());
            }
            if files_under(&sandbox).is_empty() {
                return Err("enable() wrote nothing under the sandbox".into());
            }

            app.autolaunch().disable().map_err(|e| e.to_string())?;
            if app.autolaunch().is_enabled().map_err(|e| e.to_string())? {
                return Err("disable() did not stick".into());
            }
            if !files_under(&sandbox).is_empty() {
                return Err("disable() left files behind".into());
            }
            Ok(())
        })();

        match previous {
            Some(value) => std::env::set_var("HOME", value),
            None => std::env::remove_var("HOME"),
        }
        let _ = std::fs::remove_dir_all(&sandbox);
        outcome.expect("autostart round trip");
    }
}
