//! The `#[tauri::command]` surface. Each command is thin: read the shared state (a
//! cheap lock) or, for anything that blocks — unlocking (Argon2id), the network —
//! hand the work to a blocking thread so the webview never stalls.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use tauri::{command, AppHandle, State};

use tauri_plugin_autostart::ManagerExt as _;

use syncbox_agent::SyncEvent;
use syncbox_transport::{Client, UreqHttp};

use crate::dto::{self, Activity, FolderSnapshot, Status, VaultChoice, VaultSettings};
use crate::state::{AppState, Shared};

/// The current sync status (state, last pass, any error), aggregated across the
/// folder workers.
#[command]
pub fn status(shared: State<'_, Shared>) -> Result<Status, String> {
    let state = shared.lock().map_err(|e| e.to_string())?;
    Ok(current_status(&state))
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

/// Unlocks the vault and starts a background loop per folder. Blocks on key
/// derivation, so it runs off the main thread.
#[command]
pub async fn unlock(shared: State<'_, Shared>, settings: VaultSettings) -> Result<Status, String> {
    let shared = Arc::clone(shared.inner());
    let (session, password) = settings.into_parts();
    tauri::async_runtime::spawn_blocking(move || {
        let mut state = shared.lock().map_err(|e| e.to_string())?;
        state.unlock_vault(session, password)?;
        Ok(current_status(&state))
    })
    .await
    .map_err(|e| format!("unlock task failed: {e}"))?
}

/// Locks the vault: stops the loops and drops the keys.
#[command]
pub fn lock(shared: State<'_, Shared>) -> Result<Status, String> {
    let mut state = shared.lock().map_err(|e| e.to_string())?;
    state.lock_vault();
    Ok(dto::locked())
}

/// Asks every loop to run a pass now (non-blocking) and returns the current
/// status.
#[command]
pub fn sync_now(shared: State<'_, Shared>) -> Result<Status, String> {
    let state = shared.lock().map_err(|e| e.to_string())?;
    if state.workers().is_empty() {
        return Err("the vault is locked — unlock it first".into());
    }
    for worker in state.workers() {
        worker.request_sync();
    }
    Ok(current_status(&state))
}

/// The aggregated status of a state's workers, or the locked shape when none run.
fn current_status(state: &AppState) -> Status {
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
                location: vault.location.clone(),
                default_folder: dto::resolve_location(&vault.location, home)
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
