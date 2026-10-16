//! The `#[tauri::command]` surface. Each command is thin: read the shared state (a
//! cheap lock) or, for anything that blocks — unlocking (Argon2id), the network —
//! hand the work to a blocking thread so the webview never stalls.

use std::path::Path;
use std::sync::Arc;

use tauri::{command, State};

use syncbox_transport::{Client, TransportError, UreqHttp};

use crate::dto::{self, Activity, BackupAction, BackupResult, Status, VaultSettings};
use crate::state::Shared;

/// The current sync status (state, last pass, any error).
#[command]
pub fn status(shared: State<'_, Shared>) -> Result<Status, String> {
    let state = shared.lock().map_err(|e| e.to_string())?;
    Ok(match state.worker() {
        Some(worker) => dto::status(&worker.status(), Some(worker.vault_id().to_owned())),
        None => dto::locked(),
    })
}

/// The recent sync activity feed, oldest first.
#[command]
pub fn activity(shared: State<'_, Shared>) -> Result<Vec<Activity>, String> {
    let state = shared.lock().map_err(|e| e.to_string())?;
    Ok(match state.worker() {
        Some(worker) => dto::activity(&worker.history()),
        None => Vec::new(),
    })
}

/// Unlocks the vault and starts the background loop. Blocks on key derivation, so
/// it runs off the main thread.
#[command]
pub async fn unlock(shared: State<'_, Shared>, settings: VaultSettings) -> Result<Status, String> {
    let shared = Arc::clone(shared.inner());
    let (config, password) = settings.into_parts();
    tauri::async_runtime::spawn_blocking(move || {
        let mut state = shared.lock().map_err(|e| e.to_string())?;
        state.unlock_vault(config, password)?;
        let worker = state.worker().ok_or("the vault did not start syncing")?;
        Ok(dto::status(
            &worker.status(),
            Some(worker.vault_id().to_owned()),
        ))
    })
    .await
    .map_err(|e| format!("unlock task failed: {e}"))?
}

/// Locks the vault: stops the loop and drops the keys.
#[command]
pub fn lock(shared: State<'_, Shared>) -> Result<Status, String> {
    let mut state = shared.lock().map_err(|e| e.to_string())?;
    state.lock_vault();
    Ok(dto::locked())
}

/// Asks the loop to run a pass now (non-blocking) and returns the current status.
#[command]
pub fn sync_now(shared: State<'_, Shared>) -> Result<Status, String> {
    let state = shared.lock().map_err(|e| e.to_string())?;
    let worker = state
        .worker()
        .ok_or("the vault is locked — unlock it first")?;
    worker.request_sync();
    Ok(dto::status(
        &worker.status(),
        Some(worker.vault_id().to_owned()),
    ))
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

/// Lists the server's snapshots for the Backups panel. Rides the admin route with
/// its own authenticated client — backups are independent of the sync session.
#[command]
pub async fn backups(shared: State<'_, Shared>) -> Result<BackupResult, String> {
    let shared = Arc::clone(shared.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let (server, password) = shared
            .lock()
            .map_err(|e| e.to_string())?
            .credentials()
            .ok_or("the vault is locked — unlock it first")?;

        let mut client = dial(&server, &password);
        match client.token(&password).and_then(|_| client.backups()) {
            Ok(snapshots) => Ok(BackupResult::Listed(
                snapshots.iter().map(dto::backup).collect(),
            )),
            Err(error) if is_not_configured(&error) => Ok(BackupResult::NotConfigured),
            Err(error) => Ok(BackupResult::Error(error.to_string())),
        }
    })
    .await
    .map_err(|e| format!("backups task failed: {e}"))?
}

/// Asks the server to take a snapshot now and returns it.
#[command]
pub async fn back_up_now(shared: State<'_, Shared>) -> Result<BackupAction, String> {
    let shared = Arc::clone(shared.inner());
    tauri::async_runtime::spawn_blocking(move || {
        let (server, password) = shared
            .lock()
            .map_err(|e| e.to_string())?
            .credentials()
            .ok_or("the vault is locked — unlock it first")?;

        let mut client = dial(&server, &password);
        match client.token(&password).and_then(|_| client.create_backup()) {
            Ok(snapshot) => Ok(BackupAction::Taken(dto::backup(&snapshot))),
            Err(error) if is_not_configured(&error) => Ok(BackupAction::NotConfigured),
            Err(error) => Ok(BackupAction::Error(error.to_string())),
        }
    })
    .await
    .map_err(|e| format!("backup task failed: {e}"))?
}

/// An authenticated client aimed at `server` (password already exchanged).
fn dial(server: &str, password: &str) -> Client<UreqHttp> {
    let mut client = Client::new(server, UreqHttp::new(server));
    // The call below re-checks the token result; authenticating here means the
    // backups request itself carries the bearer token.
    let _ = client.token(password);
    client
}

/// Whether a transport error is the server's "no backup target configured" answer.
fn is_not_configured(error: &TransportError) -> bool {
    matches!(error, TransportError::Refused { code, .. } if code == "not_configured")
}
