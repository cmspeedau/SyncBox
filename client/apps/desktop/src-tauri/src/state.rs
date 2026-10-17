//! The window's shared state: the background [`SyncWorker`] and what it takes to
//! (re)start it. Everything expensive — the unlocked agent, its index, the HTTP
//! client — lives on the worker thread; this holds only the handle plus the
//! credentials a pass needs.
//!
//! Locking the vault drops the worker (its `Drop` stops the loop), which drops the
//! agent and the master keys with it — nothing sensitive survives a lock.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use syncbox_agent::{Agent, Config, SyncWorker};
use syncbox_transport::{Client, UreqHttp};

/// How often the loop runs a pass when nothing is requested. A manual `Sync now`
/// and file-change pushes run ahead of this.
pub const SYNC_INTERVAL: Duration = Duration::from_secs(60);

/// The managed state, wrapped once so commands can share it cheaply.
pub type Shared = Arc<Mutex<AppState>>;

/// Everything the shell tracks about the current session.
#[derive(Default)]
pub struct AppState {
    worker: Option<SyncWorker>,
    server: String,
    password: String,
}

impl AppState {
    /// Unlocks `config` with `password` and starts the background loop, replacing
    /// any running session.
    ///
    /// Blocking: Argon2id runs on unlock and the loop's first pass authenticates
    /// immediately. Callers run this on a blocking thread (see `commands`).
    ///
    /// # Errors
    ///
    /// A human-readable reason if the vault cannot be unlocked (wrong password,
    /// unreadable header, index cannot be opened).
    pub fn unlock_vault(&mut self, config: Config, password: String) -> Result<(), String> {
        // End the previous loop before replacing the session so two never run.
        self.stop_worker();

        let agent = Agent::unlock(&config, &password).map_err(|e| e.to_string())?;
        self.server = config.server.clone();
        self.password = password.clone();

        let server = config.server.clone();
        // Build a fresh, re-authenticated client for every pass: that is where an
        // expired token gets refreshed, and why a factory (not a single client) is
        // handed to the loop. A failed token exchange is left for the pass to
        // surface as an error state; the next pass dials out again.
        let client_factory = move || {
            let mut client = Client::new(&server, UreqHttp::new(&server));
            let _ = client.token(&password);
            client
        };

        self.worker = Some(agent.spawn_loop(SYNC_INTERVAL, client_factory, crate::today));
        Ok(())
    }

    /// Stops the loop and forgets the credentials (drops the keys with the worker).
    pub fn lock_vault(&mut self) {
        self.stop_worker();
        self.server.clear();
        self.password.clear();
    }

    /// The live status handle, when a session is running.
    #[must_use]
    pub fn worker(&self) -> Option<&SyncWorker> {
        self.worker.as_ref()
    }

    fn stop_worker(&mut self) {
        if let Some(worker) = self.worker.take() {
            worker.stop();
        }
    }
}
