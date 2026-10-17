//! The IPC boundary: serializable shapes the webview sees, mapped from the
//! Tauri-free agent types. The agent owns the behaviour; this only describes it as
//! JSON. Keeping the mapping in one pure module means it is unit-testable with no
//! window (see the tests at the bottom).

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use syncbox_agent::{AgentStatus, SyncEvent, SyncState};
use syncbox_sync::SyncReport;

/// Vault settings as the frontend submits them (`camelCase`), turned into the
/// agent's [`Config`] plus the password it needs to unlock.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultSettings {
    /// Server origin, e.g. `https://sync.example`.
    pub server: String,
    /// The server's id for the vault.
    pub vault_id: String,
    /// Directory holding `vault.json`.
    pub vault_dir: String,
    /// The plaintext folder kept in sync.
    pub folder: String,
    /// Vault password (never persisted; only used to unlock this session).
    pub password: String,
}

impl VaultSettings {
    /// Splits into the durable [`Config`] and the (transient) password.
    pub fn into_parts(self) -> (syncbox_agent::Config, String) {
        let config = syncbox_agent::Config {
            server: self.server,
            vault_id: self.vault_id,
            vault_dir: PathBuf::from(self.vault_dir),
            folder: PathBuf::from(self.folder),
            index: None,
        };
        (config, self.password)
    }
}

/// One entry of the server's vault registry, as `list_vaults` returns it and
/// the welcome form's picker renders it. Mirrors the wire shape of
/// `GET /vaults` (`camelCase` for the frontend, snake_case on the wire).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultChoice {
    /// The id unlock will receive if this entry is chosen.
    pub id: String,
    /// The operator's label on the server; empty while unnamed.
    pub name: String,
    /// Retired on the server; the picker hides these rather than trusting
    /// the human to read a badge.
    pub archived: bool,
}

/// The tray/status line the frontend renders.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// `"locked"`, `"idle"`, `"syncing"`, or `"error"`.
    pub state: &'static str,
    /// Whether keys are in hand (a worker exists).
    pub unlocked: bool,
    /// The vault id, when unlocked.
    pub vault_id: Option<String>,
    /// Unix seconds of the last successful pass.
    pub last_sync_unix: Option<i64>,
    /// Why the last pass failed, if it did.
    pub last_error: Option<String>,
    /// How many passes have run (liveness).
    pub passes: u32,
}

/// A [`SyncReport`] as JSON (also embedded in activity rows).
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Report {
    /// Files pushed up.
    pub uploaded: usize,
    /// Files pulled down.
    pub downloaded: usize,
    /// Conflicted copies made.
    pub conflicts: usize,
    /// Deletions applied.
    pub deleted: usize,
    /// Files skipped (a not-yet-created directory).
    pub skipped: usize,
    /// New chunks sent.
    pub chunks_uploaded: usize,
    /// Plaintext bytes those chunks covered.
    pub bytes_uploaded: u64,
    /// True when the pass found nothing to do.
    pub quiet: bool,
}

/// One activity-feed row.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Activity {
    /// `"done"` or `"failed"`.
    pub kind: &'static str,
    /// Unix seconds it happened.
    pub at_unix: i64,
    /// Failure reason, for a failed row.
    pub error: Option<String>,
    /// The pass outcome, for a done row.
    pub report: Option<Report>,
}

/// The locked state, shown when no session exists yet.
#[must_use]
pub fn locked() -> Status {
    Status {
        state: "locked",
        unlocked: false,
        vault_id: None,
        last_sync_unix: None,
        last_error: None,
        passes: 0,
    }
}

/// Maps a live status snapshot to its JSON shape.
#[must_use]
pub fn status(snapshot: &AgentStatus, vault_id: Option<String>) -> Status {
    Status {
        state: state_str(snapshot.state),
        unlocked: snapshot.state != SyncState::Locked,
        vault_id,
        last_sync_unix: snapshot.last_sync_unix,
        last_error: snapshot.last_error.clone(),
        passes: snapshot.passes,
    }
}

/// Maps the activity feed, oldest first (the frontend may reverse it).
#[must_use]
pub fn activity(events: &[SyncEvent]) -> Vec<Activity> {
    events
        .iter()
        .map(|event| match event {
            SyncEvent::Done { report, at_unix } => Activity {
                kind: "done",
                at_unix: *at_unix,
                error: None,
                report: Some(map_report(report)),
            },
            SyncEvent::Failed { error, at_unix } => Activity {
                kind: "failed",
                at_unix: *at_unix,
                error: Some(error.clone()),
                report: None,
            },
        })
        .collect()
}

fn map_report(report: &SyncReport) -> Report {
    Report {
        uploaded: report.uploaded,
        downloaded: report.downloaded,
        conflicts: report.conflicts,
        deleted: report.deleted,
        skipped: report.skipped,
        chunks_uploaded: report.chunks_uploaded,
        bytes_uploaded: report.bytes_uploaded,
        quiet: report.is_quiet(),
    }
}

fn state_str(state: SyncState) -> &'static str {
    match state {
        SyncState::Locked => "locked",
        SyncState::Idle => "idle",
        SyncState::Syncing => "syncing",
        SyncState::Error => "error",
    }
}

#[cfg(test)]
mod tests {
    use syncbox_agent::AgentStatus;

    use super::*;

    fn quiet_report() -> SyncReport {
        SyncReport {
            uploaded: 2,
            downloaded: 1,
            conflicts: 0,
            deleted: 0,
            skipped: 0,
            chunks_uploaded: 3,
            bytes_uploaded: 4096,
            resumed_chunks: 0,
        }
    }

    #[test]
    fn an_idle_status_serialises_to_camel_case() {
        let snapshot = AgentStatus {
            state: SyncState::Idle,
            last_sync_unix: Some(1_700_000_000),
            passes: 4,
            last_report: Some(quiet_report()),
            ..Default::default()
        };
        let json = serde_json::to_value(status(&snapshot, Some("vault-1".into()))).unwrap();
        assert_eq!(json["state"], "idle");
        assert_eq!(json["unlocked"], true);
        assert_eq!(json["vaultId"], "vault-1");
        assert_eq!(json["passes"], 4);
        // The IPC status deliberately stops at liveness — what the last pass
        // did belongs to the activity feed, not to a panel of its own.
        assert!(json.get("lastReport").is_none());
    }

    #[test]
    fn the_locked_shape_is_explicit() {
        let json = serde_json::to_value(locked()).unwrap();
        assert_eq!(json["state"], "locked");
        assert_eq!(json["unlocked"], false);
        assert!(json["vaultId"].is_null());
    }

    #[test]
    fn activity_rows_carry_done_and_failed_shapes() {
        let events = vec![
            SyncEvent::Done {
                report: quiet_report(),
                at_unix: 10,
            },
            SyncEvent::Failed {
                error: "boom".into(),
                at_unix: 20,
            },
        ];
        let rows = activity(&events);
        assert_eq!(rows[0].kind, "done");
        assert!(rows[0].report.is_some());
        assert_eq!(rows[1].kind, "failed");
        assert_eq!(rows[1].error.as_deref(), Some("boom"));
    }

    #[test]
    fn settings_map_to_an_agent_config() {
        let settings = VaultSettings {
            server: "https://srv".into(),
            vault_id: "v".into(),
            vault_dir: "/vault".into(),
            folder: "/files".into(),
            password: "pw".into(),
        };
        let (config, password) = settings.into_parts();
        assert_eq!(config.index_path(), PathBuf::from("/vault/index.db"));
        assert_eq!(password, "pw");
    }
}
