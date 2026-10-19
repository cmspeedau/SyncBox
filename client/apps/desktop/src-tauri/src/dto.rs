//! The IPC boundary: serializable shapes the webview sees, mapped from the
//! Tauri-free agent types. The agent owns the behaviour; this only describes it as
//! JSON. Keeping the mapping in one pure module means it is unit-testable with no
//! window (see the tests at the bottom).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use syncbox_agent::{AgentStatus, SyncEvent, SyncState};
use syncbox_sync::SyncReport;
use syncbox_transport::dto::SpaceMode;

use crate::state::{Running, Session};

/// Vault settings as the frontend submits them (`camelCase`), turned into the
/// durable [`Session`] plus the space's display name. The *vault* password is
/// not among these fields: it belongs to the unlock window (see
/// [`crate::commands::open_unlock_window`]), so the main window's copy of the
/// session never carries it.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VaultSettings {
    /// Server origin, e.g. `https://sync.example`.
    pub server: String,
    /// The *server* password — the secret the web login asks for, which buys
    /// the bearer token every pass dials with. Not the vault password.
    pub server_password: String,
    /// The server's id for the vault.
    pub vault_id: String,
    /// Directory holding `vault.json`.
    pub vault_dir: String,
    /// The plaintext folders kept in sync. A vault can live in as many as the
    /// user wants; blank rows (an empty input) are dropped rather than opened.
    pub folders: Vec<String>,
    /// What the chosen space stores: `"vault"` or `"sync"`, as `list_vaults`
    /// reported it. Missing reads as `"vault"` — the safe reading, the same one
    /// [`SpaceMode::effective`] takes for a server that predates the field.
    #[serde(default)]
    pub mode: Option<String>,
    /// The space's display name, for the unlock window's title. Blank falls
    /// back to the id, which is all a hand-typed space has.
    #[serde(default)]
    pub name: String,
}

impl VaultSettings {
    /// Splits into the durable [`Session`] and the space's display name. An
    /// empty or whitespace-only folder is dropped, so "Add folder" then leaving
    /// it blank is harmless.
    #[must_use]
    pub fn into_parts(self) -> (Session, String) {
        let folders = self
            .folders
            .into_iter()
            .map(|folder| PathBuf::from(folder.trim()))
            .filter(|folder| !folder.as_os_str().is_empty())
            .collect();
        let mode = match self.mode.as_deref() {
            Some("sync") => SpaceMode::Sync,
            _ => SpaceMode::Vault,
        };
        let name = if self.name.trim().is_empty() {
            self.vault_id.clone()
        } else {
            self.name.trim().to_owned()
        };
        let session = Session {
            server: self.server,
            server_password: self.server_password,
            vault_id: self.vault_id,
            vault_dir: PathBuf::from(self.vault_dir),
            folders,
            mode,
        };
        (session, name)
    }
}

/// What the settings window reads when it opens: what the shell is running, and
/// what this build is. Every field is a fact the human could already read in the
/// main window; no password is among them, because a window that can be asked
/// this must not be handed a secret with it.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SettingsInfo {
    /// This build's version, as `Cargo.toml` states it.
    pub agent_version: String,
    /// The OS and architecture, e.g. `linux x86_64` — what support asks for.
    pub platform: String,
    /// The licence the binaries ship under.
    pub licence: String,
    /// The running space, or `None` while nothing is unlocked: the window then
    /// has a session to say nothing about.
    pub space: Option<RunningSpace>,
}

/// The running space, in the words the settings window prints.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RunningSpace {
    /// What to call it.
    pub name: String,
    /// The server origin, as it was typed at first run.
    pub server: String,
    /// `"vault"` or `"sync"`.
    pub mode: &'static str,
    /// Where this machine keeps the space's header and its per-folder indexes.
    pub vault_dir: String,
}

/// The settings window's one read: the build's facts plus the running space, if
/// there is one.
#[must_use]
pub fn settings_info(running: Option<&Running>) -> SettingsInfo {
    SettingsInfo {
        agent_version: env!("CARGO_PKG_VERSION").to_string(),
        platform: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        licence: "MIT".to_string(),
        space: running.map(|running| RunningSpace {
            name: running.name.clone(),
            server: running.server.clone(),
            mode: mode_str(running.mode),
            vault_dir: running.vault_dir.display().to_string(),
        }),
    }
}

/// What the unlock window (and the main window's waiting card) may know about a
/// pending unlock: which space, and in which mode. Deliberately no secret — the
/// password travels the other way, into the window's own webview.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingInfo {
    /// The space's display name, for the title.
    pub name: String,
    /// `"vault"` or `"sync"`. The window only ever opens for a vault — a sync
    /// space has no header to unlock — but the shape says which rather than
    /// assuming it.
    pub mode: &'static str,
}

/// Resolves a server-side location against a client's home directory, as the
/// desktop will use it. `None` home (no `$HOME`) leaves a relative location
/// unresolved. An empty location means the operator left the choice to each
/// client, so there is no default folder to offer.
///
/// - `Syncbox/Photos` → `<home>/Syncbox/Photos`
/// - `~/Photos` → `<home>/Photos`
/// - `/srv/photos` → used as typed
#[must_use]
pub fn resolve_location(location: &str, home: Option<&Path>) -> Option<PathBuf> {
    let location = location.trim();
    if location.is_empty() {
        return None;
    }
    if let Some(rest) = location.strip_prefix('~') {
        let home = home?;
        let rest = rest.strip_prefix('/').unwrap_or(rest);
        return Some(if rest.is_empty() {
            home.to_path_buf()
        } else {
            home.join(rest)
        });
    }
    let path = Path::new(location);
    if path.is_absolute() {
        return Some(path.to_path_buf());
    }
    home.map(|home| home.join(path))
}

/// The directory this machine keeps a space's own state in — the vault header
/// (`vault.json`) for a vault, the index for any space. Derived from the home
/// directory and the space's id, so it survives a rename of the space (the id
/// never changes) and no screen ever asks the human for it. `None` with no
/// `$HOME` to hang it on.
#[must_use]
pub fn default_header_dir(home: Option<&Path>, vault_id: &str) -> Option<PathBuf> {
    Some(home?.join(".syncbox").join(vault_id))
}

/// A [`SpaceMode`] as the frontend's word: `"vault"` or `"sync"`, after
/// [`SpaceMode::effective`] — an unknown mode ships as the safe one.
#[must_use]
pub fn mode_str(mode: SpaceMode) -> &'static str {
    if mode.is_encrypted() {
        "vault"
    } else {
        "sync"
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
    /// What the space stores: `"vault"` (encrypted on this device) or `"sync"`
    /// (kept in the clear). The picker says which, because it is a fact about
    /// the human's privacy, not bookkeeping.
    pub mode: &'static str,
    /// Where the operator said the vault's files land, as stored on the server.
    pub location: String,
    /// `location` resolved against this client's home, ready to prefill the
    /// folders editor; `null` when the operator left the choice to the client.
    pub default_folder: Option<String>,
    /// This client's own directory for the space (see [`default_header_dir`]),
    /// derived so no default screen asks for it; `null` with no `$HOME`.
    pub header_dir: Option<String>,
    /// Retired on the server; the picker hides these rather than trusting
    /// the human to read a badge.
    pub archived: bool,
}

/// What the synced folders hold, for the usage line and the per-row meta. The
/// numbers come from each folder's local index, not the server.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Usage {
    /// Files across all folders.
    pub files: u64,
    /// Referenced bytes across all folders.
    pub bytes: u64,
    /// One entry per synced folder, in the order they were unlocked.
    pub folders: Vec<FolderUsage>,
}

/// One folder's line in [`Usage`].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderUsage {
    /// The plaintext folder this copy lives in.
    pub folder: String,
    /// Files this folder's index knows.
    pub files: u64,
    /// Bytes those files reference.
    pub bytes: u64,
}

/// Assembles per-folder counts into the [`Usage`] shape; a folder whose index
/// could not be read arrives as `(0, 0)` and simply reads empty.
#[must_use]
pub fn usage(counts: &[(String, u64, u64)]) -> Usage {
    let folders = counts
        .iter()
        .map(|(folder, files, bytes)| FolderUsage {
            folder: folder.clone(),
            files: *files,
            bytes: *bytes,
        })
        .collect();
    Usage {
        files: counts.iter().map(|(_, files, _)| *files).sum(),
        bytes: counts.iter().map(|(_, _, bytes)| *bytes).sum(),
        folders,
    }
}

/// The tray/status line the frontend renders. A vault can live in many folders,
/// so the top-line numbers are the aggregate and `folders` carries each row.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    /// `"locked"`, `"idle"`, `"syncing"`, or `"error"` — the worst across folders.
    pub state: &'static str,
    /// The loops are held at the user's request. The window draws this over the
    /// state word, since a paused vault still has to say why nothing moves.
    pub paused: bool,
    /// Whether keys are in hand (a worker exists).
    pub unlocked: bool,
    /// The vault id, when unlocked.
    pub vault_id: Option<String>,
    /// Unix seconds of the last successful pass across folders.
    pub last_sync_unix: Option<i64>,
    /// Why the last pass failed, if any folder's did.
    pub last_error: Option<String>,
    /// The most passes any one folder has run (liveness).
    pub passes: u32,
    /// One entry per synced folder, in the order they were unlocked.
    pub folders: Vec<FolderStatus>,
}

/// One synced folder's line in [`Status`].
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderStatus {
    /// The plaintext folder this copy lives in.
    pub folder: String,
    /// `"idle"`, `"syncing"`, or `"error"`.
    pub state: &'static str,
    /// Unix seconds of this folder's last successful pass.
    pub last_sync_unix: Option<i64>,
    /// Why this folder's last pass failed, if it did.
    pub last_error: Option<String>,
}

/// One folder's live snapshot, paired with its path for [`status`].
pub struct FolderSnapshot {
    /// The plaintext folder this snapshot came from.
    pub folder: String,
    /// The agent status behind that folder's worker.
    pub status: AgentStatus,
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
    /// The plaintext folder the pass ran in.
    pub folder: String,
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
        paused: false,
        unlocked: false,
        vault_id: None,
        last_sync_unix: None,
        last_error: None,
        passes: 0,
        folders: Vec::new(),
    }
}

/// Maps the live snapshots to the JSON shape. The aggregate is deliberately
/// pessimistic: one folder in error makes the whole vault read "error", one
/// folder mid-pass reads "syncing", and only all-idle reads "idle" — a syncing
/// folder is not something to hide behind a quiet sibling.
#[must_use]
pub fn status(vault_id: Option<String>, folders: &[FolderSnapshot]) -> Status {
    let state = if folders
        .iter()
        .any(|folder| folder.status.state == SyncState::Error)
    {
        "error"
    } else if folders
        .iter()
        .any(|folder| folder.status.state == SyncState::Syncing)
    {
        "syncing"
    } else {
        "idle"
    };
    Status {
        state,
        paused: folders.iter().any(|folder| folder.status.paused),
        unlocked: !folders.is_empty(),
        vault_id,
        last_sync_unix: folders
            .iter()
            .filter_map(|folder| folder.status.last_sync_unix)
            .max(),
        last_error: folders
            .iter()
            .find_map(|folder| folder.status.last_error.clone()),
        passes: folders
            .iter()
            .map(|folder| folder.status.passes)
            .max()
            .unwrap_or(0),
        folders: folders
            .iter()
            .map(|folder| FolderStatus {
                folder: folder.folder.clone(),
                state: state_str(folder.status.state),
                last_sync_unix: folder.status.last_sync_unix,
                last_error: folder.status.last_error.clone(),
            })
            .collect(),
    }
}

/// Maps the activity feed, oldest first (the frontend may reverse it). Each
/// event carries the folder its pass ran in, so a feed from many folders reads
/// straight.
#[must_use]
pub fn activity(entries: &[(String, SyncEvent)]) -> Vec<Activity> {
    entries
        .iter()
        .map(|(folder, event)| match event {
            SyncEvent::Done { report, at_unix } => Activity {
                folder: folder.clone(),
                kind: "done",
                at_unix: *at_unix,
                error: None,
                report: Some(map_report(report)),
            },
            SyncEvent::Failed { error, at_unix } => Activity {
                folder: folder.clone(),
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
        let folders = vec![FolderSnapshot {
            folder: "/home/me/Syncbox".into(),
            status: snapshot,
        }];
        let json = serde_json::to_value(status(Some("vault-1".into()), &folders)).unwrap();
        assert_eq!(json["state"], "idle");
        assert_eq!(json["paused"], false);
        assert_eq!(json["unlocked"], true);
        assert_eq!(json["vaultId"], "vault-1");
        assert_eq!(json["passes"], 4);
        assert_eq!(json["folders"][0]["folder"], "/home/me/Syncbox");
        assert_eq!(json["folders"][0]["state"], "idle");
        // The IPC status deliberately stops at liveness — what the last pass
        // did belongs to the activity feed, not to a panel of its own.
        assert!(json.get("lastReport").is_none());
    }

    #[test]
    fn the_aggregate_takes_the_worst_folder() {
        let idle = AgentStatus {
            state: SyncState::Idle,
            last_sync_unix: Some(100),
            passes: 3,
            ..Default::default()
        };
        let syncing = AgentStatus {
            state: SyncState::Syncing,
            last_sync_unix: Some(200),
            passes: 5,
            ..Default::default()
        };
        let errored = AgentStatus {
            state: SyncState::Error,
            last_sync_unix: None,
            passes: 5,
            last_error: Some("server exploded".into()),
            ..Default::default()
        };
        let folders = vec![
            FolderSnapshot {
                folder: "/a".into(),
                status: idle,
            },
            FolderSnapshot {
                folder: "/b".into(),
                status: syncing,
            },
            FolderSnapshot {
                folder: "/c".into(),
                status: errored,
            },
        ];
        let mapped = status(Some("v".into()), &folders);
        assert_eq!(mapped.state, "error", "one error is the whole vault's");
        assert_eq!(mapped.last_sync_unix, Some(200), "the newest pass");
        assert_eq!(mapped.last_error.as_deref(), Some("server exploded"));
        assert_eq!(mapped.passes, 5);
        assert_eq!(mapped.folders.len(), 3);
        // The error is the reported one even though another folder synced later:
        // a failure is never hidden behind a quiet sibling.
        assert_eq!(mapped.folders[2].state, "error");
    }

    #[test]
    fn a_paused_folder_makes_the_vault_read_paused() {
        let running = AgentStatus {
            state: SyncState::Idle,
            passes: 2,
            ..Default::default()
        };
        let held = AgentStatus {
            state: SyncState::Idle,
            paused: true,
            passes: 2,
            ..Default::default()
        };
        let folders = vec![
            FolderSnapshot {
                folder: "/a".into(),
                status: running.clone(),
            },
            FolderSnapshot {
                folder: "/b".into(),
                status: held,
            },
        ];
        assert!(status(Some("v".into()), &folders).paused);
        // Nothing paused reads false, and the flag does not colour the state
        // word: a pause is not a failure, and the window draws it separately.
        let folders = vec![FolderSnapshot {
            folder: "/a".into(),
            status: running,
        }];
        let mapped = status(Some("v".into()), &folders);
        assert!(!mapped.paused);
        assert_eq!(mapped.state, "idle");
    }

    #[test]
    fn the_locked_shape_is_explicit() {
        let json = serde_json::to_value(locked()).unwrap();
        assert_eq!(json["state"], "locked");
        assert_eq!(json["unlocked"], false);
        assert!(json["vaultId"].is_null());
        assert_eq!(json["folders"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn activity_rows_carry_done_and_failed_shapes() {
        let entries = vec![
            (
                "/home/me/Syncbox".to_string(),
                SyncEvent::Done {
                    report: quiet_report(),
                    at_unix: 10,
                },
            ),
            (
                "/home/me/Backup".to_string(),
                SyncEvent::Failed {
                    error: "boom".into(),
                    at_unix: 20,
                },
            ),
        ];
        let rows = activity(&entries);
        assert_eq!(rows[0].kind, "done");
        assert_eq!(rows[0].folder, "/home/me/Syncbox");
        assert!(rows[0].report.is_some());
        assert_eq!(rows[1].kind, "failed");
        assert_eq!(rows[1].folder, "/home/me/Backup");
        assert_eq!(rows[1].error.as_deref(), Some("boom"));
    }

    #[test]
    fn a_location_resolves_against_home_or_stands_alone() {
        let home = Path::new("/home/me");
        assert_eq!(
            resolve_location("Syncbox/Photos", Some(home)),
            Some(PathBuf::from("/home/me/Syncbox/Photos"))
        );
        assert_eq!(
            resolve_location("~/Photos", Some(home)),
            Some(PathBuf::from("/home/me/Photos"))
        );
        assert_eq!(
            resolve_location("~", Some(home)),
            Some(PathBuf::from("/home/me"))
        );
        assert_eq!(
            resolve_location("/srv/photos", Some(home)),
            Some(PathBuf::from("/srv/photos")),
            "an absolute location is used as typed"
        );
        assert_eq!(
            resolve_location("  ", Some(home)),
            None,
            "empty means no default"
        );
        assert_eq!(resolve_location("Photos", None), None, "no home, no guess");
    }

    #[test]
    fn settings_map_to_a_session_and_drop_blank_folders() {
        let settings = VaultSettings {
            server: "https://srv".into(),
            server_password: "server-pw".into(),
            vault_id: "v".into(),
            vault_dir: "/vault".into(),
            folders: vec!["/files".into(), "  ".into(), "/backup".into()],
            mode: None,
            name: "  Files synced  ".into(),
        };
        let (session, name) = settings.into_parts();
        assert_eq!(session.server, "https://srv");
        assert_eq!(session.server_password, "server-pw", "the token's secret");
        assert_eq!(session.vault_id, "v");
        assert_eq!(session.vault_dir, PathBuf::from("/vault"));
        assert_eq!(session.mode, SpaceMode::Vault, "no mode reads vault");
        assert_eq!(
            session.folders,
            vec![PathBuf::from("/files"), PathBuf::from("/backup")]
        );
        assert_eq!(name, "Files synced", "trimmed, for the window's title");
    }

    #[test]
    fn a_nameless_space_is_titled_by_its_id() {
        // A hand-typed space has an id and nothing else to call it.
        let settings = VaultSettings {
            server: "https://srv".into(),
            server_password: "pw".into(),
            vault_id: "vault-7".into(),
            vault_dir: "/state".into(),
            folders: vec!["/files".into()],
            mode: None,
            name: String::new(),
        };
        let (_, name) = settings.into_parts();
        assert_eq!(name, "vault-7");
    }

    #[test]
    fn a_sync_space_carries_its_mode() {
        // The one word that decides whether the session derives keys.
        let json = r#"{
            "server": "https://srv",
            "serverPassword": "server-pw",
            "vaultId": "v",
            "vaultDir": "/state",
            "folders": ["/files"],
            "mode": "sync"
        }"#;
        let settings: VaultSettings = serde_json::from_str(json).unwrap();
        let (session, name) = settings.into_parts();
        assert_eq!(session.mode, SpaceMode::Sync);
        assert_eq!(name, "v", "no name given, the id stands in");
    }

    #[test]
    fn the_settings_window_sees_the_space_and_the_build_but_no_password() {
        let locked = settings_info(None);
        assert!(locked.space.is_none(), "locked: nothing to describe");
        assert!(
            !locked.agent_version.is_empty(),
            "the build says its version"
        );
        assert!(!locked.platform.is_empty());
        assert_eq!(locked.licence, "MIT");

        let running = Running {
            name: "Files synced".into(),
            server: "https://sync.example.org".into(),
            mode: SpaceMode::Vault,
            vault_dir: PathBuf::from("/home/me/.syncbox/demo"),
        };
        let json = serde_json::to_value(settings_info(Some(&running))).unwrap();
        assert_eq!(json["space"]["name"], "Files synced");
        assert_eq!(json["space"]["server"], "https://sync.example.org");
        assert_eq!(json["space"]["mode"], "vault");
        assert_eq!(json["space"]["vaultDir"], "/home/me/.syncbox/demo");
        // The whole point of this read: it is safe to hand a window.
        assert!(json["space"]["password"].is_null());
        assert!(json["space"]["serverPassword"].is_null());
    }

    #[test]
    fn a_pending_unlock_says_which_space_without_a_secret() {
        let json = serde_json::to_value(PendingInfo {
            name: "Files synced".into(),
            mode: "vault",
        })
        .unwrap();
        assert_eq!(json["name"], "Files synced");
        assert_eq!(json["mode"], "vault");
        // The window asks who, never what: nothing here is a credential.
        assert!(json.get("password").is_none());
        assert!(json.get("serverPassword").is_none());
    }

    #[test]
    fn a_mode_reads_as_a_word_and_the_safe_way() {
        assert_eq!(mode_str(SpaceMode::Vault), "vault");
        assert_eq!(mode_str(SpaceMode::Sync), "sync");
        assert_eq!(mode_str(SpaceMode::Unknown), "vault", "unknown ships safe");
    }

    #[test]
    fn the_header_dir_hangs_under_the_home_by_space_id() {
        let home = Path::new("/home/me");
        assert_eq!(
            default_header_dir(Some(home), "vault-7"),
            Some(PathBuf::from("/home/me/.syncbox/vault-7")),
            "the id, not the name: a rename does not move it"
        );
        assert_eq!(
            default_header_dir(None, "vault-7"),
            None,
            "no home, no guess"
        );
    }

    #[test]
    fn usage_counts_each_folder_and_sums_the_line() {
        let counts = vec![
            ("/files".to_string(), 412, 1_800_000_000),
            ("/mirror".to_string(), 412, 1_800_000_000),
            ("/broken".to_string(), 0, 0),
        ];
        let json = serde_json::to_value(usage(&counts)).unwrap();
        assert_eq!(json["files"], 824);
        assert_eq!(json["bytes"], 3_600_000_000u64);
        assert_eq!(json["folders"][0]["folder"], "/files");
        assert_eq!(json["folders"][0]["files"], 412);
        assert_eq!(
            json["folders"][2]["bytes"], 0,
            "an unreadable index reads empty"
        );
    }
}
