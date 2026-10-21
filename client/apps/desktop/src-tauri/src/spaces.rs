//! The spaces this computer has opened, remembered across launches.
//!
//! Metadata only: the server, the space's id and name, its mode, the state
//! directory and the synced folders. Never the server password, a bearer token
//! or the vault password — a remembered space therefore comes back as a
//! **locked row**, and unlocking asks the human for the server password again
//! (the vault password already has its own window).
//!
//! Like [`crate::prefs`], the file is deliberately forgiving: absent, unreadable
//! or written by a newer build reads as an empty list rather than stopping the
//! app from opening.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use syncbox_transport::dto::SpaceMode;

use crate::state::Session;

/// How many spaces are remembered. A human with more than this many spaces on
/// one machine is better served by the hidden tier's hand-typed id than by an
/// unbounded list; an old entry falls off the end.
pub const MAX_SPACES: usize = 20;

/// One remembered space. Everything here is safe to hand a window: the state
/// directory and folders are the same facts the settings window already shows,
/// and no credential is among them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Space {
    /// Server origin, e.g. `https://sync.example`.
    pub server: String,
    /// The server's id for the space; the durable handle, unchanged by a rename.
    pub vault_id: String,
    /// The display name at the time it was last opened.
    #[serde(default)]
    pub name: String,
    /// What the space stores. An older file without the field reads as a vault,
    /// the safe reading.
    #[serde(default)]
    pub mode: SpaceMode,
    /// This machine's state directory for the space.
    pub vault_dir: PathBuf,
    /// The plaintext folders this space was syncing. Empty in a future file that
    /// predates no field but lost its folders: the row still shows, and the
    /// unlock path falls back to the server's derived folder.
    #[serde(default)]
    pub folders: Vec<PathBuf>,
}

impl Space {
    /// The non-secret half of a session, ready to remember.
    #[must_use]
    pub fn from_session(session: &Session, name: &str) -> Self {
        Self {
            server: session.server.clone(),
            vault_id: session.vault_id.clone(),
            name: name.to_owned(),
            // An unknown mode is never written; a vault is what this build can
            // honour, and it is the safe word for an older reader.
            mode: session.mode.effective(),
            vault_dir: session.vault_dir.clone(),
            folders: session.folders.clone(),
        }
    }
}

/// Reads the remembered spaces; anything wrong on disk reads as an empty list.
#[must_use]
pub fn load(path: &Path) -> Vec<Space> {
    fs::read_to_string(path)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok())
        .unwrap_or_default()
}

/// Writes the remembered spaces, creating the directory if this is the first
/// save.
///
/// # Errors
///
/// A human-readable reason if the file (or its directory) cannot be written.
pub fn save(path: &Path, spaces: &[Space]) -> Result<(), String> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| format!("could not create the config dir: {e}"))?;
    }
    let text = serde_json::to_string_pretty(spaces).map_err(|e| e.to_string())?;
    fs::write(path, text).map_err(|e| format!("could not write the remembered spaces: {e}"))
}

/// Remembers a space: an older entry for the same server and id is replaced, the
/// newest sits first, and the list is capped. Returns the entry that was
/// displaced, for a caller that wants to say so.
pub fn remember(spaces: &mut Vec<Space>, space: Space) -> Option<Space> {
    let replaced = spaces
        .iter()
        .position(|known| known.server == space.server && known.vault_id == space.vault_id)
        .map(|index| spaces.remove(index));
    spaces.insert(0, space);
    spaces.truncate(MAX_SPACES);
    replaced
}

#[cfg(test)]
mod tests {
    use super::*;

    fn space(id: &str) -> Space {
        Space {
            server: "https://sync.example".into(),
            vault_id: id.into(),
            name: format!("Space {id}"),
            mode: SpaceMode::Vault,
            vault_dir: PathBuf::from(format!("/home/me/.syncbox/{id}")),
            folders: vec![PathBuf::from("/home/me/Syncbox")],
        }
    }

    #[test]
    fn spaces_survive_a_round_trip() {
        let dir = std::env::temp_dir().join(format!("syncbox-spaces-{}", std::process::id()));
        let file = dir.join("spaces.json");
        let _ = fs::remove_dir_all(&dir);

        assert!(
            load(&file).is_empty(),
            "absent reads as no remembered spaces"
        );
        let spaces = vec![space("a"), space("b")];
        save(&file, &spaces).expect("first save creates the dir");
        assert_eq!(load(&file), spaces);

        let text = fs::read_to_string(&file).unwrap();
        assert!(
            !text.to_lowercase().contains("password"),
            "no secret is stored"
        );
        assert!(!text.contains("token"), "no bearer token is stored");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_broken_or_future_file_still_opens_the_app() {
        let dir = std::env::temp_dir().join(format!("syncbox-spaces-bad-{}", std::process::id()));
        let file = dir.join("spaces.json");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        fs::write(&file, "not json at all").unwrap();
        assert!(load(&file).is_empty(), "unreadable reads as empty");

        // A file from a build that knows one more field: this build reads what
        // it knows and ignores the rest.
        fs::write(
            &file,
            r#"[{"server":"https://s","vaultId":"v","vaultDir":"/state","pinned":true}]"#,
        )
        .unwrap();
        let loaded = load(&file);
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].mode, SpaceMode::Vault, "no mode reads safe");
        assert_eq!(loaded[0].name, "", "no name reads empty");
        assert!(loaded[0].folders.is_empty(), "no folders reads empty");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remembering_moves_the_newest_first_and_never_stores_twice() {
        let mut spaces = Vec::new();
        remember(&mut spaces, space("a"));
        remember(&mut spaces, space("b"));
        assert_eq!(
            spaces
                .iter()
                .map(|s| s.vault_id.as_str())
                .collect::<Vec<_>>(),
            vec!["b", "a"]
        );

        let mut renamed = space("a");
        renamed.name = "Renamed".into();
        assert!(remember(&mut spaces, renamed.clone()).is_some());
        assert_eq!(spaces.len(), 2, "the same server and id is one row");
        assert_eq!(spaces[0].vault_id, "a", "the reopened space sits first");
        assert_eq!(spaces[0].name, "Renamed");

        // The same id on another server is a different space.
        let mut other = space("a");
        other.server = "https://other.example".into();
        remember(&mut spaces, other);
        assert_eq!(spaces.len(), 3);
    }

    #[test]
    fn the_list_is_capped() {
        let mut spaces = Vec::new();
        for i in 0..(MAX_SPACES + 3) {
            remember(&mut spaces, space(&format!("v{i}")));
        }
        assert_eq!(spaces.len(), MAX_SPACES);
        assert_eq!(spaces[0].vault_id, format!("v{}", MAX_SPACES + 2));
    }

    #[test]
    fn a_remembered_session_keeps_no_secret() {
        let session = Session {
            server: "https://sync.example".into(),
            server_password: "server-secret".into(),
            vault_id: "v1".into(),
            vault_dir: PathBuf::from("/home/me/.syncbox/v1"),
            folders: vec![PathBuf::from("/home/me/Syncbox")],
            mode: SpaceMode::Sync,
        };
        let remembered = Space::from_session(&session, "Files synced");
        assert_eq!(remembered.server, session.server);
        assert_eq!(remembered.vault_id, session.vault_id);
        assert_eq!(remembered.name, "Files synced");
        assert_eq!(remembered.vault_dir, session.vault_dir);
        assert_eq!(remembered.folders, session.folders);
        assert_eq!(remembered.mode, SpaceMode::Sync);

        let json = serde_json::to_string(&remembered).unwrap();
        assert!(!json.contains("server-secret"), "the password stays out");
        assert!(!json.contains("serverPassword"));
    }

    #[test]
    fn an_unknown_mode_is_remembered_as_the_safe_one() {
        let session = Session {
            server: "https://s".into(),
            server_password: String::new(),
            vault_id: "v".into(),
            vault_dir: PathBuf::from("/s"),
            folders: vec![PathBuf::from("/f")],
            mode: SpaceMode::Unknown,
        };
        assert_eq!(Space::from_session(&session, "v").mode, SpaceMode::Vault);
    }
}
