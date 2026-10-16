//! Wire types, in the exact snake_case shape the Go server speaks.
//!
//! Two rules govern these shapes, and both come from the vault being hidden:
//!
//! - Nothing here carries a plaintext filename, a path, or file content. A
//!   `Revision` holds an *encrypted* manifest blob, which is why a server with a
//!   subpoena can produce sizes and timings and nothing else.
//! - Sizes are plaintext, because a client cannot tell the server how much to
//!   send without knowing. That is the leak the design accepts.

use serde::{Deserialize, Serialize};

/// Deserialises a JSON field that may be `null` as an empty `String`.
///
/// The Go server marshals a nil `[]byte` (a tombstone's absent manifest) as
/// `null`; this reads `null`, a string, or an absent field alike into `""`.
fn null_to_empty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(deserializer)?.unwrap_or_default())
}

/// `POST /api/v1/auth/token`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenRequest {
    /// The account password, over TLS and never stored by the server.
    pub password: String,
}

/// Response to [`TokenRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenResponse {
    /// Bearer token for subsequent calls.
    pub token: String,
    /// When the token stops being accepted, seconds since the Unix epoch.
    pub expires_unix: i64,
}

/// One committed file revision, as the server stores it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revision {
    /// Server-assigned revision number within the vault, starting at 1.
    pub revision: u64,
    /// Revision this one was derived from, `0` for the first.
    pub parent: u64,
    /// Which file this revision is of, by directory id.
    pub dir_id: String,
    /// The file's encrypted name, without its `.c9r` suffix.
    pub cipher_name: String,
    /// Encrypted chunk list. Opaque to the server.
    ///
    /// A tombstone carries no manifest, and the Go server stores that as a nil
    /// `[]byte`, which `encoding/json` writes as `null` (not `""`). Deserialising
    /// it as an empty string keeps one JSON shape (`null` == `""` == absent) so a
    /// delete parses the same way whether it came from Go or a test fixture.
    #[serde(default, deserialize_with = "null_to_empty_string")]
    pub manifest: String,
    /// Plaintext size of the file, which the client needs to allocate and cannot
    /// learn from the ciphertext.
    pub size: u64,
    /// Last modification time, seconds since the Unix epoch.
    pub modified_unix: i64,
    /// A tombstone: this revision deletes the file rather than writing it.
    pub deleted: bool,
}

/// `POST /api/v1/vaults/{id}/revisions`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitRequest {
    /// Revision the client believed was current when it edited. A mismatch is how
    /// the server detects a conflict without reading anything.
    pub parent: u64,
    /// The new revision.
    pub revision: Revision,
}

/// Response to a commit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitResponse {
    /// Revision number the server assigned.
    pub revision: u64,
}

/// `GET /api/v1/vaults/{id}/revisions?since=N`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevisionPage {
    /// Revisions newer than the requested point, oldest first.
    pub revisions: Vec<Revision>,
    /// Highest revision the server holds, to be used as `since` next time.
    pub upto: u64,
}

/// `POST /api/v1/chunks/exists`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkCheckRequest {
    /// Chunk ids to test.
    pub ids: Vec<String>,
}

/// Response to [`ChunkCheckRequest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChunkCheckResponse {
    /// The subset that the server does not already store.
    pub missing: Vec<String>,
}

/// The error body every non-2xx response carries.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// Stable machine-readable code.
    pub code: String,
    /// Message meant for a log or a tooltip.
    pub reason: String,
}

/// `GET /admin/backups` (an array) and `POST /admin/backups` (one).
///
/// Mirrors the Go `backup.Snapshot`, whose fields carry no `json` tags and so
/// arrive in Go's default casing (`ID`, `CreatedAt`, `Manifest`) — unlike the rest
/// of the protocol. The nested manifest *is* tagged snake_case. Only the fields the
/// Backups panel shows are modelled; unknown manifest fields are ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Snapshot id (a sortable timestamp plus a random suffix).
    #[serde(rename = "ID")]
    pub id: String,
    /// Creation time, RFC 3339 as Go writes it.
    #[serde(rename = "CreatedAt")]
    pub created_at: String,
    /// The manifest the snapshot was sealed with.
    #[serde(rename = "Manifest")]
    pub manifest: BackupManifest,
}

/// The part of a snapshot manifest the panel needs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupManifest {
    /// Manifest format version.
    #[serde(default)]
    pub version: u32,
    /// Server version that wrote the snapshot.
    #[serde(default)]
    pub server_version: String,
    /// Total bytes across every chunk the snapshot captured.
    #[serde(default)]
    pub chunk_bytes: i64,
    /// Every chunk captured, with the checksum taken when it was written.
    #[serde(default)]
    pub chunks: Vec<BackupChunk>,
}

/// One chunk inside a [`BackupManifest`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupChunk {
    /// Chunk id.
    pub id: String,
    /// Stored size in bytes.
    pub size: i64,
    /// Hex SHA-256 recorded when the chunk was copied.
    pub sha256: String,
}

impl BackupManifest {
    /// How many chunks the snapshot holds.
    #[must_use]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_names_are_snake_case_on_the_wire() {
        // The Go server is written against these exact keys, so a rename here is
        // a protocol break and this test is the tripwire.
        let revision = Revision {
            revision: 3,
            parent: 2,
            dir_id: "ABCDEFGHIJ".into(),
            cipher_name: "KLMN".into(),
            manifest: "YWJj".into(),
            size: 12,
            modified_unix: 1_700_000_000,
            deleted: false,
        };
        let json = serde_json::to_string(&revision).expect("serializable");
        for key in [
            "\"revision\"",
            "\"parent\"",
            "\"dir_id\"",
            "\"cipher_name\"",
            "\"manifest\"",
            "\"modified_unix\"",
            "\"deleted\"",
        ] {
            assert!(json.contains(key), "missing {key} in {json}");
        }
        assert!(
            !json.contains("modifiedUnix") && !json.contains("dirId"),
            "camelCase leaked into the protocol: {json}"
        );
    }

    #[test]
    fn a_revision_never_carries_a_plaintext_name() {
        // Structural guard for the zero-knowledge claim: the only name-ish fields
        // are the directory id and the encrypted name, and neither is checked
        // against the plaintext tree on the way in.
        let json = serde_json::to_string(&Revision {
            revision: 1,
            parent: 0,
            dir_id: "AA".into(),
            cipher_name: "BB".into(),
            manifest: String::new(),
            size: 0,
            modified_unix: 0,
            deleted: true,
        })
        .expect("serializable");
        assert!(!json.contains("path"));
    }

    #[test]
    fn a_page_round_trips() {
        let page = RevisionPage {
            revisions: Vec::new(),
            upto: 0,
        };
        let json = serde_json::to_string(&page).expect("serializable");
        let back: RevisionPage = serde_json::from_str(&json).expect("deserializable");
        assert_eq!(back, page);
    }

    #[test]
    fn a_null_manifest_from_the_server_is_read_as_empty() {
        // The Go server writes a tombstone's nil []byte manifest as JSON null;
        // this is the tripwire that the Rust client still parses it. Regression
        // caught against the real server during the M3 end-to-end smoke test.
        let json = r#"{"revisions":[{
            "vault_id":"v","revision":4,"parent":3,
            "dir_id":"AA","cipher_name":"BB","manifest":null,
            "size":0,"modified_unix":1,"deleted":true,"stored_at":"2026-01-01T00:00:00Z"
        }],"upto":4}"#;
        let page: RevisionPage = serde_json::from_str(json).expect("tombstone parses");
        assert_eq!(page.revisions[0].manifest, "", "null became empty");
        assert!(page.revisions[0].deleted);
        assert_eq!(page.upto, 4);
    }
}
