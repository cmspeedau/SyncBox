//! A durable [`Index`] backed by SQLite, the client's on-disk state.
//!
//! The point of a durable index is that an interrupted sync resumes without a
//! rescan: [`Index::files`] and the chunk reference counts have to survive the
//! process exiting, which [`crate::MemoryIndex`] cannot do. This type keeps the
//! same records in a small database beside the vault.
//!
//! Semantics are identical to [`crate::MemoryIndex`] — the two share a conformance
//! test in `tests/conformance.rs`, so neither can drift. The reference-count rules
//! are expressed directly in SQL so each is a single atomic statement:
//!
//! * retaining a chunk uses `INSERT … ON CONFLICT DO UPDATE`, keeping the first
//!   non-zero size and adding one to the count;
//! * releasing uses `UPDATE … WHERE refs > 0`, so an unknown chunk changes no row
//!   and a count bottoms out at zero instead of wrapping — the same leniency the
//!   in-memory index allows after an interrupted run.
//!
//! The [`Index`] trait is infallible, matching how the engine codes against it.
//! A failure here means the database file itself is unusable (full disk,
//! corruption), which no sync run can safely continue through, so those cases
//! abort with a clear message rather than pretend the write landed. The
//! constructors, by contrast, return `Result`: opening or creating the file is an
//! ordinary thing to get wrong on a first run.

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use syncbox_crypto::ChunkId;

use crate::types::{DeletedFile, FileEntry};
use crate::Index;

/// Adds one reference to a chunk, recording `?2` as its size the first time it is
/// seen and thereafter keeping whatever size is already stored. This mirrors the
/// in-memory rule that an explicit size (from [`Index::retain_chunk`]) is what
/// pins a chunk's byte count, while a size contributed by [`Index::put_file`] (0)
/// does not overwrite one already known.
const RETAIN_SQL: &str = "INSERT INTO chunks (chunk_id, size, refs) VALUES (?1, ?2, 1)
     ON CONFLICT(chunk_id) DO UPDATE SET
         size = CASE WHEN chunks.size = 0 THEN excluded.size ELSE chunks.size END,
         refs = chunks.refs + 1";

/// Drops one reference, affecting nothing when the chunk is unknown or already
/// unreferenced, so an over-release cannot wrap the count below zero.
const RELEASE_SQL: &str = "UPDATE chunks SET refs = refs - 1 WHERE chunk_id = ?1 AND refs > 0";

/// The [`Index`] the running client uses between sessions.
pub struct SqliteIndex {
    conn: Connection,
}

impl SqliteIndex {
    /// Opens (creating if needed) the index database at `path`.
    ///
    /// Any missing parent directory is created first, so a caller can point the
    /// index at a fresh location. A genuine failure to open the file is returned
    /// rather than swallowed.
    ///
    /// # Errors
    ///
    /// Returns a SQLite error if the file cannot be opened or the schema cannot be
    /// created.
    pub fn open(path: impl AsRef<Path>) -> rusqlite::Result<Self> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                // Best effort; if the directory truly cannot exist, the open below
                // fails with the real reason.
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let conn = Connection::open(path)?;
        Self::init(&conn)?;
        Ok(Self { conn })
    }

    /// An index that lives only in memory, for tests.
    ///
    /// Panics only if SQLite itself refuses to start, which is not a condition the
    /// tests exercise.
    #[must_use]
    pub fn open_in_memory() -> Self {
        let conn = Connection::open_in_memory().expect("open in-memory sqlite");
        Self::init(&conn).expect("init in-memory schema");
        Self { conn }
    }

    fn init(conn: &Connection) -> rusqlite::Result<()> {
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS files (
                 path          TEXT PRIMARY KEY,
                 dir_id        TEXT NOT NULL,
                 cipher_name   TEXT NOT NULL,
                 size          INTEGER NOT NULL,
                 modified_unix INTEGER NOT NULL,
                 revision      INTEGER NOT NULL,
                 local_dirty   INTEGER NOT NULL,
                 remote_dirty  INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS file_chunks (
                 path     TEXT NOT NULL,
                 ord      INTEGER NOT NULL,
                 chunk_id TEXT NOT NULL,
                 PRIMARY KEY (path, ord)
             );
             CREATE INDEX IF NOT EXISTS idx_file_chunks_path ON file_chunks (path);
             CREATE TABLE IF NOT EXISTS chunks (
                 chunk_id TEXT PRIMARY KEY,
                 size     INTEGER NOT NULL,
                 refs     INTEGER NOT NULL
             );
             CREATE TABLE IF NOT EXISTS pending_deletes (
                 dir_id        TEXT NOT NULL,
                 cipher_name   TEXT NOT NULL,
                 path          TEXT NOT NULL,
                 modified_unix INTEGER NOT NULL,
                 PRIMARY KEY (dir_id, cipher_name)
             );
             CREATE TABLE IF NOT EXISTS meta (
                 key   TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );",
        )
    }

    /// Reads the ordered chunk ids recorded for one file path, using the open
    /// connection directly (so it can run inside a larger statement loop).
    fn chunks_for(conn: &Connection, path: &str) -> Vec<ChunkId> {
        let mut stmt = conn
            .prepare_cached("SELECT chunk_id FROM file_chunks WHERE path = ?1 ORDER BY ord")
            .expect("prepare chunk lookup");
        stmt.query_map(params![path], |row| row.get::<_, String>(0))
            .expect("query chunks")
            .map(|r| ChunkId::from_base32(&r.expect("chunk id")))
            .collect()
    }
}

impl Index for SqliteIndex {
    fn file(&self, path: &str) -> Option<FileEntry> {
        let meta = self
            .conn
            .query_row(
                "SELECT path, dir_id, cipher_name, size, modified_unix, revision,
                        local_dirty, remote_dirty
                 FROM files WHERE path = ?1",
                params![path],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, i64>(4)?,
                        row.get::<_, i64>(5)?,
                        row.get::<_, i64>(6)?,
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()
            .expect("query file");
        let (path, dir_id, cipher_name, size, modified_unix, revision, local, remote) = meta?;
        let chunk_ids = Self::chunks_for(&self.conn, &path);
        Some(FileEntry {
            path,
            dir_id: syncbox_crypto::names::DirId::from_base32(&dir_id),
            cipher_name,
            size: size as u64,
            modified_unix,
            revision: revision as u64,
            chunk_ids,
            local_dirty: local != 0,
            remote_dirty: remote != 0,
        })
    }

    fn files(&self) -> Vec<FileEntry> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT path, dir_id, cipher_name, size, modified_unix, revision,
                        local_dirty, remote_dirty
                 FROM files ORDER BY path",
            )
            .expect("prepare files");
        let metas = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, i64>(5)?,
                    row.get::<_, i64>(6)?,
                    row.get::<_, i64>(7)?,
                ))
            })
            .expect("query files")
            .collect::<Result<Vec<_>, _>>()
            .expect("read file rows");

        metas
            .into_iter()
            .map(
                |(path, dir_id, cipher_name, size, modified_unix, revision, local, remote)| {
                    let chunks = Self::chunks_for(&self.conn, &path);
                    FileEntry {
                        path,
                        dir_id: syncbox_crypto::names::DirId::from_base32(&dir_id),
                        cipher_name,
                        size: size as u64,
                        modified_unix,
                        revision: revision as u64,
                        chunk_ids: chunks,
                        local_dirty: local != 0,
                        remote_dirty: remote != 0,
                    }
                },
            )
            .collect()
    }

    fn put_file(&mut self, entry: FileEntry) {
        let FileEntry {
            path,
            dir_id,
            cipher_name,
            size,
            modified_unix,
            revision,
            chunk_ids,
            local_dirty,
            remote_dirty,
        } = entry;
        let chunk_ids: Vec<String> = chunk_ids.iter().map(|c| c.as_str().to_owned()).collect();

        let tx = self.conn.transaction().expect("begin put_file");

        // Drop the old chunk references first, exactly as the in-memory index
        // does, so a rewrite that keeps some chunks leaves those at the right
        // count instead of drifting upward.
        let stale: Vec<String> = {
            let mut stmt = tx
                .prepare("SELECT chunk_id FROM file_chunks WHERE path = ?1")
                .expect("prepare stale");
            stmt.query_map(params![path], |row| row.get::<_, String>(0))
                .expect("query stale")
                .map(|r| r.expect("stale id"))
                .collect()
        };
        for id in &stale {
            tx.execute(RELEASE_SQL, params![id]).expect("release stale");
        }
        tx.execute("DELETE FROM file_chunks WHERE path = ?1", params![path])
            .expect("clear chunks");

        tx.execute(
            "INSERT INTO files (path, dir_id, cipher_name, size, modified_unix, revision,
                               local_dirty, remote_dirty)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(path) DO UPDATE SET
                 dir_id = excluded.dir_id,
                 cipher_name = excluded.cipher_name,
                 size = excluded.size,
                 modified_unix = excluded.modified_unix,
                 revision = excluded.revision,
                 local_dirty = excluded.local_dirty,
                 remote_dirty = excluded.remote_dirty",
            params![
                path,
                dir_id.as_str(),
                cipher_name,
                size as i64,
                modified_unix,
                revision as i64,
                i64::from(local_dirty),
                i64::from(remote_dirty),
            ],
        )
        .expect("upsert file");

        for (ord, id) in chunk_ids.iter().enumerate() {
            tx.execute(
                "INSERT INTO file_chunks (path, ord, chunk_id) VALUES (?1, ?2, ?3)",
                params![path, ord as i64, id],
            )
            .expect("insert chunk link");
            tx.execute(RETAIN_SQL, params![id, 0i64])
                .expect("retain chunk");
        }

        tx.commit().expect("commit put_file");
    }

    fn remove_file(&mut self, path: &str) -> bool {
        let tx = self.conn.transaction().expect("begin remove_file");

        let ids: Vec<String> = {
            let mut stmt = tx
                .prepare("SELECT chunk_id FROM file_chunks WHERE path = ?1")
                .expect("prepare remove chunks");
            stmt.query_map(params![path], |row| row.get::<_, String>(0))
                .expect("query remove chunks")
                .map(|r| r.expect("chunk id"))
                .collect()
        };
        let removed = tx
            .execute("DELETE FROM files WHERE path = ?1", params![path])
            .expect("delete file")
            > 0;
        tx.execute("DELETE FROM file_chunks WHERE path = ?1", params![path])
            .expect("delete file chunks");
        for id in &ids {
            tx.execute(RELEASE_SQL, params![id]).expect("release chunk");
        }

        tx.commit().expect("commit remove_file");
        removed
    }

    fn retain_chunk(&mut self, id: &ChunkId, size: u64) {
        self.conn
            .execute(RETAIN_SQL, params![id.as_str(), size as i64])
            .expect("retain chunk");
    }

    fn release_chunk(&mut self, id: &ChunkId) {
        self.conn
            .execute(RELEASE_SQL, params![id.as_str()])
            .expect("release chunk");
    }

    fn chunk_refs(&self, id: &ChunkId) -> u32 {
        self.conn
            .query_row(
                "SELECT refs FROM chunks WHERE chunk_id = ?1",
                params![id.as_str()],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .expect("query refs")
            .map_or(0, |refs| refs.max(0) as u32)
    }

    fn unreferenced_chunks(&self) -> Vec<ChunkId> {
        let mut stmt = self
            .conn
            .prepare_cached("SELECT chunk_id FROM chunks WHERE refs = 0 ORDER BY chunk_id")
            .expect("prepare unreferenced");
        stmt.query_map([], |row| row.get::<_, String>(0))
            .expect("query unreferenced")
            .map(|r| ChunkId::from_base32(&r.expect("chunk id")))
            .collect()
    }

    fn referenced_bytes(&self) -> u64 {
        self.conn
            .query_row(
                "SELECT COALESCE(SUM(size), 0) FROM chunks WHERE refs > 0",
                [],
                |row| row.get::<_, i64>(0),
            )
            .expect("sum referenced bytes")
            .max(0) as u64
    }

    fn note_delete(&mut self, entry: &FileEntry) {
        self.conn
            .execute(
                "INSERT OR REPLACE INTO pending_deletes
                     (dir_id, cipher_name, path, modified_unix)
                 VALUES (?1, ?2, ?3, ?4)",
                params![
                    entry.dir_id.as_str(),
                    entry.cipher_name,
                    entry.path,
                    entry.modified_unix
                ],
            )
            .expect("note delete");
    }

    fn pending_deletes(&self) -> Vec<DeletedFile> {
        let mut stmt = self
            .conn
            .prepare_cached(
                "SELECT path, dir_id, cipher_name, modified_unix
                 FROM pending_deletes ORDER BY rowid",
            )
            .expect("prepare pending deletes");
        stmt.query_map([], |row| {
            Ok(DeletedFile {
                path: row.get(0)?,
                dir_id: syncbox_crypto::names::DirId::from_base32(&row.get::<_, String>(1)?),
                cipher_name: row.get(2)?,
                modified_unix: row.get(3)?,
            })
        })
        .expect("query pending deletes")
        .collect::<Result<Vec<_>, _>>()
        .expect("read pending delete rows")
    }

    fn clear_deletes(&mut self, keys: &[(syncbox_crypto::names::DirId, String)]) {
        for (dir_id, cipher_name) in keys {
            self.conn
                .execute(
                    "DELETE FROM pending_deletes WHERE dir_id = ?1 AND cipher_name = ?2",
                    params![dir_id.as_str(), cipher_name],
                )
                .expect("clear delete");
        }
    }

    fn meta_value(&self, key: &str) -> Option<String> {
        self.conn
            .query_row(
                "SELECT value FROM meta WHERE key = ?1",
                params![key],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .expect("read meta")
    }

    fn set_meta_value(&mut self, key: &str, value: &str) {
        self.conn
            .execute(
                "INSERT INTO meta (key, value) VALUES (?1, ?2)
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                params![key, value],
            )
            .expect("write meta");
    }
}
