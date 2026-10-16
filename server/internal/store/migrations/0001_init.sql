-- Initial schema for the durable store (M2).
--
-- This is written now rather than in M2 for one reason: the API, the backup
-- engine, and the protocol types are all already shaped around it, so the
-- migration is the place where any disagreement between them shows up.
--
-- Two rules govern this schema:
--
--   1. Nothing here stores anything a key is needed to read. Filename, path, and
--      content are absent by design; dir_id and cipher_name are ciphertext the
--      server only compares for equality.
--   2. Sizes are stored in plaintext. A client cannot be told how much to download
--      without it, and that is the metadata the design accepts leaking.

PRAGMA foreign_keys = ON;

-- One row per stored chunk. The id is the address, derived by the client from an
-- HMAC of the plaintext, so re-uploading identical content cannot create a second
-- row.
CREATE TABLE IF NOT EXISTS chunk (
    id         TEXT    PRIMARY KEY CHECK (length(id) BETWEEN 8 AND 128),
    size       INTEGER NOT NULL CHECK (size >= 0),
    sha256     TEXT,                       -- taken at rest, for snapshot verify
    stored_at  INTEGER NOT NULL            -- seconds since the Unix epoch
);

-- A vault is a namespace of revisions. v1 has exactly one row; the table exists so
-- a second vault is a code change rather than a schema change.
CREATE TABLE IF NOT EXISTS vault (
    id     TEXT PRIMARY KEY,
    created_at INTEGER NOT NULL
);

-- One row per committed file revision. parent is the revision this one was
-- derived from, and the UNIQUE index on (vault_id, revision) is what makes a lost
-- update a constraint violation instead of silent data loss.
CREATE TABLE IF NOT EXISTS revision (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    vault_id      TEXT    NOT NULL REFERENCES vault(id) ON DELETE CASCADE,
    revision      INTEGER NOT NULL,
    parent        INTEGER NOT NULL,
    dir_id        TEXT    NOT NULL,        -- ciphertext directory id
    cipher_name   TEXT    NOT NULL,        -- ciphertext file name
    manifest      BLOB    NOT NULL,        -- encrypted chunk list, opaque here
    size          INTEGER NOT NULL,        -- plaintext size, needed to allocate
    modified_unix INTEGER NOT NULL,
    deleted       INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
    stored_at     INTEGER NOT NULL,
    UNIQUE (vault_id, revision)
);

CREATE INDEX IF NOT EXISTS revision_vault_since
    ON revision (vault_id, revision);

-- Which chunks a revision needs. This is the reference table garbage collection
-- reads, and it is why a snapshot must be counted here too: a chunk is only
-- collectable when no revision *and* no retained snapshot points at it.
CREATE TABLE IF NOT EXISTS revision_chunk (
    revision_id INTEGER NOT NULL REFERENCES revision(id) ON DELETE CASCADE,
    chunk_id    TEXT    NOT NULL REFERENCES chunk(id),
    position    INTEGER NOT NULL,          -- order within the file
    PRIMARY KEY (revision_id, position)
);

CREATE INDEX IF NOT EXISTS revision_chunk_chunk
    ON revision_chunk (chunk_id);

-- Snapshots the server has taken. The bundle itself lives in the backup target;
-- this table records what was taken and under which retention policy, so `prune`
-- can explain its decisions and a stale row can be reconciled against the target.
CREATE TABLE IF NOT EXISTS snapshot (
    id           TEXT    PRIMARY KEY,
    created_at   INTEGER NOT NULL,
    manifest_path TEXT   NOT NULL,
    chunk_count  INTEGER NOT NULL,
    chunk_bytes  INTEGER NOT NULL,
    policy_hourly  INTEGER NOT NULL,
    policy_daily   INTEGER NOT NULL,
    policy_weekly  INTEGER NOT NULL,
    policy_monthly INTEGER NOT NULL,
    retired_at   INTEGER                  -- set when retention deleted the bundle
);

CREATE INDEX IF NOT EXISTS snapshot_created
    ON snapshot (created_at DESC);
