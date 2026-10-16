package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// metadataFileName is the bookkeeping file inside DataDir, and the name a restored
// snapshot writes. Open adopts one of these when it finds it beside an empty
// database, so `syncboxd restore` produces a directory the server can start from.
const metadataFileName = "metadata.json"

// Durable is a Store that survives a restart: chunk bytes live as files under
// DataDir/chunks, and the bookkeeping about them lives in a SQLite database in
// DataDir. It satisfies the same Store interface as Memory, so the API and the
// backup engine do not change between a test double and a real deployment.
//
// The server never opens a chunk for anything but copying it. A chunk file's name
// is the id the client derived from the plaintext, and the database records only
// opaque facts about it — a size, a timestamp, an opaque encrypted manifest.
type Durable struct {
	db        *sql.DB
	dir       string
	chunksDir string
	maxChunk  int64
	now       func() time.Time
}

// compile-time check that Durable satisfies the interface, alongside Memory.
var _ Store = (*Durable)(nil)

// Open prepares a durable store rooted at dir, creating the directory layout and
// applying any pending migrations. An empty database beside a restored
// metadata.json is seeded from it, which is how an offline restore becomes a
// running server.
func Open(dir string, maxChunk int64) (*Durable, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("store: durable store needs a data directory")
	}
	if maxChunk <= 0 {
		maxChunk = 8 << 20
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("creating data directory %s: %w", dir, err)
	}
	chunksDir := filepath.Join(dir, "chunks")
	if err := os.MkdirAll(chunksDir, 0o750); err != nil {
		return nil, fmt.Errorf("creating chunk directory %s: %w", chunksDir, err)
	}

	db, err := openSQLite(filepath.Join(dir, "syncbox.sqlite"))
	if err != nil {
		return nil, err
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}

	st := &Durable{
		db:        db,
		dir:       dir,
		chunksDir: chunksDir,
		maxChunk:  maxChunk,
		now:       time.Now,
	}
	if err := st.seedFromRestore(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return st, nil
}

// openSQLite opens the database with the pragmas the server relies on, applied per
// connection: foreign keys (off by default in SQLite), WAL so reads do not block
// the single writer, a busy timeout so brief contention waits instead of failing,
// and immediate write transactions so two concurrent commits cannot deadlock on a
// lock upgrade.
func openSQLite(path string) (*sql.DB, error) {
	dsn := "file:" + filepath.ToSlash(path) +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(15000)" +
		"&_pragma=foreign_keys(1)" +
		"&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening database %s: %w", path, err)
	}
	// Ping forces the first connection, so a bad path or pragma surfaces here
	// rather than at the first request.
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("opening database %s: %w", path, err)
	}
	return db, nil
}

// Close releases the database handle. It is not part of the Store interface —
// Memory needs no equivalent — but a caller holding a Durable should close it.
func (d *Durable) Close() error {
	if err := d.db.Close(); err != nil {
		return fmt.Errorf("closing database: %w", err)
	}
	return nil
}

// Location describes the store for logs and the health endpoint.
func (d *Durable) Location() string { return d.dir }

// chunkPath resolves an id to its file, refusing anything that is not a plain,
// well-formed content address so a client-supplied id cannot traverse directories.
func (d *Durable) chunkPath(id string) (string, error) {
	if err := CheckChunkID(id); err != nil {
		return "", err
	}
	return filepath.Join(d.chunksDir, id), nil
}

// ChunkPath returns the filesystem path holding a chunk, for the backup engine to
// hard link rather than copy. It reports ErrNotFound when the metadata row exists
// but its file does not.
func (d *Durable) ChunkPath(ctx context.Context, id string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("path for chunk %s: %w", id, err)
	}
	path, err := d.chunkPath(id)
	if err != nil {
		return "", err
	}
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", fmt.Errorf("%w: chunk %s", ErrNotFound, id)
		}
		return "", fmt.Errorf("checking chunk %s on disk: %w", id, err)
	}
	return path, nil
}

// PutChunk stores body under id as a file, then records it in the database. The
// write happens before the insert on purpose: a crash in between leaves a chunk
// file no row points at, which is invisible and harmless, whereas a row pointing at
// a missing file would be a broken chunk.
func (d *Durable) PutChunk(ctx context.Context, id string, body io.Reader) (int64, error) {
	if err := CheckChunkID(id); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("storing chunk %s: %w", id, err)
	}

	// The content address already present means the identical bytes are on disk;
	// there is nothing to write and the body need not be read.
	var found int64
	err := d.db.QueryRowContext(ctx, `SELECT 1 FROM chunk WHERE id = ?`, id).Scan(&found)
	if err == nil {
		return 0, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("checking chunk %s: %w", id, err)
	}

	size, err := d.writeChunkFile(ctx, id, body)
	if err != nil {
		return 0, err
	}

	res, err := d.db.ExecContext(ctx,
		`INSERT OR IGNORE INTO chunk (id, size, stored_at) VALUES (?, ?, ?)`,
		id, size, d.now().Unix())
	if err != nil {
		return 0, fmt.Errorf("recording chunk %s: %w", id, err)
	}
	stored, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("recording chunk %s: %w", id, err)
	}
	// RowsAffected 0 means a concurrent upload of the same id won the race; the
	// bytes are identical, so nothing new was logically stored.
	return stored * size, nil
}

// writeChunkFile streams body into a temporary file, enforces the size limit, and
// renames it into place so a partial body never appears at the final path.
func (d *Durable) writeChunkFile(ctx context.Context, id string, body io.Reader) (int64, error) {
	path, err := d.chunkPath(id)
	if err != nil {
		return 0, err
	}

	tmp, err := os.CreateTemp(d.chunksDir, ".syncbox-partial-*")
	if err != nil {
		return 0, fmt.Errorf("creating temporary chunk file: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { tmp.Close(); os.Remove(tmpName) }

	// Read one byte past the limit so an oversized upload is noticed without
	// buffering more than we are willing to hold on disk.
	written, err := io.Copy(tmp, io.LimitReader(body, d.maxChunk+1))
	if err != nil {
		cleanup()
		return 0, fmt.Errorf("writing chunk %s: %w", id, err)
	}
	if written > d.maxChunk {
		cleanup()
		return 0, fmt.Errorf("%w: chunk %s is over %d bytes", ErrTooLarge, id, d.maxChunk)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return 0, fmt.Errorf("syncing chunk %s: %w", id, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("closing chunk %s: %w", id, err)
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("setting mode on chunk %s: %w", id, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("installing chunk %s: %w", id, err)
	}
	return written, nil
}

// MissingChunks returns the ids the store does not hold, preserving input order.
// It queries in bounded batches so a large chunk list stays within SQLite's limit
// on host parameters.
func (d *Durable) MissingChunks(ctx context.Context, ids []string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("checking chunks: %w", err)
	}

	present, err := d.presentChunks(ctx, ids)
	if err != nil {
		return nil, err
	}
	missing := make([]string, 0, len(ids))
	for _, id := range ids {
		if !present[id] {
			missing = append(missing, id)
		}
	}
	return missing, nil
}

// presentChunks returns the subset of ids the store holds.
func (d *Durable) presentChunks(ctx context.Context, ids []string) (map[string]bool, error) {
	const batch = 500
	present := make(map[string]bool)
	for start := 0; start < len(ids); start += batch {
		end := min(start+batch, len(ids))
		group := ids[start:end]

		args := make([]any, len(group))
		for i, id := range group {
			args[i] = id
		}
		query := `SELECT id FROM chunk WHERE id IN (` + placeholders(len(group)) + `)`
		rows, err := d.db.QueryContext(ctx, query, args...)
		if err != nil {
			return nil, fmt.Errorf("checking chunks: %w", err)
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return nil, fmt.Errorf("checking chunks: %w", err)
			}
			present[id] = true
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, fmt.Errorf("checking chunks: %w", err)
		}
		rows.Close()
	}
	return present, nil
}

// OpenChunk returns a reader over a stored chunk.
func (d *Durable) OpenChunk(ctx context.Context, id string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("opening chunk %s: %w", id, err)
	}
	path, err := d.chunkPath(id)
	if err != nil {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: chunk %s", ErrNotFound, id)
		}
		return nil, fmt.Errorf("opening chunk %s: %w", id, err)
	}
	return file, nil
}

// ChunkSize returns a chunk's size.
func (d *Durable) ChunkSize(ctx context.Context, id string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("sizing chunk %s: %w", id, err)
	}
	var size int64
	err := d.db.QueryRowContext(ctx, `SELECT size FROM chunk WHERE id = ?`, id).Scan(&size)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, fmt.Errorf("%w: chunk %s", ErrNotFound, id)
	}
	if err != nil {
		return 0, fmt.Errorf("sizing chunk %s: %w", id, err)
	}
	return size, nil
}

// Commit appends a revision, rejecting one whose parent is not the vault's current
// head. The whole check-and-append runs in one immediate transaction, so two
// racing clients cannot both see the same head and both append: one sees the other's
// commit and loses.
func (d *Durable) Commit(ctx context.Context, rev Revision) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("committing to vault %s: %w", rev.VaultID, err)
	}
	if rev.VaultID == "" {
		return 0, errors.New("revision has no vault id")
	}

	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("beginning commit for vault %s: %w", rev.VaultID, err)
	}
	defer tx.Rollback()

	now := d.now()
	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO vault (id, created_at) VALUES (?, ?)`, rev.VaultID, now.Unix()); err != nil {
		return 0, fmt.Errorf("registering vault %s: %w", rev.VaultID, err)
	}

	var head int64
	if err := tx.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(revision), 0) FROM revision WHERE vault_id = ?`, rev.VaultID).Scan(&head); err != nil {
		return 0, fmt.Errorf("reading head for vault %s: %w", rev.VaultID, err)
	}
	if int64(rev.Parent) != head {
		return 0, fmt.Errorf("%w: vault %s is at revision %d, client committed against %d",
			ErrConflict, rev.VaultID, head, rev.Parent)
	}

	next := uint64(head + 1)
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO revision
			(vault_id, revision, parent, dir_id, cipher_name, manifest, size, modified_unix, deleted, stored_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rev.VaultID, next, rev.Parent, rev.DirID, rev.CipherName, manifestBytes(rev.Manifest),
		rev.Size, rev.ModifiedAt, boolInt(rev.Deleted), now.Unix()); err != nil {
		return 0, fmt.Errorf("appending revision %d for vault %s: %w", next, rev.VaultID, err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("committing revision for vault %s: %w", rev.VaultID, err)
	}
	return next, nil
}

// RevisionsSince returns revisions newer than since, oldest first, with the highest
// revision the vault holds.
func (d *Durable) RevisionsSince(ctx context.Context, vaultID string, since uint64, limit int) ([]Revision, uint64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, fmt.Errorf("listing revisions for vault %s: %w", vaultID, err)
	}
	if limit <= 0 {
		limit = 500
	}

	var head int64
	if err := d.db.QueryRowContext(ctx,
		`SELECT COALESCE(MAX(revision), 0) FROM revision WHERE vault_id = ?`, vaultID).Scan(&head); err != nil {
		return nil, 0, fmt.Errorf("reading head for vault %s: %w", vaultID, err)
	}

	rows, err := d.db.QueryContext(ctx, `
		SELECT revision, parent, dir_id, cipher_name, manifest, size, modified_unix, deleted, stored_at
		FROM revision
		WHERE vault_id = ? AND revision > ?
		ORDER BY revision ASC
		LIMIT ?`, vaultID, int64(since), limit)
	if err != nil {
		return nil, 0, fmt.Errorf("listing revisions for vault %s: %w", vaultID, err)
	}
	defer rows.Close()

	out := make([]Revision, 0, min(limit, 64))
	for rows.Next() {
		rev, err := scanRevision(rows)
		if err != nil {
			return nil, 0, fmt.Errorf("listing revisions for vault %s: %w", vaultID, err)
		}
		rev.VaultID = vaultID
		out = append(out, rev)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("listing revisions for vault %s: %w", vaultID, err)
	}
	return out, uint64(head), nil
}

// Stats summarises the store. LargestChunk is the largest chunk actually stored,
// or zero when the store is empty.
func (d *Durable) Stats(ctx context.Context) (Stats, error) {
	if err := ctx.Err(); err != nil {
		return Stats{}, fmt.Errorf("reading stats: %w", err)
	}

	var stats Stats
	var largest sql.NullInt64
	err := d.db.QueryRowContext(ctx,
		`SELECT COUNT(*), COALESCE(SUM(size), 0), MAX(size) FROM chunk`).
		Scan(&stats.Chunks, &stats.ChunkBytes, &largest)
	if err != nil {
		return Stats{}, fmt.Errorf("summarising chunks: %w", err)
	}
	stats.LargestChunk = largest.Int64

	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM revision`).Scan(&stats.Revisions); err != nil {
		return Stats{}, fmt.Errorf("summarising revisions: %w", err)
	}
	return stats, nil
}

// ChunkIDs lists stored chunk ids, sorted.
func (d *Durable) ChunkIDs(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("listing chunks: %w", err)
	}
	rows, err := d.db.QueryContext(ctx, `SELECT id FROM chunk ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("listing chunks: %w", err)
	}
	defer rows.Close()

	ids := make([]string, 0, 64)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("listing chunks: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("listing chunks: %w", err)
	}
	return ids, nil
}

// DumpMetadata serialises the bookkeeping for a snapshot, read within a single
// transaction so the document reflects one instant even as commits continue around
// it. It contains no chunk content.
func (d *Durable) DumpMetadata(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dumping metadata: %w", err)
	}

	tx, err := d.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("beginning metadata read: %w", err)
	}
	defer tx.Rollback()

	doc, err := dumpMetadataTx(ctx, tx)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("finishing metadata read: %w", err)
	}
	return encodeMetadata(doc)
}

// ImportMetadata rebuilds the tables from a snapshot's metadata document. Rows are
// inserted idempotently, so importing twice or over a partly-populated store does
// not duplicate anything. It returns the counts taken in.
func (d *Durable) ImportMetadata(ctx context.Context, doc Metadata) (chunks, revisions int, err error) {
	tx, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("beginning metadata import: %w", err)
	}
	defer tx.Rollback()

	for _, vault := range doc.Vaults {
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO vault (id, created_at) VALUES (?, ?)`, vault, d.now().Unix()); err != nil {
			return 0, 0, fmt.Errorf("importing vault %s: %w", vault, err)
		}
	}
	for _, chunk := range doc.Chunks {
		if err := CheckChunkID(chunk.ID); err != nil {
			return 0, 0, err
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT OR IGNORE INTO chunk (id, size, stored_at) VALUES (?, ?, ?)`,
			chunk.ID, chunk.Size, chunk.StoredAt.Unix()); err != nil {
			return 0, 0, fmt.Errorf("importing chunk %s: %w", chunk.ID, err)
		}
		chunks++
	}
	for _, vaultID := range sortedKeys(doc.Revisions) {
		for _, rev := range doc.Revisions[vaultID] {
			if _, err := tx.ExecContext(ctx,
				`INSERT OR IGNORE INTO vault (id, created_at) VALUES (?, ?)`, vaultID, d.now().Unix()); err != nil {
				return 0, 0, fmt.Errorf("importing vault %s: %w", vaultID, err)
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT OR IGNORE INTO revision
					(vault_id, revision, parent, dir_id, cipher_name, manifest, size, modified_unix, deleted, stored_at)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				vaultID, rev.Revision, rev.Parent, rev.DirID, rev.CipherName, manifestBytes(rev.Manifest),
				rev.Size, rev.ModifiedAt, boolInt(rev.Deleted), rev.StoredAt.Unix()); err != nil {
				return 0, 0, fmt.Errorf("importing revision %d for %s: %w", rev.Revision, vaultID, err)
			}
			revisions++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("committing metadata import: %w", err)
	}
	return chunks, revisions, nil
}

// seedFromRestore adopts a metadata.json left beside a fresh, empty database — the
// product of `syncboxd restore` — and renames the file aside so a later restart does
// not repeat the import. A populated store ignores the file entirely.
func (d *Durable) seedFromRestore(ctx context.Context) error {
	path := filepath.Join(d.dir, metadataFileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	var existing int
	if err := d.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM revision`).Scan(&existing); err != nil {
		return fmt.Errorf("checking store before seed: %w", err)
	}
	if existing > 0 {
		// The database already has history; a leftover metadata.json is stale.
		return nil
	}

	doc, err := DecodeMetadata(data)
	if err != nil {
		return fmt.Errorf("seeding from %s: %w", path, err)
	}
	if _, _, err := d.ImportMetadata(ctx, doc); err != nil {
		return fmt.Errorf("seeding from %s: %w", path, err)
	}
	if err := os.Rename(path, path+".imported"); err != nil {
		return fmt.Errorf("retiring seeded %s: %w", path, err)
	}
	return nil
}

// dumpMetadataTx reads the whole bookkeeping set from within an open transaction.
func dumpMetadataTx(ctx context.Context, tx *sql.Tx) (Metadata, error) {
	doc := Metadata{Chunks: []Chunk{}, Vaults: []string{}, Revisions: map[string][]Revision{}}

	chunkRows, err := tx.QueryContext(ctx, `SELECT id, size, stored_at FROM chunk ORDER BY id`)
	if err != nil {
		return Metadata{}, fmt.Errorf("reading chunks for dump: %w", err)
	}
	defer chunkRows.Close()
	for chunkRows.Next() {
		var (
			id    string
			size  int64
			stamp int64
		)
		if err := chunkRows.Scan(&id, &size, &stamp); err != nil {
			return Metadata{}, fmt.Errorf("reading chunks for dump: %w", err)
		}
		doc.Chunks = append(doc.Chunks, Chunk{ID: id, Size: size, StoredAt: time.Unix(stamp, 0).UTC()})
	}
	if err := chunkRows.Err(); err != nil {
		return Metadata{}, fmt.Errorf("reading chunks for dump: %w", err)
	}

	vaultRows, err := tx.QueryContext(ctx, `SELECT id FROM vault ORDER BY id`)
	if err != nil {
		return Metadata{}, fmt.Errorf("reading vaults for dump: %w", err)
	}
	defer vaultRows.Close()
	for vaultRows.Next() {
		var id string
		if err := vaultRows.Scan(&id); err != nil {
			return Metadata{}, fmt.Errorf("reading vaults for dump: %w", err)
		}
		doc.Vaults = append(doc.Vaults, id)
	}
	if err := vaultRows.Err(); err != nil {
		return Metadata{}, fmt.Errorf("reading vaults for dump: %w", err)
	}

	revRows, err := tx.QueryContext(ctx, `
		SELECT vault_id, revision, parent, dir_id, cipher_name, manifest, size, modified_unix, deleted, stored_at
		FROM revision
		ORDER BY vault_id, revision`)
	if err != nil {
		return Metadata{}, fmt.Errorf("reading revisions for dump: %w", err)
	}
	defer revRows.Close()
	for revRows.Next() {
		var (
			vaultID string
			rev     Revision
			deleted int
			stamp   int64
		)
		if err := revRows.Scan(
			&vaultID, &rev.Revision, &rev.Parent, &rev.DirID, &rev.CipherName,
			&rev.Manifest, &rev.Size, &rev.ModifiedAt, &deleted, &stamp); err != nil {
			return Metadata{}, fmt.Errorf("reading revisions for dump: %w", err)
		}
		rev.Deleted = deleted != 0
		rev.StoredAt = time.Unix(stamp, 0).UTC()
		rev.VaultID = vaultID
		doc.Revisions[vaultID] = append(doc.Revisions[vaultID], rev)
	}
	if err := revRows.Err(); err != nil {
		return Metadata{}, fmt.Errorf("reading revisions for dump: %w", err)
	}
	return doc, nil
}

// scanRevision reads one revision row into a Revision. stored_at is stored as Unix
// seconds and deleted as 0/1, so both go through a temporary rather than scanning
// straight into time.Time / bool, which database/sql will not convert.
func scanRevision(rows *sql.Rows) (Revision, error) {
	var (
		rev     Revision
		deleted int
		stamp   int64
	)
	err := rows.Scan(
		&rev.Revision, &rev.Parent, &rev.DirID, &rev.CipherName, &rev.Manifest,
		&rev.Size, &rev.ModifiedAt, &deleted, &stamp)
	if err != nil {
		return rev, err
	}
	rev.Deleted = deleted != 0
	rev.StoredAt = time.Unix(stamp, 0).UTC()
	return rev, nil
}

// placeholders returns "?,?,…" for n parameters.
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// boolInt maps a Go bool to SQLite's 0/1.
func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// manifestBytes keeps a nil manifest from becoming SQL NULL, which the NOT NULL
// column rejects — and, under INSERT OR IGNORE, which would silently drop the
// revision rather than error. An empty blob is the correct encoding for "no
// manifest"; only the UNIQUE(vault_id, revision) constraint should be ignorable.
func manifestBytes(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

// sortedKeys returns the keys of a map in sorted order, so an import applies
// revisions in a stable sequence.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
