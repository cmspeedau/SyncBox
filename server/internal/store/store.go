// Package store keeps the server's bookkeeping: which chunks it holds, and which
// revisions a vault has committed.
//
// Nothing in here can read a chunk. Chunks arrive as already-encrypted bytes and
// are stored under the id the client derived from their plaintext, so the server's
// whole view of a file is "an object of this size exists at this address".
//
// Memory is the implementation tests use, and the one the durable store is checked
// against (see conformance_test.go). Durable keeps the same bookkeeping across a
// restart. Both satisfy one Store interface, which is the point: the API and the
// backup engine are written against the interface and never learned that durability
// arrived.
package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"time"
)

// Sentinel errors the API maps onto HTTP statuses.
var (
	// ErrNotFound means the chunk or vault revision does not exist.
	ErrNotFound = errors.New("not found")
	// ErrConflict means a commit's parent is not the vault's current head, which
	// is how the server detects two clients editing the same file without being
	// able to read either.
	ErrConflict = errors.New("revision conflict")
	// ErrTooLarge means a body exceeded the configured limit.
	ErrTooLarge = errors.New("body too large")
	// ErrBadChunkID means the id is not a well-formed content address.
	ErrBadChunkID = errors.New("malformed chunk id")
)

// Chunk is one stored object.
type Chunk struct {
	ID       string    `json:"id"`
	Size     int64     `json:"size"`
	StoredAt time.Time `json:"stored_at"`
}

// Revision is one committed file revision.
//
// DirID and CipherName are ciphertext. The server stores them opaquely and only
// ever compares them for equality, which is all it needs to route a revision to
// the right file.
type Revision struct {
	VaultID    string    `json:"vault_id"`
	Revision   uint64    `json:"revision"`
	Parent     uint64    `json:"parent"`
	DirID      string    `json:"dir_id"`
	CipherName string    `json:"cipher_name"`
	Manifest   []byte    `json:"manifest"`
	Size       int64     `json:"size"`
	ModifiedAt int64     `json:"modified_unix"`
	Deleted    bool      `json:"deleted"`
	StoredAt   time.Time `json:"stored_at"`
}

// Stats summarises what the server holds, for the health endpoint.
type Stats struct {
	Chunks       int   `json:"chunks"`
	ChunkBytes   int64 `json:"chunk_bytes"`
	Revisions    int   `json:"revisions"`
	LargestChunk int64 `json:"largest_chunk"`
}

// Store is what the API and the backup engine need.
type Store interface {
	// PutChunk stores body under id, returning the bytes written. Storing the
	// same id twice is a no-op, because the id is a content address.
	PutChunk(ctx context.Context, id string, body io.Reader) (int64, error)
	// MissingChunks returns the ids the store does not hold, preserving order.
	MissingChunks(ctx context.Context, ids []string) ([]string, error)
	// OpenChunk returns a reader over a chunk. It is the caller's to close.
	OpenChunk(ctx context.Context, id string) (io.ReadCloser, error)
	// ChunkSize returns a chunk's size, or ErrNotFound.
	ChunkSize(ctx context.Context, id string) (int64, error)
	// Commit appends a revision and returns its assigned number.
	Commit(ctx context.Context, rev Revision) (uint64, error)
	// RevisionsSince returns revisions newer than since, oldest first, along with
	// the highest revision the vault holds.
	RevisionsSince(ctx context.Context, vaultID string, since uint64, limit int) ([]Revision, uint64, error)
	// Stats summarises the store.
	Stats(ctx context.Context) (Stats, error)
	// ChunkIDs lists every stored chunk id, sorted, for snapshotting.
	ChunkIDs(ctx context.Context) ([]string, error)
	// DumpMetadata serialises the bookkeeping, for a snapshot. It contains no
	// chunk content.
	DumpMetadata(ctx context.Context) ([]byte, error)
}

// Memory is an in-RAM Store.
type Memory struct {
	mu        sync.RWMutex
	chunks    map[string]Chunk
	bodies    map[string][]byte
	revisions map[string][]Revision
	maxChunk  int64
	now       func() time.Time
}

// compile-time check that Memory satisfies the interface it exists to demonstrate.
var _ Store = (*Memory)(nil)

// NewMemory returns an empty store that limits chunks to maxChunk bytes.
func NewMemory(maxChunk int64) *Memory {
	if maxChunk <= 0 {
		maxChunk = 1 << 20
	}
	return &Memory{
		chunks:    make(map[string]Chunk),
		bodies:    make(map[string][]byte),
		revisions: make(map[string][]Revision),
		maxChunk:  maxChunk,
		now:       time.Now,
	}
}

// PutChunk stores body under id.
func (m *Memory) PutChunk(ctx context.Context, id string, body io.Reader) (int64, error) {
	if err := CheckChunkID(id); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("storing chunk %s: %w", id, err)
	}

	// Read one byte past the limit so an oversized body is noticed without
	// buffering more than we are willing to hold.
	data, err := io.ReadAll(io.LimitReader(body, m.maxChunk+1))
	if err != nil {
		return 0, fmt.Errorf("reading chunk body for %s: %w", id, err)
	}
	if int64(len(data)) > m.maxChunk {
		return 0, fmt.Errorf("%w: chunk %s is over %d bytes", ErrTooLarge, id, m.maxChunk)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.chunks[id]; exists {
		// Content address already present: the bytes are identical by
		// construction, so there is nothing to write.
		return 0, nil
	}
	m.chunks[id] = Chunk{ID: id, Size: int64(len(data)), StoredAt: m.now()}
	m.bodies[id] = data
	return int64(len(data)), nil
}

// MissingChunks returns the ids the store does not hold.
func (m *Memory) MissingChunks(ctx context.Context, ids []string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("checking chunks: %w", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	missing := make([]string, 0, len(ids))
	for _, id := range ids {
		if _, ok := m.chunks[id]; !ok {
			missing = append(missing, id)
		}
	}
	return missing, nil
}

// OpenChunk returns a reader over a stored chunk.
func (m *Memory) OpenChunk(ctx context.Context, id string) (io.ReadCloser, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("opening chunk %s: %w", id, err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	data, ok := m.bodies[id]
	if !ok {
		return nil, fmt.Errorf("%w: chunk %s", ErrNotFound, id)
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// ChunkSize returns a chunk's size.
func (m *Memory) ChunkSize(ctx context.Context, id string) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("sizing chunk %s: %w", id, err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	chunk, ok := m.chunks[id]
	if !ok {
		return 0, fmt.Errorf("%w: chunk %s", ErrNotFound, id)
	}
	return chunk.Size, nil
}

// Commit appends a revision, rejecting one whose parent is not the current head.
func (m *Memory) Commit(ctx context.Context, rev Revision) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("committing to vault %s: %w", rev.VaultID, err)
	}
	if rev.VaultID == "" {
		return 0, errors.New("revision has no vault id")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	history := m.revisions[rev.VaultID]
	var head uint64
	if len(history) > 0 {
		head = history[len(history)-1].Revision
	}
	if rev.Parent != head {
		return 0, fmt.Errorf("%w: vault %s is at revision %d, client committed against %d",
			ErrConflict, rev.VaultID, head, rev.Parent)
	}

	next := head + 1
	rev.Revision = next
	rev.StoredAt = m.now()
	m.revisions[rev.VaultID] = append(history, rev)
	return next, nil
}

// RevisionsSince returns revisions newer than since.
func (m *Memory) RevisionsSince(ctx context.Context, vaultID string, since uint64, limit int) ([]Revision, uint64, error) {
	if err := ctx.Err(); err != nil {
		return nil, 0, fmt.Errorf("listing revisions for vault %s: %w", vaultID, err)
	}
	if limit <= 0 {
		limit = 500
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	history := m.revisions[vaultID]
	var head uint64
	if len(history) > 0 {
		head = history[len(history)-1].Revision
	}

	out := make([]Revision, 0, limit)
	for _, rev := range history {
		if rev.Revision <= since {
			continue
		}
		out = append(out, rev)
		if len(out) >= limit {
			break
		}
	}
	return out, head, nil
}

// Stats summarises the store.
func (m *Memory) Stats(ctx context.Context) (Stats, error) {
	if err := ctx.Err(); err != nil {
		return Stats{}, fmt.Errorf("reading stats: %w", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	stats := Stats{LargestChunk: m.maxChunk}
	for _, chunk := range m.chunks {
		stats.Chunks++
		stats.ChunkBytes += chunk.Size
	}
	for _, history := range m.revisions {
		stats.Revisions += len(history)
	}
	return stats, nil
}

// ChunkIDs lists stored chunk ids, sorted.
func (m *Memory) ChunkIDs(ctx context.Context) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("listing chunks: %w", err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	ids := make([]string, 0, len(m.chunks))
	for id := range m.chunks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// DumpMetadata serialises the bookkeeping for a snapshot.
func (m *Memory) DumpMetadata(ctx context.Context) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("dumping metadata: %w", err)
	}
	m.mu.RLock()
	chunks := make([]Chunk, 0, len(m.chunks))
	for _, chunk := range m.chunks {
		chunks = append(chunks, chunk)
	}
	vaults := make([]string, 0, len(m.revisions))
	for vault := range m.revisions {
		vaults = append(vaults, vault)
	}
	revisions := make(map[string][]Revision, len(m.revisions))
	for vault, history := range m.revisions {
		revisions[vault] = append([]Revision(nil), history...)
	}
	m.mu.RUnlock()

	sort.Slice(chunks, func(i, j int) bool { return chunks[i].ID < chunks[j].ID })
	sort.Strings(vaults)

	return encodeMetadata(Metadata{Chunks: chunks, Vaults: vaults, Revisions: revisions})
}

// Metadata is the bookkeeping a snapshot captures: which chunks exist and which
// revisions each vault holds. It never contains chunk content. The durable store
// and the in-memory store both serialise to this one shape so the backup engine,
// the restore path, and the checksums in a manifest all speak a single format.
type Metadata struct {
	Chunks    []Chunk               `json:"chunks"`
	Vaults    []string              `json:"vaults"`
	Revisions map[string][]Revision `json:"revisions"`
}

// encodeMetadata renders the document with a stable field order and sorted keys,
// so two snapshots of the same state are byte-identical and a restore can be
// verified against a recorded hash. Callers sort before handing it over.
func encodeMetadata(doc Metadata) ([]byte, error) {
	if doc.Chunks == nil {
		doc.Chunks = []Chunk{}
	}
	if doc.Vaults == nil {
		doc.Vaults = []string{}
	}
	if doc.Revisions == nil {
		doc.Revisions = map[string][]Revision{}
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding metadata: %w", err)
	}
	return data, nil
}

// DecodeMetadata parses a document produced by DumpMetadata. The restore path
// hands it to a durable store to rebuild its tables from a snapshot.
func DecodeMetadata(data []byte) (Metadata, error) {
	var doc Metadata
	if err := json.Unmarshal(data, &doc); err != nil {
		return Metadata{}, fmt.Errorf("decoding metadata: %w", err)
	}
	return doc, nil
}

// CheckChunkID rejects ids that could escape the blob directory or that the
// client would never produce.
//
// The server never decrypts a chunk, so it cannot check an id against its
// content. What it can do is refuse anything that is not shaped like a base32
// content address, which keeps path traversal and absurd filenames out of the
// store.
func CheckChunkID(id string) error {
	if len(id) < 8 || len(id) > 128 {
		return fmt.Errorf("%w: length %d is outside 8..128", ErrBadChunkID, len(id))
	}
	for _, r := range id {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		default:
			return fmt.Errorf("%w: %q is not alphanumeric", ErrBadChunkID, id)
		}
	}
	return nil
}
