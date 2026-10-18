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
	"crypto/rand"
	"encoding/base32"
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
	// ErrLocationTaken means a live vault already claims the folder a vault is
	// being pointed at. Two vaults sharing one folder would shred each other's
	// index, so the second is refused rather than silently allowed.
	ErrLocationTaken = errors.New("location already in use")
	// ErrBadMode means a space was asked for a mode that is not one of the two
	// a space may have. The API refuses an unknown mode with a code before the
	// store is reached, but the store guards itself too, so no caller can write
	// a mode the registry would then have to guess about.
	ErrBadMode = errors.New("unknown space mode")
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

// Mode is what a space is. A sync space is stored in the clear server-side, so
// the server can index, browse and share it; a vault is encrypted on the client,
// so the server holds only an opaque blob and never a key. One column decides
// which, and nothing else about a space changes with it: the commit protocol,
// the chunk store and the registry read the same in both modes.
//
// Only a vault is encrypted. A sync space relies on TLS in flight and on
// whatever encryption the operator put under the disk, not on us — which is the
// product decision S1's honesty pass makes every sentence agree with.
type Mode string

const (
	// ModeSync is a space the server can read: cleartext names and bytes.
	ModeSync Mode = "sync"
	// ModeVault is a space only a client can read: ciphertext names and bytes.
	ModeVault Mode = "vault"
)

// Valid reports whether m is a mode a space may have. The empty string is not
// valid; a caller that wants the new-registration default must say so with
// ModeSync, so "unset" can never be mistaken for a mode.
func (m Mode) Valid() bool {
	return m == ModeSync || m == ModeVault
}

// VaultInfo is one row of the vault registry: everything the server can know
// about a vault while holding no key. Name and Location are metadata an
// operator typed; Mode says whether the space is stored in the clear or
// encrypted; the rest is bookkeeping counted from revisions. LiveFiles and
// Bytes count only each file's newest revision when that revision is not a
// tombstone, so a deleted-then-reuploaded file counts once and at its current
// size.
type VaultInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Location    string `json:"location"`
	Mode        Mode   `json:"mode"`
	CreatedAt   int64  `json:"created_at"`
	Archived    bool   `json:"archived"`
	Revisions   int    `json:"revisions"`
	LiveFiles   int    `json:"live_files"`
	Bytes       int64  `json:"bytes"`
	LastWriteAt int64  `json:"last_write_at"`
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

	// The vault registry (M10, and the mode column M11 S1 adds). Vaults are
	// server-side facts an operator creates in the console and points clients
	// at, rather than namespaces a client invents silently. Since M11 each
	// space also carries a mode — sync (server-readable) or vault (encrypted)
	// — set when it is registered. Registration through the registry is not yet
	// required — commits still birth vaults implicitly, and the registry
	// reports those too, nameless — until enforcement lands.
	//
	// CreateVault mints a fresh id and registers it under name, in location,
	// with mode. An empty location means the vault's name is the default; an
	// empty mode means ModeSync, the default a new registration gets — the
	// everyday case is a space the server can index, and encryption is the
	// deliberate choice. A mode that is neither sync nor vault is ErrBadMode.
	CreateVault(ctx context.Context, name, location string, mode Mode) (string, error)
	// ListVaults returns every vault, registry-created or implied by stored
	// revisions, with per-vault bookkeeping. Order is by creation, then id.
	ListVaults(ctx context.Context) ([]VaultInfo, error)
	// RenameVault sets an operator's name, or returns ErrNotFound.
	RenameVault(ctx context.Context, id, name string) error
	// SetVaultLocation points a vault at a folder, or returns ErrNotFound. It
	// returns ErrLocationTaken if another live vault already claims it.
	SetVaultLocation(ctx context.Context, id, location string) error
	// SetVaultArchived flags a vault as retired, or returns ErrNotFound.
	SetVaultArchived(ctx context.Context, id string, archived bool) error
	// VaultRegistered reports whether id is a vault the registry knows —
	// created in the console, adopted by migration, or born of a commit made
	// before enforcement. Enforcement refuses a commit to an id this answers
	// false for, rather than birthing a vault nameless.
	VaultRegistered(ctx context.Context, id string) (bool, error)
}

// Memory is an in-RAM Store.
type Memory struct {
	mu        sync.RWMutex
	chunks    map[string]Chunk
	bodies    map[string][]byte
	revisions map[string][]Revision
	vaults    map[string]*memoryVault
	maxChunk  int64
	now       func() time.Time
}

// memoryVault is the registry half of a vault in Memory: what an operator set,
// as opposed to the revision history kept beside it.
type memoryVault struct {
	name      string
	location  string
	mode      Mode
	createdAt int64
	archived  bool
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
		vaults:    make(map[string]*memoryVault),
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

	// Mirror the durable store: a commit is also where an unregistered vault
	// enters the registry, nameless, until enforcement requires registration.
	// It enters as a vault, not a sync space: nothing registered it, so the
	// server keeps claiming it cannot read it rather than exposing names and
	// bytes it was never handed in the clear.
	if _, ok := m.vaults[rev.VaultID]; !ok {
		m.vaults[rev.VaultID] = &memoryVault{createdAt: rev.StoredAt.Unix(), mode: ModeVault}
	}
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

// CreateVault mints a fresh id and registers it under name, in location, with
// mode. An empty location defaults to the vault's name, an empty mode to
// ModeSync, and a location another live vault already claims is refused.
func (m *Memory) CreateVault(ctx context.Context, name, location string, mode Mode) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", fmt.Errorf("creating vault: %w", err)
	}
	if location == "" {
		location = name
	}
	if mode == "" {
		mode = ModeSync
	}
	if !mode.Valid() {
		return "", fmt.Errorf("%w: %q", ErrBadMode, mode)
	}
	id, err := newVaultID()
	if err != nil {
		return "", err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if locationLiveInMemory(m.vaults, location, "") {
		return "", fmt.Errorf("%w: %s", ErrLocationTaken, location)
	}
	m.vaults[id] = &memoryVault{name: name, location: location, mode: mode, createdAt: m.now().Unix()}
	return id, nil
}

// locationLiveInMemory reports whether a live (unarchived) vault other than
// skipID already claims location. An empty location is never a claim, so
// commit-born vaults that were never pointed anywhere do not collide.
func locationLiveInMemory(vaults map[string]*memoryVault, location, skipID string) bool {
	if location == "" {
		return false
	}
	for id, vault := range vaults {
		if id == skipID || vault.archived {
			continue
		}
		if vault.location == location {
			return true
		}
	}
	return false
}

// ListVaults returns every registered or revision-implied vault with its
// bookkeeping.
func (m *Memory) ListVaults(ctx context.Context) ([]VaultInfo, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("listing vaults: %w", err)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	// A vault can exist on either side alone: created in the console before
	// any client pointed at it, or committed into without registration.
	ids := make(map[string]struct{}, len(m.vaults)+len(m.revisions))
	for id := range m.vaults {
		ids[id] = struct{}{}
	}
	for id := range m.revisions {
		ids[id] = struct{}{}
	}

	out := make([]VaultInfo, 0, len(ids))
	for id := range ids {
		info := VaultInfo{ID: id}
		if registered, ok := m.vaults[id]; ok {
			info.Name = registered.name
			info.Location = registered.location
			info.Mode = registered.mode
			info.CreatedAt = registered.createdAt
			info.Archived = registered.archived
		}
		for _, rev := range m.revisions[id] {
			info.Revisions++
			if rev.StoredAt.Unix() > info.LastWriteAt {
				info.LastWriteAt = rev.StoredAt.Unix()
			}
		}
		info.LiveFiles, info.Bytes = liveTally(m.revisions[id])
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt != out[j].CreatedAt {
			return out[i].CreatedAt < out[j].CreatedAt
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// liveTally counts each file's newest revision, skipping tombstones. Revision
// histories are in commit order, so the last entry per (dir, name) wins.
func liveTally(history []Revision) (files int, bytes int64) {
	type fileKey struct{ dirID, cipherName string }
	latest := make(map[fileKey]Revision, len(history))
	for _, rev := range history {
		latest[fileKey{rev.DirID, rev.CipherName}] = rev
	}
	for _, rev := range latest {
		if rev.Deleted {
			continue
		}
		files++
		bytes += rev.Size
	}
	return files, bytes
}

// RenameVault sets an operator's name.
func (m *Memory) RenameVault(ctx context.Context, id, name string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("renaming vault %s: %w", id, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	registered, ok := m.vaults[id]
	if !ok {
		return fmt.Errorf("%w: vault %s", ErrNotFound, id)
	}
	registered.name = name
	return nil
}

// SetVaultLocation points a vault at a folder, refusing one another live vault
// already claims.
func (m *Memory) SetVaultLocation(ctx context.Context, id, location string) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("locating vault %s: %w", id, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	registered, ok := m.vaults[id]
	if !ok {
		return fmt.Errorf("%w: vault %s", ErrNotFound, id)
	}
	if locationLiveInMemory(m.vaults, location, id) {
		return fmt.Errorf("%w: %s", ErrLocationTaken, location)
	}
	registered.location = location
	return nil
}

// SetVaultArchived flags a vault as retired.
func (m *Memory) SetVaultArchived(ctx context.Context, id string, archived bool) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("archiving vault %s: %w", id, err)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	registered, ok := m.vaults[id]
	if !ok {
		return fmt.Errorf("%w: vault %s", ErrNotFound, id)
	}
	registered.archived = archived
	return nil
}

// VaultRegistered reports whether the registry knows this vault. Commit births
// one, CreateVault mints one and a restore imports one, so a vault holding
// revisions always has a row here too.
func (m *Memory) VaultRegistered(ctx context.Context, id string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("checking vault %s: %w", id, err)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	_, ok := m.vaults[id]
	return ok, nil
}

// newVaultID mints a short, typeable vault id: five random bytes as base32,
// eight characters from A–Z2–7 — the alphabet vault root ids already use, so
// a pairing code can be read out loud without a hex table.
func newVaultID() (string, error) {
	var buf [5]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", fmt.Errorf("minting vault id: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf[:]), nil
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
	vaults := make([]string, 0, len(m.revisions)+len(m.vaults))
	for vault := range m.revisions {
		vaults = append(vaults, vault)
	}
	for vault := range m.vaults {
		if _, committed := m.revisions[vault]; !committed {
			vaults = append(vaults, vault)
		}
	}
	revisions := make(map[string][]Revision, len(m.revisions))
	for vault, history := range m.revisions {
		revisions[vault] = append([]Revision(nil), history...)
	}
	// The dump reflects the registry exactly as the live store holds it:
	// every vault Memory knows — registered, committed-into, or both.
	registry := make([]VaultRecord, 0, len(m.vaults))
	for id, registered := range m.vaults {
		registry = append(registry, VaultRecord{
			ID:        id,
			Name:      registered.name,
			Location:  registered.location,
			Mode:      registered.mode,
			CreatedAt: registered.createdAt,
			Archived:  registered.archived,
		})
	}
	m.mu.RUnlock()

	sort.Slice(chunks, func(i, j int) bool { return chunks[i].ID < chunks[j].ID })
	sort.Strings(vaults)
	sort.Slice(registry, func(i, j int) bool { return registry[i].ID < registry[j].ID })

	return encodeMetadata(Metadata{Chunks: chunks, Vaults: vaults, Revisions: revisions, VaultRegistry: registry})
}

// Metadata is the bookkeeping a snapshot captures: which chunks exist and which
// revisions each vault holds. It never contains chunk content. The durable store
// and the in-memory store both serialise to this one shape so the backup engine,
// the restore path, and the checksums in a manifest all speak a single format.
type Metadata struct {
	Chunks    []Chunk               `json:"chunks"`
	Vaults    []string              `json:"vaults"`
	Revisions map[string][]Revision `json:"revisions"`
	// VaultRegistry carries what the operator set in the console (names,
	// modes, locations, retired flags, minting times) so a restore keeps a
	// named vault named, pointed and in the mode it was created in. Documents
	// from before the registry — or before modes — simply lack the key, and
	// their vaults import nameless and as vaults, which is what they were.
	VaultRegistry []VaultRecord `json:"vault_registry,omitempty"`
}

// VaultRecord is the registry row as a snapshot captures it: only the facts
// an operator (or the minting) established. The counted halves of VaultInfo —
// revision counts, live bytes — are re-derived from the revisions a snapshot
// already carries, so they are not stored twice and cannot drift.
//
// Mode is the M11 S1 addition. A document written before it simply lacks the
// key, and its vaults import as ModeVault — which is what they were: the era
// before modes had one kind of space, and it was encrypted.
type VaultRecord struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Location  string `json:"location,omitempty"`
	Mode      Mode   `json:"mode,omitempty"`
	CreatedAt int64  `json:"created_at"`
	Archived  bool   `json:"archived,omitempty"`
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
