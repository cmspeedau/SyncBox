// Package backup takes self-contained snapshots of a Syncbox server.
//
// A snapshot holds everything needed to rebuild the server on a blank host: a
// consistent copy of the bookkeeping, and every chunk the server held at that
// moment. It stays ciphertext throughout — the backup path never touches a key, so
// a stolen backup is no more readable than a stolen server.
//
// Three properties shape the design:
//
//   - manifest.json is written last. A directory with a manifest is complete; one
//     without it is a crashed attempt and is ignored rather than half-restored.
//   - Every object is checksummed as it is written, so Verify can prove a snapshot
//     was not quietly corrupted afterwards.
//   - A finished snapshot is sealed through target.ReadOnly, which is what makes a
//     backup survivable from a server that is later compromised.
//
// Snapshots are full rather than incremental, and this is a deliberate choice, not
// a placeholder: a snapshot must be self-contained and independent of the live
// store, because the whole point is that it survives the server that made it being
// deleted, corrupted, or compromised. Hard links share an inode with the running
// server's data, so they would tie every snapshot's integrity to that of the live
// store and undo the guarantee the manifest's checksums exist to prove. Space is
// cheap relative to that guarantee; a size-vs-safety tradeoff (copy-on-write on a
// WORM-capable target, or a separate incremental pass) belongs with the space
// hardening in M7, not here.
package backup

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/syncbox/server/internal/backup/target"
)

// Layout inside a target, documented in one place because the restore path and the
// retention pass both depend on it.
const (
	// ManifestVersion is written into every manifest and checked on restore.
	ManifestVersion = 1

	snapshotsDir = "snapshots"
	metadataFile = "metadata.json"
	chunksDir    = "chunks"
	manifestFile = "manifest.json"
)

// ErrIncomplete means a snapshot directory has no manifest, so it was never
// finished.
var ErrIncomplete = errors.New("snapshot is incomplete")

// ErrCorrupt means a stored object no longer matches the checksum recorded for it.
var ErrCorrupt = errors.New("snapshot is corrupt")

// ErrRefusesOverwrite means a restore target already holds restored data, and
// the manager refused to replace live contents.
var ErrRefusesOverwrite = errors.New("refuses to overwrite")

// ChunkEntry is one stored chunk and the checksum taken when it was written.
type ChunkEntry struct {
	ID     string `json:"id"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	// VersionID names the exact object version this entry's bytes went into,
	// when the target has versions (empty otherwise). Verify and Restore read
	// by it, so a newer version PUT in front of the bundle cannot be served.
	VersionID string `json:"version_id,omitempty"`
}

// Manifest describes a snapshot and commits to its contents.
type Manifest struct {
	Version        int       `json:"version"`
	ID             string    `json:"id"`
	CreatedAt      time.Time `json:"created_at"`
	ServerVersion  string    `json:"server_version"`
	MetadataBytes  int64     `json:"metadata_bytes"`
	MetadataSHA256 string    `json:"metadata_sha256"`
	// MetadataVersionID pins the metadata object's version where the target
	// has versions, like ChunkEntry.VersionID does for chunks.
	MetadataVersionID string       `json:"metadata_version_id,omitempty"`
	ChunkBytes        int64        `json:"chunk_bytes"`
	Chunks            []ChunkEntry `json:"chunks"`
	Policy            Policy       `json:"policy"`
}

// Pinned reports whether the manifest recorded version identities for any of
// its objects — which tells a reader whether Verify and Restore followed the
// sealed bytes or the current ones.
func (m Manifest) Pinned() bool {
	if m.MetadataVersionID != "" {
		return true
	}
	for _, entry := range m.Chunks {
		if entry.VersionID != "" {
			return true
		}
	}
	return false
}

// Snapshot is a manifest plus where it lives.
type Snapshot struct {
	ID        string
	CreatedAt time.Time
	Manifest  Manifest
}

// Source is the part of the server a snapshot captures.
type Source interface {
	// DumpMetadata returns a consistent copy of the bookkeeping.
	DumpMetadata(ctx context.Context) ([]byte, error)
	// ChunkIDs lists every stored chunk id.
	ChunkIDs(ctx context.Context) ([]string, error)
	// OpenChunk returns a reader over a chunk. It is the caller's to close.
	OpenChunk(ctx context.Context, id string) (io.ReadCloser, error)
}

// Manager creates, lists, verifies, prunes, and restores snapshots.
type Manager struct {
	tgt      target.Target
	src      Source
	now      func() time.Time
	version  string
	postHook func(context.Context, Snapshot)
}

// NewManager returns a manager writing into tgt and reading from src.
func NewManager(tgt target.Target, src Source, serverVersion string) *Manager {
	return &Manager{tgt: tgt, src: src, now: time.Now, version: serverVersion}
}

// SetPostHook installs a function that runs after every snapshot this manager
// seals. A snapshot is committed the moment its seal lands, so the hook is a
// notification, not a step: its outcome never changes the result of Create,
// and reporting a failure is the hook's own job (PostCommand logs its shells).
// Hooks must not block the caller; PostCommand returns at once.
func (m *Manager) SetPostHook(hook func(context.Context, Snapshot)) {
	m.postHook = hook
}

// Create takes a snapshot and seals it, returning what was written.
//
// The policy is recorded in the manifest so a later retention pass can tell which
// ladder a snapshot was taken under.
func (m *Manager) Create(ctx context.Context, policy Policy) (Snapshot, error) {
	id, err := newID(m.now())
	if err != nil {
		return Snapshot{}, err
	}

	metadata, err := m.src.DumpMetadata(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot %s: %w", id, err)
	}

	manifest := Manifest{
		Version:        ManifestVersion,
		ID:             id,
		CreatedAt:      m.now().UTC(),
		ServerVersion:  m.version,
		MetadataBytes:  int64(len(metadata)),
		MetadataSHA256: hexSHA256(metadata),
		Policy:         policy,
	}

	metadataVersion, err := m.write(ctx, metadataRel(id), bytes.NewReader(metadata))
	if err != nil {
		return Snapshot{}, err
	}
	manifest.MetadataVersionID = metadataVersion

	ids, err := m.src.ChunkIDs(ctx)
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot %s: listing chunks: %w", id, err)
	}
	sort.Strings(ids)

	manifest.Chunks = make([]ChunkEntry, 0, len(ids))
	for _, chunkID := range ids {
		entry, err := m.copyChunk(ctx, id, chunkID)
		if err != nil {
			return Snapshot{}, err
		}
		manifest.Chunks = append(manifest.Chunks, entry)
		manifest.ChunkBytes += entry.Size
	}

	// The manifest goes down last: until it exists the snapshot is not a snapshot.
	body, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot %s: encoding manifest: %w", id, err)
	}
	// The manifest cannot name its own version (the identity exists only
	// after its bytes are final), so it is the one object Verify and Restore
	// read unpinned — the documented bootstrap boundary in docs/backup.md.
	if _, err := m.write(ctx, manifestRel(id), bytes.NewReader(body)); err != nil {
		return Snapshot{}, err
	}
	if err := m.tgt.ReadOnly(ctx, snapshotRel(id)); err != nil {
		// A snapshot that could not be sealed is not the snapshot the caller
		// asked for — and leaving it sitting in the target would advertise it
		// in every listing as if it were. Best-effort removal; the one seal
		// failure the drill surfaced (a bucket without object lock, refusing
		// on the very first object) is exactly the case where nothing is
		// locked yet and this cleanup fully succeeds.
		if cleanErr := m.tgt.RemoveAll(ctx, snapshotRel(id)); cleanErr != nil {
			return Snapshot{}, fmt.Errorf("sealing snapshot %s: %w (and its half-sealed bytes refused cleanup: %v)", id, err, cleanErr)
		}
		return Snapshot{}, fmt.Errorf("sealing snapshot %s: %w", id, err)
	}

	snapshot := Snapshot{ID: id, CreatedAt: manifest.CreatedAt, Manifest: manifest}
	if m.postHook != nil {
		m.postHook(ctx, snapshot)
	}
	return snapshot, nil
}

// copyChunk streams one chunk into the snapshot, checksumming it in passing
// and recording the version the bytes landed in.
func (m *Manager) copyChunk(ctx context.Context, snapshotID, chunkID string) (ChunkEntry, error) {
	if err := checkChunkID(chunkID); err != nil {
		return ChunkEntry{}, fmt.Errorf("snapshot %s: %w", snapshotID, err)
	}

	reader, err := m.src.OpenChunk(ctx, chunkID)
	if err != nil {
		return ChunkEntry{}, fmt.Errorf("snapshot %s: opening chunk %s: %w", snapshotID, chunkID, err)
	}
	defer reader.Close()

	hasher := sha256.New()
	written, version, err := m.tgt.Write(ctx, chunkRel(snapshotID, chunkID), io.TeeReader(reader, hasher))
	if err != nil {
		return ChunkEntry{}, fmt.Errorf("snapshot %s: storing chunk %s: %w", snapshotID, chunkID, err)
	}
	return ChunkEntry{ID: chunkID, Size: written, SHA256: hex.EncodeToString(hasher.Sum(nil)), VersionID: version}, nil
}

// write is Target.Write with the error context every caller would repeat; it
// hands back the version identity for callers that pin.
func (m *Manager) write(ctx context.Context, rel string, body io.Reader) (string, error) {
	if _, version, err := m.tgt.Write(ctx, rel, body); err != nil {
		return "", fmt.Errorf("writing %s: %w", rel, err)
	} else {
		return version, nil
	}
}

// openAt opens rel, preferring the version pinned at snapshot time when the
// target has versions and the manifest recorded an identity. A snapshot
// written to a target without versions (a plain directory) recorded none and
// reads the file that is there, exactly as it always has.
func (m *Manager) openAt(ctx context.Context, rel, versionID string) (io.ReadCloser, error) {
	if versionID != "" {
		if versions, ok := m.tgt.(target.Versioned); ok {
			return versions.ReadVersion(ctx, rel, versionID)
		}
	}
	return m.tgt.Read(ctx, rel)
}

// List returns complete snapshots, newest first. Directories without a manifest
// are skipped: they are interrupted attempts, not history.
func (m *Manager) List(ctx context.Context) ([]Snapshot, error) {
	names, err := m.tgt.Entries(ctx, snapshotsDir)
	if err != nil {
		return nil, fmt.Errorf("listing snapshots: %w", err)
	}

	out := make([]Snapshot, 0, len(names))
	for _, name := range names {
		manifest, err := m.readManifest(ctx, name)
		if errors.Is(err, ErrIncomplete) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, Snapshot{ID: name, CreatedAt: manifest.CreatedAt, Manifest: manifest})
	}

	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

// readManifest loads and validates one snapshot's manifest.
func (m *Manager) readManifest(ctx context.Context, id string) (Manifest, error) {
	reader, err := m.tgt.Read(ctx, manifestRel(id))
	if err != nil {
		if errors.Is(err, target.ErrNotFound) {
			return Manifest{}, fmt.Errorf("%w: %s has no manifest", ErrIncomplete, id)
		}
		return Manifest{}, fmt.Errorf("reading manifest for %s: %w", id, err)
	}
	defer reader.Close()

	body, err := io.ReadAll(reader)
	if err != nil {
		return Manifest{}, fmt.Errorf("reading manifest for %s: %w", id, err)
	}
	var manifest Manifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return Manifest{}, fmt.Errorf("parsing manifest for %s: %w", id, err)
	}
	if manifest.Version > ManifestVersion {
		return Manifest{}, fmt.Errorf("snapshot %s uses manifest version %d, this server reads %d",
			id, manifest.Version, ManifestVersion)
	}
	return manifest, nil
}

// Verify re-reads a snapshot and checks every checksum it recorded.
func (m *Manager) Verify(ctx context.Context, id string) (Manifest, error) {
	manifest, err := m.readManifest(ctx, id)
	if err != nil {
		return Manifest{}, err
	}

	metadata, err := m.readAllAt(ctx, metadataRel(id), manifest.MetadataVersionID)
	if err != nil {
		return Manifest{}, fmt.Errorf("verifying %s: %w", id, err)
	}
	if got := hexSHA256(metadata); got != manifest.MetadataSHA256 {
		return Manifest{}, fmt.Errorf("%w: %s metadata is %s, manifest says %s",
			ErrCorrupt, id, got, manifest.MetadataSHA256)
	}

	for _, entry := range manifest.Chunks {
		body, err := m.readAllAt(ctx, chunkRel(id, entry.ID), entry.VersionID)
		if err != nil {
			return Manifest{}, fmt.Errorf("verifying %s: %w", id, err)
		}
		if int64(len(body)) != entry.Size {
			return Manifest{}, fmt.Errorf("%w: %s chunk %s is %d bytes, manifest says %d",
				ErrCorrupt, id, entry.ID, len(body), entry.Size)
		}
		if got := hexSHA256(body); got != entry.SHA256 {
			return Manifest{}, fmt.Errorf("%w: %s chunk %s is %s, manifest says %s",
				ErrCorrupt, id, entry.ID, got, entry.SHA256)
		}
	}
	return manifest, nil
}

// Restore copies a snapshot's contents into destDir.
//
// This is the offline path: stop the server, restore into the data directory,
// start again. It refuses to write over a directory that already holds metadata,
// because silently replacing live data is the one thing a restore must not do.
func (m *Manager) Restore(ctx context.Context, id, destDir string) (Manifest, error) {
	manifest, err := m.Verify(ctx, id)
	if err != nil {
		return Manifest{}, err
	}

	if strings.TrimSpace(destDir) == "" {
		return Manifest{}, errors.New("restore needs a destination directory")
	}
	if _, err := os.Stat(filepath.Join(destDir, metadataFile)); err == nil {
		return Manifest{}, fmt.Errorf("%w: %s already holds a metadata.json",
			ErrRefusesOverwrite, destDir)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Manifest{}, fmt.Errorf("checking %s: %w", destDir, err)
	}

	if err := os.MkdirAll(filepath.Join(destDir, chunksDir), 0o750); err != nil {
		return Manifest{}, fmt.Errorf("creating %s: %w", destDir, err)
	}

	metadata, err := m.readAllAt(ctx, metadataRel(id), manifest.MetadataVersionID)
	if err != nil {
		return Manifest{}, fmt.Errorf("restoring %s: %w", id, err)
	}
	if err := os.WriteFile(filepath.Join(destDir, metadataFile), metadata, 0o640); err != nil {
		return Manifest{}, fmt.Errorf("writing restored metadata: %w", err)
	}

	for _, entry := range manifest.Chunks {
		if err := ctx.Err(); err != nil {
			return Manifest{}, fmt.Errorf("restoring %s: %w", id, err)
		}
		body, err := m.readAllAt(ctx, chunkRel(id, entry.ID), entry.VersionID)
		if err != nil {
			return Manifest{}, fmt.Errorf("restoring %s: %w", id, err)
		}
		dest := filepath.Join(destDir, chunksDir, filepath.Base(entry.ID))
		if err := os.WriteFile(dest, body, 0o640); err != nil {
			return Manifest{}, fmt.Errorf("writing restored chunk %s: %w", entry.ID, err)
		}
	}
	return manifest, nil
}

// Prune retires snapshots the policy no longer wants, returning what remains and
// what was deleted.
func (m *Manager) Prune(ctx context.Context, policy Policy) (kept, dropped []Snapshot, err error) {
	snapshots, err := m.List(ctx)
	if err != nil {
		return nil, nil, err
	}

	kept, dropped = Prune(snapshots, policy)
	var refused []Snapshot
	for _, snapshot := range dropped {
		if err := m.tgt.RemoveAll(ctx, snapshotRel(snapshot.ID)); err != nil {
			// A sealed snapshot under live retention refuses deletion, and
			// that refusal is the system working: the snapshot stays in kept
			// (it is still there, still whole) and a later pass retires it
			// once the retention date has passed.
			if errors.Is(err, target.ErrRetained) {
				kept = append(kept, snapshot)
				refused = append(refused, snapshot)
				continue
			}
			return kept, dropped, fmt.Errorf("retiring snapshot %s: %w", snapshot.ID, err)
		}
	}
	if len(refused) > 0 {
		// Nothing was actually dropped about them, and the report should say
		// what is true, not what was attempted.
		dropped = without(dropped, refused)
	}
	return kept, dropped, nil
}

// without drops from `all` every snapshot named in `gone`, by ID.
func without(all, gone []Snapshot) []Snapshot {
	drop := make(map[string]bool, len(gone))
	for _, snapshot := range gone {
		drop[snapshot.ID] = true
	}
	out := all[:0:0]
	for _, snapshot := range all {
		if !drop[snapshot.ID] {
			out = append(out, snapshot)
		}
	}
	return out
}

// readAllAt loads an object from the target fully, for checksumming, pinned
// to the version the snapshot wrote when the target has versions and the
// manifest recorded one (see openAt).
func (m *Manager) readAllAt(ctx context.Context, rel, versionID string) ([]byte, error) {
	reader, err := m.openAt(ctx, rel, versionID)
	if err != nil {
		if errors.Is(err, target.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s is missing", ErrCorrupt, rel)
		}
		return nil, fmt.Errorf("reading %s: %w", rel, err)
	}
	defer reader.Close()

	body, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", rel, err)
	}
	return body, nil
}

// newID is a sortable, collision-resistant snapshot name: a timestamp to the
// second, then four random bytes so two servers sharing a target cannot collide.
func newID(now time.Time) (string, error) {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generating snapshot id: %w", err)
	}
	return now.UTC().Format("2006-01-02T150405Z") + "-" + hex.EncodeToString(suffix[:]), nil
}

// checkChunkID keeps a chunk id from escaping the snapshot directory. Store ids
// are validated on the way in, but a snapshot is read back long after that, so the
// backup path checks again rather than trusting what it finds.
func checkChunkID(id string) error {
	if id == "" || id != path.Base(id) || strings.ContainsAny(id, `/\`) || id == "." || id == ".." {
		return fmt.Errorf("chunk id %q is not a plain name", id)
	}
	return nil
}

func hexSHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func snapshotRel(id string) string { return path.Join(snapshotsDir, id) }
func metadataRel(id string) string { return path.Join(snapshotsDir, id, metadataFile) }
func manifestRel(id string) string { return path.Join(snapshotsDir, id, manifestFile) }
func chunkRel(snapshotID, id string) string {
	return path.Join(snapshotsDir, snapshotID, chunksDir, id)
}
