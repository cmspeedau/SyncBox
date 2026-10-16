package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/syncbox/server/internal/backup/target"
	"github.com/syncbox/server/internal/store"
)

// fixture is a manager writing into a temporary target, plus the store it
// snapshots.
type fixture struct {
	manager *Manager
	stored  *store.Memory
	root    string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()

	root := t.TempDir()
	tgt, err := target.NewLocal(filepath.Join(root, "target"))
	if err != nil {
		t.Fatalf("target.NewLocal: %v", err)
	}

	stored := store.NewMemory(1 << 20)
	manager := NewManager(tgt, stored, "test")

	// Sealed snapshots are mode 0550, which would make t.TempDir's cleanup fail
	// to remove them. Clearing the modes afterwards is what a real deployment's
	// maintenance path does.
	t.Cleanup(func() { unsealTree(t, root) })

	return &fixture{manager: manager, stored: stored, root: root}
}

func unsealTree(t *testing.T, root string) {
	t.Helper()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			os.Chmod(path, 0o755)
			return nil
		}
		os.Chmod(path, 0o644)
		return nil
	})
	if err != nil {
		t.Logf("unsealing %s: %v", root, err)
	}
}

// seed puts two chunks and one revision into the store.
func (f *fixture) seed(t *testing.T) {
	t.Helper()

	ctx := context.Background()
	for _, id := range []string{"AAAAAAAABBBB", "CCCCCCCCDDDD"} {
		if _, err := f.stored.PutChunk(ctx, id, strings.NewReader("content of "+id)); err != nil {
			t.Fatalf("PutChunk %s: %v", id, err)
		}
	}
	if _, err := f.stored.Commit(ctx, store.Revision{
		VaultID:    "vault",
		Parent:     0,
		DirID:      "DIRID1",
		CipherName: "CIPHER1",
		Manifest:   []byte("encrypted chunk list"),
		Size:       11,
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
}

func (f *fixture) snapshotPath(id string) string {
	return filepath.Join(f.root, "target", "snapshots", id)
}

func TestCreateWritesACompleteSealedSnapshot(t *testing.T) {
	f := newFixture(t)
	f.seed(t)

	f.manager.now = func() time.Time {
		return time.Date(2026, 10, 16, 3, 0, 0, 0, time.UTC)
	}

	snapshot, err := f.manager.Create(context.Background(), DefaultPolicy())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !strings.HasPrefix(snapshot.ID, "2026-10-16T030000Z-") {
		t.Errorf("snapshot id %q does not start with its timestamp", snapshot.ID)
	}
	if len(snapshot.Manifest.Chunks) != 2 {
		t.Errorf("manifest lists %d chunks, want 2", len(snapshot.Manifest.Chunks))
	}
	if snapshot.Manifest.MetadataBytes == 0 || snapshot.Manifest.MetadataSHA256 == "" {
		t.Errorf("manifest has no metadata commitment: %+v", snapshot.Manifest)
	}
	if snapshot.Manifest.ServerVersion != "test" {
		t.Errorf("ServerVersion = %q, want test", snapshot.Manifest.ServerVersion)
	}

	dir := f.snapshotPath(snapshot.ID)
	for _, rel := range []string{"metadata.json", "manifest.json",
		filepath.Join("chunks", "AAAAAAAABBBB"), filepath.Join("chunks", "CCCCCCCCDDDD")} {
		if _, err := os.Stat(filepath.Join(dir, rel)); err != nil {
			t.Errorf("snapshot is missing %s: %v", rel, err)
		}
	}

	// The seal is the ransomware control, so it is asserted rather than assumed.
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat snapshot: %v", err)
	}
	if info.Mode().Perm()&0o200 != 0 {
		t.Errorf("snapshot dir is writable (%o), but Create should seal it", info.Mode().Perm())
	}

	if _, err := f.manager.Verify(context.Background(), snapshot.ID); err != nil {
		t.Errorf("Verify of a fresh snapshot: %v", err)
	}
}

func TestListIgnoresAnInterruptedAttempt(t *testing.T) {
	f := newFixture(t)
	f.seed(t)

	if _, err := f.manager.Create(context.Background(), DefaultPolicy()); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A crashed attempt leaves a directory with content but no manifest. Listing
	// must skip it rather than offer a half snapshot for restore.
	orphan := filepath.Join(f.root, "target", "snapshots", "2000-01-01T000000Z-deadbeef")
	if err := os.MkdirAll(orphan, 0o755); err != nil {
		t.Fatalf("mkdir orphan: %v", err)
	}
	if err := os.WriteFile(filepath.Join(orphan, "metadata.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write orphan metadata: %v", err)
	}

	snapshots, err := f.manager.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("List returned %d snapshots, want 1: %v", len(snapshots), ids(snapshots))
	}
	if snapshots[0].ID == "2000-01-01T000000Z-deadbeef" {
		t.Error("List offered an incomplete snapshot")
	}
}

func TestVerifyDetectsAQuietlyChangedChunk(t *testing.T) {
	f := newFixture(t)
	f.seed(t)

	snapshot, err := f.manager.Create(context.Background(), DefaultPolicy())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	chunkPath := filepath.Join(f.snapshotPath(snapshot.ID), "chunks", "AAAAAAAABBBB")
	if err := os.Chmod(chunkPath, 0o644); err != nil {
		t.Fatalf("chmod chunk: %v", err)
	}
	if err := os.WriteFile(chunkPath, []byte("silently damaged"), 0o644); err != nil {
		t.Fatalf("overwrite chunk: %v", err)
	}

	if _, err := f.manager.Verify(context.Background(), snapshot.ID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Verify of a damaged snapshot = %v, want ErrCorrupt", err)
	}
}

func TestVerifyDetectsDamagedMetadata(t *testing.T) {
	f := newFixture(t)
	f.seed(t)

	snapshot, err := f.manager.Create(context.Background(), DefaultPolicy())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	metadataPath := filepath.Join(f.snapshotPath(snapshot.ID), "metadata.json")
	if err := os.Chmod(metadataPath, 0o644); err != nil {
		t.Fatalf("chmod metadata: %v", err)
	}
	if err := os.WriteFile(metadataPath, []byte("rewritten"), 0o644); err != nil {
		t.Fatalf("overwrite metadata: %v", err)
	}

	if _, err := f.manager.Verify(context.Background(), snapshot.ID); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("Verify = %v, want ErrCorrupt", err)
	}
}

func TestRestoreWritesUsableFiles(t *testing.T) {
	f := newFixture(t)
	f.seed(t)

	snapshot, err := f.manager.Create(context.Background(), DefaultPolicy())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	dest := filepath.Join(f.root, "restored")
	manifest, err := f.manager.Restore(context.Background(), snapshot.ID, dest)
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if manifest.ID != snapshot.ID {
		t.Errorf("restored %q, asked for %q", manifest.ID, snapshot.ID)
	}

	body, err := os.ReadFile(filepath.Join(dest, "metadata.json"))
	if err != nil {
		t.Fatalf("restored metadata is missing: %v", err)
	}
	if !strings.Contains(string(body), "vault") {
		t.Error("restored metadata does not name the vault it came from")
	}
	chunk, err := os.ReadFile(filepath.Join(dest, "chunks", "AAAAAAAABBBB"))
	if err != nil {
		t.Fatalf("restored chunk is missing: %v", err)
	}
	if string(chunk) != "content of AAAAAAAABBBB" {
		t.Errorf("restored chunk = %q", chunk)
	}
}

func TestRestoreRefusesToOverwriteLiveData(t *testing.T) {
	f := newFixture(t)
	f.seed(t)

	snapshot, err := f.manager.Create(context.Background(), DefaultPolicy())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	dest := filepath.Join(f.root, "already-in-use")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatalf("mkdir dest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dest, "metadata.json"), []byte("live"), 0o644); err != nil {
		t.Fatalf("seed live metadata: %v", err)
	}

	if _, err := f.manager.Restore(context.Background(), snapshot.ID, dest); err == nil {
		t.Fatal("Restore wrote over a directory that already holds data")
	}

	body, err := os.ReadFile(filepath.Join(dest, "metadata.json"))
	if err != nil {
		t.Fatalf("reading metadata: %v", err)
	}
	if string(body) != "live" {
		t.Errorf("live metadata was replaced by %q", body)
	}
}

func TestPruneDeletesWhatThePolicyRetires(t *testing.T) {
	f := newFixture(t)
	f.seed(t)

	// A zero policy retires everything, which is the clearest way to show that
	// pruning really removes rather than merely hides.
	first, err := f.manager.Create(context.Background(), DefaultPolicy())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	kept, dropped, err := f.manager.Prune(context.Background(), Policy{})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(kept) != 0 || len(dropped) != 1 {
		t.Fatalf("kept %d dropped %d, want 0 and 1", len(kept), len(dropped))
	}
	if _, err := os.Stat(f.snapshotPath(first.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("retired snapshot still on disk: %v", err)
	}
}

// retentionTarget refuses RemoveAll on one path with ErrRetained, exactly as
// a bucket whose object lock keeps sealed bytes undeletable until the
// retention date passes.
type retentionTarget struct {
	target.Target
	refuse string
}

func (r retentionTarget) RemoveAll(ctx context.Context, rel string) error {
	if strings.HasPrefix(rel, r.refuse) {
		return fmt.Errorf("s3: 403 AccessDenied: %w", target.ErrRetained)
	}
	return r.Target.RemoveAll(ctx, rel)
}

func TestPruneKeepsSnapshotsStillUnderRetention(t *testing.T) {
	f := newFixture(t)
	f.seed(t)

	sealed, err := f.manager.Create(context.Background(), DefaultPolicy())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Wrap the same target so this one snapshot answers "retained", and prune
	// with a policy that would retire everything: the refusal must surface as
	// kept, not as failure and not as a false drop.
	wrapped := retentionTarget{
		Target: mustTarget(t, filepath.Join(f.root, "target")),
		refuse: "snapshots/" + sealed.ID,
	}
	manager := NewManager(wrapped, f.stored, "test")

	kept, dropped, err := manager.Prune(context.Background(), Policy{})
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if len(kept) != 1 || kept[0].ID != sealed.ID {
		t.Fatalf("kept = %v, want just the retained snapshot", kept)
	}
	if len(dropped) != 0 {
		t.Fatalf("dropped = %v, want none — a refused delete was not a drop", dropped)
	}
	// The bytes the refusal protected are still whole enough to verify.
	if _, err := manager.Verify(context.Background(), sealed.ID); err != nil {
		t.Errorf("retained snapshot must still verify: %v", err)
	}
}

// sealFailTarget refuses to seal, the way a bucket without object lock does.
type sealFailTarget struct {
	target.Target
}

func (r sealFailTarget) ReadOnly(context.Context, string) error {
	return fmt.Errorf("s3: 405 MethodNotAllowed")
}

func TestCreateCleansUpAfterAFailedSeal(t *testing.T) {
	f := newFixture(t)
	f.seed(t)
	ctx := context.Background()

	// The MinIO drill surfaced this: a seal that the service refuses must
	// not leave a complete-looking snapshot sitting in every listing. The
	// one failure mode that matters — a bucket without object lock — refuses
	// before locking anything, so cleanup can and must fully succeed.
	wrapped := sealFailTarget{Target: mustTarget(t, filepath.Join(f.root, "target"))}
	manager := NewManager(wrapped, f.stored, "test")

	if _, err := manager.Create(ctx, DefaultPolicy()); err == nil {
		t.Fatal("Create must report the seal failure")
	}
	listed, err := manager.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 0 {
		t.Fatalf("a create that failed to seal left %d snapshot(s) listed", len(listed))
	}
}

func TestCreateLeavesNothingBehindOnAFailedChunk(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	if _, err := f.stored.PutChunk(ctx, "AAAAAAAABBBB", strings.NewReader("fine")); err != nil {
		t.Fatalf("PutChunk: %v", err)
	}

	// A chunk that vanished between the listing and the open must abort the
	// snapshot rather than produce a manifest that promises a missing object.
	failing := &vanishingSource{Source: f.stored, failOn: "ZZZZZZZZ9999"}
	manager := NewManager(mustTarget(t, filepath.Join(f.root, "target2")), failing, "test")

	if _, err := manager.Create(ctx, DefaultPolicy()); err == nil {
		t.Fatal("Create succeeded despite an unreadable chunk")
	}
}

// vanishingSource is a Source that cannot open one particular chunk.
type vanishingSource struct {
	Source
	failOn string
}

func (v *vanishingSource) ChunkIDs(ctx context.Context) ([]string, error) {
	ids, err := v.Source.ChunkIDs(ctx)
	if err != nil {
		return nil, err
	}
	return append(ids, v.failOn), nil
}

func (v *vanishingSource) OpenChunk(ctx context.Context, id string) (io.ReadCloser, error) {
	if id == v.failOn {
		return nil, errors.New("chunk disappeared")
	}
	return v.Source.OpenChunk(ctx, id)
}

func mustTarget(t *testing.T, dir string) *target.Local {
	t.Helper()
	tgt, err := target.NewLocal(dir)
	if err != nil {
		t.Fatalf("target.NewLocal: %v", err)
	}
	return tgt
}
