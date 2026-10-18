package store

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// The API and the backup engine are written against the Store interface, not
// against Memory. These conformance tests run the same contract against every
// implementation, so the durable store cannot quietly diverge from the behaviour
// the rest of the server assumes: content-addressed idempotence, head-conflict
// detection, per-vault histories, and a stable, content-free metadata dump.

type factory struct {
	name string
	// make returns a ready store and a cleanup func. maxChunk bounds uploads.
	make func(t *testing.T, maxChunk int64) (Store, func())
}

func allStores() []factory {
	return []factory{
		{
			name: "memory",
			make: func(t *testing.T, maxChunk int64) (Store, func()) {
				return NewMemory(maxChunk), func() {}
			},
		},
		{
			name: "durable",
			make: func(t *testing.T, maxChunk int64) (Store, func()) {
				st, err := Open(t.TempDir(), maxChunk)
				if err != nil {
					t.Fatalf("Open: %v", err)
				}
				return st, func() { st.Close() }
			},
		},
	}
}

func runPerStore(t *testing.T, fn func(t *testing.T, st Store)) {
	t.Helper()
	for _, f := range allStores() {
		f := f
		t.Run(f.name, func(t *testing.T) {
			st, cleanup := f.make(t, 1<<20)
			t.Cleanup(cleanup)
			fn(t, st)
		})
	}
}

func TestConformPutOnceAndMissingOrder(t *testing.T) {
	runPerStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		written, err := st.PutChunk(ctx, "ABCDEFGH1234", strings.NewReader("payload"))
		if err != nil {
			t.Fatalf("PutChunk: %v", err)
		}
		if written != int64(len("payload")) {
			t.Errorf("written = %d, want %d", written, len("payload"))
		}

		again, err := st.PutChunk(ctx, "ABCDEFGH1234", strings.NewReader("payload"))
		if err != nil {
			t.Fatalf("PutChunk again: %v", err)
		}
		if again != 0 {
			t.Errorf("re-upload wrote %d bytes, want 0", again)
		}

		missing, err := st.MissingChunks(ctx, []string{"ZZZZZZZZ9999", "ABCDEFGH1234", "QQQQQQQQ0000"})
		if err != nil {
			t.Fatalf("MissingChunks: %v", err)
		}
		if len(missing) != 2 || missing[0] != "ZZZZZZZZ9999" || missing[1] != "QQQQQQQQ0000" {
			t.Errorf("missing = %v, want input order preserved", missing)
		}
	})
}

func TestConformChunkRoundTrip(t *testing.T) {
	runPerStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		body := bytes.Repeat([]byte("syncbox"), 512)

		if _, err := st.PutChunk(ctx, "ABCDEFGH1234", bytes.NewReader(body)); err != nil {
			t.Fatalf("PutChunk: %v", err)
		}
		reader, err := st.OpenChunk(ctx, "ABCDEFGH1234")
		if err != nil {
			t.Fatalf("OpenChunk: %v", err)
		}
		defer reader.Close()

		got, err := io.ReadAll(reader)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(got, body) {
			t.Errorf("round-trip mismatch: %d bytes back, want %d", len(got), len(body))
		}
		size, err := st.ChunkSize(ctx, "ABCDEFGH1234")
		if err != nil || size != int64(len(body)) {
			t.Errorf("ChunkSize = %d, %v; want %d", size, err, len(body))
		}
	})
}

func TestConformOversizedRejected(t *testing.T) {
	for _, f := range allStores() {
		f := f
		t.Run(f.name, func(t *testing.T) {
			st, cleanup := f.make(t, 16)
			t.Cleanup(cleanup)
			ctx := context.Background()

			_, err := st.PutChunk(ctx, "ABCDEFGH1234", strings.NewReader(strings.Repeat("x", 4096)))
			if !errors.Is(err, ErrTooLarge) {
				t.Fatalf("PutChunk = %v, want ErrTooLarge", err)
			}
			missing, err := st.MissingChunks(ctx, []string{"ABCDEFGH1234"})
			if err != nil {
				t.Fatalf("MissingChunks: %v", err)
			}
			if len(missing) != 1 {
				t.Errorf("rejected chunk was still stored: %v", missing)
			}
		})
	}
}

func TestConformHeadConflict(t *testing.T) {
	runPerStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		first, err := st.Commit(ctx, Revision{VaultID: "vault", Parent: 0})
		if err != nil || first != 1 {
			t.Fatalf("first Commit = %d, %v; want 1", first, err)
		}
		if _, err := st.Commit(ctx, Revision{VaultID: "vault", Parent: 1}); err != nil {
			t.Fatalf("second Commit: %v", err)
		}
		if _, err := st.Commit(ctx, Revision{VaultID: "vault", Parent: 1}); !errors.Is(err, ErrConflict) {
			t.Fatalf("stale Commit = %v, want ErrConflict", err)
		}
	})
}

func TestConformRevisionsSince(t *testing.T) {
	runPerStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		for i := uint64(0); i < 5; i++ {
			if _, err := st.Commit(ctx, Revision{VaultID: "vault", Parent: i}); err != nil {
				t.Fatalf("Commit %d: %v", i, err)
			}
		}
		page, head, err := st.RevisionsSince(ctx, "vault", 3, 2)
		if err != nil {
			t.Fatalf("RevisionsSince: %v", err)
		}
		if head != 5 || len(page) != 2 || page[0].Revision != 4 || page[1].Revision != 5 {
			t.Errorf("page=%+v head=%d, want 4,5 head 5", page, head)
		}
		quiet, headAgain, err := st.RevisionsSince(ctx, "vault", head, 10)
		if err != nil || len(quiet) != 0 || headAgain != 5 {
			t.Errorf("page from head = %+v %d %v; want empty 5", quiet, headAgain, err)
		}
	})
}

func TestConformSeparateVaults(t *testing.T) {
	runPerStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		if _, err := st.Commit(ctx, Revision{VaultID: "one", Parent: 0}); err != nil {
			t.Fatalf("Commit one: %v", err)
		}
		if _, err := st.Commit(ctx, Revision{VaultID: "two", Parent: 0}); err != nil {
			t.Fatalf("Commit two: %v", err)
		}
		two, _, err := st.RevisionsSince(ctx, "two", 0, 10)
		if err != nil || len(two) != 1 {
			t.Errorf("vault two has %d revisions %v; want 1", len(two), err)
		}
	})
}

func TestConformNotFoundAndStats(t *testing.T) {
	runPerStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		if _, err := st.OpenChunk(ctx, "ABCDEFGH1234"); !errors.Is(err, ErrNotFound) {
			t.Errorf("OpenChunk = %v, want ErrNotFound", err)
		}
		if _, err := st.ChunkSize(ctx, "ABCDEFGH1234"); !errors.Is(err, ErrNotFound) {
			t.Errorf("ChunkSize = %v, want ErrNotFound", err)
		}
		if _, err := st.PutChunk(ctx, "ABCDEFGH1234", strings.NewReader("12345")); err != nil {
			t.Fatalf("PutChunk: %v", err)
		}
		stats, err := st.Stats(ctx)
		if err != nil {
			t.Fatalf("Stats: %v", err)
		}
		if stats.Chunks != 1 || stats.ChunkBytes != 5 {
			t.Errorf("stats = %+v, want 1 chunk, 5 bytes", stats)
		}
	})
}

func TestConformDumpStableAndNoContent(t *testing.T) {
	runPerStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()
		for _, id := range []string{"ZZZZZZZZ9999", "AAAAAAAA1111"} {
			if _, err := st.PutChunk(ctx, id, strings.NewReader(id)); err != nil {
				t.Fatalf("PutChunk: %v", err)
			}
		}
		if _, err := st.Commit(ctx, Revision{VaultID: "vault", Parent: 0, Manifest: []byte("opaque")}); err != nil {
			t.Fatalf("Commit: %v", err)
		}

		first, err := st.DumpMetadata(ctx)
		if err != nil {
			t.Fatalf("DumpMetadata: %v", err)
		}
		second, err := st.DumpMetadata(ctx)
		if err != nil {
			t.Fatalf("DumpMetadata again: %v", err)
		}
		if !bytes.Equal(first, second) {
			t.Error("two dumps of the same state differ")
		}

		var decoded struct {
			Chunks []struct {
				ID string `json:"id"`
			} `json:"chunks"`
		}
		if err := json.Unmarshal(first, &decoded); err != nil {
			t.Fatalf("metadata not JSON: %v", err)
		}
		if len(decoded.Chunks) != 2 || decoded.Chunks[0].ID != "AAAAAAAA1111" {
			t.Errorf("chunks not sorted: %+v", decoded.Chunks)
		}
		if strings.Contains(string(first), "opaque") {
			t.Error("metadata leaked a manifest body")
		}
	})
}

func TestConformCancelledContext(t *testing.T) {
	runPerStore(t, func(t *testing.T, st Store) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := st.PutChunk(ctx, "ABCDEFGH1234", strings.NewReader("x")); err == nil {
			t.Error("PutChunk ignored a cancelled context")
		}
		if _, err := st.ChunkIDs(ctx); err == nil {
			t.Error("ChunkIDs ignored a cancelled context")
		}
		if _, _, err := st.RevisionsSince(ctx, "vault", 0, 10); err == nil {
			t.Error("RevisionsSince ignored a cancelled context")
		}
	})
}

func TestConformVaultRegistry(t *testing.T) {
	runPerStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		id, err := st.CreateVault(ctx, "Photos", "", ModeSync)
		if err != nil {
			t.Fatalf("CreateVault: %v", err)
		}
		if len(id) != 8 {
			t.Errorf("minted id %q, want eight base32 characters", id)
		}
		second, err := st.CreateVault(ctx, "Work", "Syncbox/Work", ModeVault)
		if err != nil || second == id {
			t.Errorf("second CreateVault = %q, %v; want a different id", second, err)
		}

		// Enforcement (S5) reads this: a registered vault answers true, and an
		// id nothing ever registered answers false.
		if ok, err := st.VaultRegistered(ctx, id); err != nil || !ok {
			t.Errorf("VaultRegistered(%s) = %v, %v; want true", id, ok, err)
		}
		if ok, err := st.VaultRegistered(ctx, "NOSUCHVAULT"); err != nil || ok {
			t.Errorf("VaultRegistered(unknown) = %v, %v; want false", ok, err)
		}

		vaults, err := st.ListVaults(ctx)
		if err != nil {
			t.Fatalf("ListVaults: %v", err)
		}
		if len(vaults) != 2 {
			t.Fatalf("ListVaults returned %d vaults, want 2", len(vaults))
		}
		for _, info := range vaults {
			if info.Revisions != 0 || info.LiveFiles != 0 || info.Bytes != 0 {
				t.Errorf("vault %s reports bookkeeping for a vault nothing touched: %+v", info.ID, info)
			}
		}
		byID := map[string]VaultInfo{}
		for _, info := range vaults {
			byID[info.ID] = info
		}
		if byID[id].Location != "Photos" {
			t.Errorf("an empty location should default to the name, got %q", byID[id].Location)
		}
		if byID[second].Location != "Syncbox/Work" {
			t.Errorf("explicit location = %q, want Syncbox/Work", byID[second].Location)
		}
		if byID[id].Mode != ModeSync {
			t.Errorf("Photos mode = %q, want the sync it was created as", byID[id].Mode)
		}
		if byID[second].Mode != ModeVault {
			t.Errorf("Work mode = %q, want the vault it was created as", byID[second].Mode)
		}

		// A commit into an unregistered vault enters the registry nameless,
		// exactly as it did before the registry existed. The tally counts
		// each file's newest revision: A was written then deleted, B lives.
		const legacy = "LEGACYV1"
		head, err := st.Commit(ctx, Revision{VaultID: legacy, Parent: 0,
			DirID: "dir", CipherName: "A", Manifest: []byte{1}, Size: 7})
		if err != nil {
			t.Fatalf("Commit A: %v", err)
		}
		head, err = st.Commit(ctx, Revision{VaultID: legacy, Parent: head,
			DirID: "dir", CipherName: "B", Manifest: []byte{2}, Size: 10})
		if err != nil {
			t.Fatalf("Commit B: %v", err)
		}
		if _, err := st.Commit(ctx, Revision{VaultID: legacy, Parent: head,
			DirID: "dir", CipherName: "A", Deleted: true}); err != nil {
			t.Fatalf("Commit tombstone: %v", err)
		}
		if ok, err := st.VaultRegistered(ctx, legacy); err != nil || !ok {
			t.Errorf("a commit must register its vault: VaultRegistered(%s) = %v, %v", legacy, ok, err)
		}

		vaults, err = st.ListVaults(ctx)
		if err != nil {
			t.Fatalf("ListVaults after commits: %v", err)
		}
		if len(vaults) != 3 {
			t.Fatalf("ListVaults returned %d vaults, want 3 (the commit must register its vault)", len(vaults))
		}
		var found *VaultInfo
		for i := range vaults {
			if vaults[i].ID == legacy {
				found = &vaults[i]
			}
		}
		if found == nil {
			t.Fatalf("committed vault %s absent from ListVaults", legacy)
		}
		if found.Name != "" || found.Archived {
			t.Errorf("commit-born vault should be nameless and unarchived, got %+v", found)
		}
		if found.Mode != ModeVault {
			t.Errorf("commit-born vault mode = %q, want vault (nothing registered it)", found.Mode)
		}
		if found.Revisions != 3 || found.LiveFiles != 1 || found.Bytes != 10 {
			t.Errorf("tally = %+v, want 3 revisions, 1 live file, 10 bytes", found)
		}
		if found.LastWriteAt == 0 {
			t.Error("LastWriteAt is zero after commits")
		}

		// Locations (S3c): a vault may keep its own, take a free one, or be
		// refused one a live vault already claims. Unknown ids 404.
		if err := st.SetVaultLocation(ctx, id, "Photos"); err != nil {
			t.Errorf("re-setting a vault's own location = %v, want nil", err)
		}
		if err := st.SetVaultLocation(ctx, legacy, "Syncbox/Work"); !errors.Is(err, ErrLocationTaken) {
			t.Errorf("taking a live vault's location = %v, want ErrLocationTaken", err)
		}
		if err := st.SetVaultLocation(ctx, legacy, "Grandma"); err != nil {
			t.Errorf("SetVaultLocation on a commit-born vault: %v", err)
		}
		if err := st.SetVaultLocation(ctx, "NOSUCHVAULT", "x"); !errors.Is(err, ErrNotFound) {
			t.Errorf("locating an unknown vault = %v, want ErrNotFound", err)
		}
		// An archived vault no longer claims its folder, so it can be reused.
		if err := st.SetVaultArchived(ctx, second, true); err != nil {
			t.Fatalf("archiving the second vault: %v", err)
		}
		if err := st.SetVaultLocation(ctx, legacy, "Syncbox/Work"); err != nil {
			t.Errorf("a retired vault should not hoard its folder: %v", err)
		}
		if err := st.SetVaultArchived(ctx, second, false); err != nil {
			t.Fatalf("restoring the second vault: %v", err)
		}
		if err := st.SetVaultLocation(ctx, legacy, "Grandma"); err != nil {
			t.Errorf("restoring the location for later assertions: %v", err)
		}

		// Operator facts are set on either kind of vault, and unknown ids
		// answer with the sentinel the API maps onto a 404.
		if err := st.RenameVault(ctx, legacy, "Grandma's"); err != nil {
			t.Fatalf("RenameVault on a commit-born vault: %v", err)
		}
		if err := st.SetVaultArchived(ctx, id, true); err != nil {
			t.Fatalf("SetVaultArchived: %v", err)
		}
		if err := st.RenameVault(ctx, "NOSUCHVAULT", "x"); !errors.Is(err, ErrNotFound) {
			t.Errorf("renaming an unknown vault = %v, want ErrNotFound", err)
		}
		if err := st.SetVaultArchived(ctx, "NOSUCHVAULT", true); !errors.Is(err, ErrNotFound) {
			t.Errorf("archiving an unknown vault = %v, want ErrNotFound", err)
		}

		vaults, err = st.ListVaults(ctx)
		if err != nil {
			t.Fatalf("ListVaults after edits: %v", err)
		}
		names := map[string]VaultInfo{}
		for _, info := range vaults {
			names[info.ID] = info
		}
		if names[legacy].Name != "Grandma's" {
			t.Errorf("rename did not stick: %+v", names[legacy])
		}
		if !names[id].Archived {
			t.Errorf("vault %s should read as archived", id)
		}
		if names[second].Name != "Work" {
			t.Errorf("vault %s lost its created name: %+v", second, names[second])
		}

		// Modes (M11 S1): an empty mode is the new-registration default, sync,
		// and a mode that is neither sync nor vault is refused before anything
		// is minted, so the registry can never hold a mode no reader knows.
		def, err := st.CreateVault(ctx, "Default Mode", "", "")
		if err != nil {
			t.Fatalf("CreateVault with an empty mode = %v, want the sync default", err)
		}
		final, err := st.ListVaults(ctx)
		if err != nil {
			t.Fatalf("ListVaults: %v", err)
		}
		for _, info := range final {
			if info.ID == def && info.Mode != ModeSync {
				t.Errorf("an empty mode created %q, want sync", info.Mode)
			}
		}
		if _, err := st.CreateVault(ctx, "Bad Mode", "", Mode("nonsense")); !errors.Is(err, ErrBadMode) {
			t.Errorf("CreateVault with a bad mode = %v, want ErrBadMode", err)
		}
	})
}

// commitRevision commits one revision against the head it is given and returns
// the number the store assigned.
func commitRevision(t *testing.T, st Store, vaultID string, parent uint64, dirID, name string, size int64, deleted bool) uint64 {
	t.Helper()

	next, err := st.Commit(context.Background(), Revision{
		VaultID:    vaultID,
		Parent:     parent,
		DirID:      dirID,
		CipherName: name,
		Manifest:   []byte("manifest for " + name),
		Size:       size,
		ModifiedAt: 1760000000,
		Deleted:    deleted,
	})
	if err != nil {
		t.Fatalf("commit %s/%s: %v", dirID, name, err)
	}
	return next
}

func TestConformSyncSpaceReads(t *testing.T) {
	runPerStore(t, func(t *testing.T, st Store) {
		ctx := context.Background()

		space, err := st.CreateVault(ctx, "Docs", "", ModeSync)
		if err != nil {
			t.Fatalf("CreateVault: %v", err)
		}
		// A commit into an id nothing registered births a vault, so the mode a
		// reader gets back for it must stay "vault".
		const born = "COMMITBE"

		// Browse reads the newest revision per key and skips tombstones.
		head := commitRevision(t, st, space, 0, "DIRA", "one.txt", 11, false)
		head = commitRevision(t, st, space, head, "DIRA", "two.txt", 22, false)
		head = commitRevision(t, st, space, head, "DIRA", "one.txt", 33, false) // an edit
		head = commitRevision(t, st, space, head, "DIRA", "one.txt", 0, true)   // a deletion

		if mode, err := st.VaultMode(ctx, space); err != nil || mode != ModeSync {
			t.Errorf("VaultMode(sync space) = %q, %v; want sync", mode, err)
		}
		if _, err := st.VaultMode(ctx, born); !errors.Is(err, ErrNotFound) {
			t.Errorf("VaultMode(unknown) = %v, want ErrNotFound", err)
		}

		files, err := st.LiveFiles(ctx, space)
		if err != nil {
			t.Fatalf("LiveFiles: %v", err)
		}
		if len(files) != 1 || files[0].CipherName != "two.txt" {
			t.Fatalf("LiveFiles = %+v, want only two.txt", files)
		}
		if files[0].Revision != 2 {
			t.Errorf("two.txt reported revision %d, want the revision that made it live", files[0].Revision)
		}

		if _, err := st.LiveFile(ctx, space, "DIRA", "one.txt"); !errors.Is(err, ErrNotFound) {
			t.Errorf("LiveFile of a deleted key = %v, want ErrNotFound", err)
		}
		rev, err := st.LiveFile(ctx, space, "DIRA", "two.txt")
		if err != nil {
			t.Fatalf("LiveFile: %v", err)
		}
		if rev.Size != 22 || rev.VaultID != space {
			t.Errorf("LiveFile = %+v, want size 22 in space %s", rev, space)
		}

		// The bin holds the tombstone, and reports the size the file had.
		bin, err := st.RecycleBin(ctx, space, 0)
		if err != nil {
			t.Fatalf("RecycleBin: %v", err)
		}
		if len(bin) != 1 || bin[0].CipherName != "one.txt" || bin[0].Size != 33 {
			t.Fatalf("RecycleBin = %+v, want one.txt at its last live size 33", bin)
		}
		// A window that has already closed shows nothing.
		empty, err := st.RecycleBin(ctx, space, 1<<62)
		if err != nil {
			t.Fatalf("RecycleBin with a closed window: %v", err)
		}
		if len(empty) != 0 {
			t.Errorf("RecycleBin past the window = %+v, want nothing", empty)
		}

		// Restore is a commit: the file comes back at the head with its content.
		// A peer commit in between is what proves it chains from the space's
		// head rather than from the revision this file was last seen at.
		head = commitRevision(t, st, space, head, "DIRA", "peer.txt", 7, false)
		restored, err := st.RestoreRecycled(ctx, space, "DIRA", "one.txt")
		if err != nil {
			t.Fatalf("RestoreRecycled: %v", err)
		}
		if restored.Revision != head+1 || restored.Size != 33 {
			t.Errorf("restored = %+v, want revision %d and size 33", restored, head+1)
		}
		if bin, err = st.RecycleBin(ctx, space, 0); err != nil || len(bin) != 0 {
			t.Errorf("RecycleBin after a restore = %+v, %v; want empty", bin, err)
		}
		if _, err := st.RestoreRecycled(ctx, space, "DIRA", "two.txt"); !errors.Is(err, ErrNotFound) {
			t.Errorf("restoring a live key = %v, want ErrNotFound", err)
		}
		if _, err := st.RestoreRecycled(ctx, space, "DIRA", "never.txt"); !errors.Is(err, ErrNotFound) {
			t.Errorf("restoring an unknown key = %v, want ErrNotFound", err)
		}

		// Re-delete one.txt, and give the vault space a tombstone too: the sweep
		// expires only the sync space, and it keeps each tombstone so a client
		// that was away still learns the file is gone.
		commitRevision(t, st, space, restored.Revision, "DIRA", "one.txt", 0, true)
		commitRevision(t, st, born, 0, "DIRA", "secret.txt", 44, false)
		commitRevision(t, st, born, 1, "DIRA", "secret.txt", 0, true)

		if dropped, err := st.SweepRecycle(ctx, 0); err != nil || dropped != 0 {
			t.Errorf("SweepRecycle(epoch) = %d, %v; want nothing dropped", dropped, err)
		}
		if dropped, err := st.SweepRecycle(ctx, 1<<62); err != nil || dropped == 0 {
			t.Errorf("SweepRecycle(far future) = %d, %v; want the dead history dropped", dropped, err)
		}

		if bin, err := st.RecycleBin(ctx, space, 0); err != nil || len(bin) != 1 {
			t.Errorf("the sync space lost its tombstone: %+v, %v", bin, err)
		}
		if _, err := st.LiveFile(ctx, space, "DIRA", "one.txt"); !errors.Is(err, ErrNotFound) {
			t.Errorf("a swept file became restorable again: %v", err)
		}
		if _, err := st.LiveFile(ctx, born, "DIRA", "secret.txt"); !errors.Is(err, ErrNotFound) {
			t.Errorf("the swept space was not a vault: %v", err)
		}
		if rows, _, err := st.RevisionsSince(ctx, born, 0, 100); err != nil || len(rows) != 2 {
			t.Errorf("a vault's history was swept: %d rows, %v; want both revisions", len(rows), err)
		}
		// The tombstone still answers for the space, so the sweep is idempotent.
		if dropped, err := st.SweepRecycle(ctx, 1<<62); err != nil || dropped != 0 {
			t.Errorf("second SweepRecycle = %d, %v; want nothing left to drop", dropped, err)
		}
	})
}
