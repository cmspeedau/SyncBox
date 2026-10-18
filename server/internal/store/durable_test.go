package store

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func openDurable(t *testing.T, dir string, maxChunk int64) *Durable {
	t.Helper()
	st, err := Open(dir, maxChunk)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestDurableSurvivesReopen(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	st := openDurable(t, dir, 1<<20)
	if _, err := st.PutChunk(ctx, "ABCDEFGH1234", strings.NewReader("hello world")); err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	if _, err := st.Commit(ctx, Revision{VaultID: "vault", Parent: 0, Manifest: []byte("m"), Size: 11}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Reopen the same directory: the chunk file and the metadata must both be back.
	reopened := openDurable(t, dir, 1<<20)
	reader, err := reopened.OpenChunk(ctx, "ABCDEFGH1234")
	if err != nil {
		t.Fatalf("OpenChunk after reopen: %v", err)
	}
	defer reader.Close()
	got, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "hello world" {
		t.Errorf("chunk after reopen = %q", got)
	}
	page, head, err := reopened.RevisionsSince(ctx, "vault", 0, 10)
	if err != nil || head != 1 || len(page) != 1 || string(page[0].Manifest) != "m" {
		t.Errorf("revisions after reopen = %+v head %d err %v", page, head, err)
	}
	// A reopen is not a second seed: history continues at 2.
	if _, err := reopened.Commit(ctx, Revision{VaultID: "vault", Parent: 1}); err != nil {
		t.Errorf("Commit after reopen: %v", err)
	}
}

func TestDurableDumpImportRoundTrip(t *testing.T) {
	ctx := context.Background()

	// Populate a Memory store, dump it, and import into a fresh durable store:
	// the durable store must reproduce the same ids, revisions, and head.
	src := NewMemory(1 << 20)
	for _, id := range []string{"AAAAAAAA1111", "BBBBBBBB2222", "CCCCCCCC3333"} {
		if _, err := src.PutChunk(ctx, id, strings.NewReader("body-"+id)); err != nil {
			t.Fatalf("PutChunk: %v", err)
		}
	}
	for i := uint64(0); i < 3; i++ {
		if _, err := src.Commit(ctx, Revision{VaultID: "vault", Parent: i, DirID: "D", CipherName: "C", Manifest: []byte("mm"), Size: 42}); err != nil {
			t.Fatalf("Commit: %v", err)
		}
	}
	// Operator facts the import must carry across: a minted name, a mode, an
	// empty vault that no client has touched yet, and a retired flag.
	photosID, err := src.CreateVault(ctx, "Photos", "", ModeSync)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	retiredID, err := src.CreateVault(ctx, "Retired", "Archive/Retired", ModeVault)
	if err != nil {
		t.Fatalf("CreateVault: %v", err)
	}
	if err := src.SetVaultArchived(ctx, retiredID, true); err != nil {
		t.Fatalf("SetVaultArchived: %v", err)
	}
	dump, err := src.DumpMetadata(ctx)
	if err != nil {
		t.Fatalf("DumpMetadata: %v", err)
	}

	dst := openDurable(t, t.TempDir(), 1<<20)
	doc, err := DecodeMetadata(dump)
	if err != nil {
		t.Fatalf("DecodeMetadata: %v", err)
	}
	chunks, revisions, err := dst.ImportMetadata(ctx, doc)
	if err != nil {
		t.Fatalf("ImportMetadata: %v", err)
	}
	if chunks != 3 || revisions != 3 {
		t.Errorf("imported %d chunks %d revisions, want 3 and 3", chunks, revisions)
	}

	ids, err := dst.ChunkIDs(ctx)
	if err != nil || strings.Join(ids, ",") != "AAAAAAAA1111,BBBBBBBB2222,CCCCCCCC3333" {
		t.Errorf("imported chunk ids = %v err %v", ids, err)
	}
	page, head, err := dst.RevisionsSince(ctx, "vault", 0, 10)
	if err != nil || head != 3 || len(page) != 3 {
		t.Fatalf("imported revisions = %+v head %d err %v", page, head, err)
	}
	if page[0].Size != 42 || string(page[0].Manifest) != "mm" {
		t.Errorf("imported revision lost fields: %+v", page[0])
	}

	// The registry crossed intact: minted ids unchanged, names kept, the
	// untouched vault imported as the empty vault it is, retirement honoured,
	// and the revision-born vault still nameless.
	imported, err := dst.ListVaults(ctx)
	if err != nil {
		t.Fatalf("ListVaults after import: %v", err)
	}
	byID := map[string]VaultInfo{}
	for _, info := range imported {
		byID[info.ID] = info
	}
	if len(byID) != 3 {
		t.Fatalf("imported %d vaults, want 3: %+v", len(byID), imported)
	}
	if photos := byID[photosID]; photos.Name != "Photos" || photos.ID != photosID || photos.Revisions != 0 {
		t.Errorf("imported Photos vault = %+v, want name Photos at id %s with no revisions", photos, photosID)
	} else if photos.Location != "Photos" {
		t.Errorf("imported Photos location = %q, want the name it defaulted to", photos.Location)
	} else if photos.Mode != ModeSync {
		t.Errorf("imported Photos mode = %q, want the sync it was created as", photos.Mode)
	}
	retired := byID[retiredID]
	if !retired.Archived || retired.Name != "Retired" {
		t.Errorf("imported retired vault = %+v", retired)
	} else if retired.Location != "Archive/Retired" {
		t.Errorf("imported retired location = %q, want Archive/Retired", retired.Location)
	} else if retired.Mode != ModeVault {
		t.Errorf("imported retired mode = %q, want the vault it was created as", retired.Mode)
	}
	if commitBorn := byID["vault"]; commitBorn.Name != "" || commitBorn.Revisions != 3 {
		t.Errorf("imported commit-born vault = %+v, want nameless with 3 revisions", commitBorn)
	} else if commitBorn.Mode != ModeVault {
		t.Errorf("imported commit-born mode = %q, want vault (nothing registered it)", commitBorn.Mode)
	}

	// Importing the same document again is idempotent: nothing doubles.
	if _, _, err := dst.ImportMetadata(ctx, doc); err != nil {
		t.Fatalf("second ImportMetadata: %v", err)
	}
	if again, _ := dst.ChunkIDs(ctx); len(again) != 3 {
		t.Errorf("re-import duplicated chunks: %v", again)
	}
	reimported, err := dst.ListVaults(ctx)
	if err != nil {
		t.Fatalf("ListVaults after re-import: %v", err)
	}
	if len(reimported) != 3 {
		t.Errorf("re-import duplicated vaults: %+v", reimported)
	}
	for _, info := range reimported {
		if info.ID == photosID && (info.Name != "Photos" || info.Archived) {
			t.Errorf("re-import damaged the registry: %+v", info)
		}
	}
}

// TestDurableImportsPreRegistryDocument is the compatibility promise the NUC
// runs on: a metadata.json written before the registry — bare id list, no
// vault_registry key at all — must restore into a registry-era server, with
// its vaults nameless exactly as they were when written.
func TestDurableImportsPreRegistryDocument(t *testing.T) {
	ctx := context.Background()

	doc := Metadata{
		Chunks: []Chunk{{ID: "AAAAAAAA1111", Size: 5, StoredAt: time.Unix(1000, 0).UTC()}},
		Vaults: []string{"OLDVAULT"},
		Revisions: map[string][]Revision{
			"OLDVAULT": {{VaultID: "OLDVAULT", Revision: 1, Parent: 0,
				DirID: "D", CipherName: "C", Manifest: []byte("mm"), Size: 5,
				StoredAt: time.Unix(1000, 0).UTC()}},
		},
	}
	data, err := encodeMetadata(doc)
	if err != nil {
		t.Fatalf("encodeMetadata: %v", err)
	}
	if strings.Contains(string(data), "vault_registry") {
		t.Fatal("pre-registry document should carry no registry key (omitempty failed)")
	}

	parsed, err := DecodeMetadata(data)
	if err != nil {
		t.Fatalf("DecodeMetadata: %v", err)
	}
	dst := openDurable(t, t.TempDir(), 1<<20)
	if _, _, err := dst.ImportMetadata(ctx, parsed); err != nil {
		t.Fatalf("ImportMetadata: %v", err)
	}

	vaults, err := dst.ListVaults(ctx)
	if err != nil {
		t.Fatalf("ListVaults: %v", err)
	}
	if len(vaults) != 1 || vaults[0].ID != "OLDVAULT" || vaults[0].Name != "" || vaults[0].Archived {
		t.Fatalf("imported pre-registry vaults = %+v, want one nameless OLDVAULT", vaults)
	}
	// A document from before modes has no mode to read; its spaces were all
	// encrypted, so they import as vaults and nothing claims otherwise.
	if vaults[0].Mode != ModeVault {
		t.Errorf("pre-mode vault mode = %q, want vault", vaults[0].Mode)
	}
	if vaults[0].Revisions != 1 || vaults[0].LiveFiles != 1 || vaults[0].Bytes != 5 {
		t.Errorf("bookkeeping after legacy import = %+v", vaults[0])
	}
}

// TestDurableMigrationAdoptsExistingVaultsAsVaults pins M11 S1's migration: a
// database written before the mode column existed opens at the new schema with
// every pre-existing space reading as a vault. That is the only kind there was,
// so nothing the operator already had is suddenly claimed to be readable.
func TestDurableMigrationAdoptsExistingVaultsAsVaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "syncbox.sqlite")

	// Build the schema as it stood before 0004 and stamp that version, so Open
	// sees a genuine pre-mode database rather than a fresh one.
	db, err := openSQLite(path)
	if err != nil {
		t.Fatalf("openSQLite: %v", err)
	}
	for _, name := range []string{"0001_init.sql", "0002_vault_registry.sql", "0003_vault_location.sql"} {
		body, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if _, err := db.Exec(string(body)); err != nil {
			t.Fatalf("applying %s: %v", name, err)
		}
	}
	if _, err := db.Exec(`PRAGMA user_version = 3`); err != nil {
		t.Fatalf("stamping version 3: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO vault (id, name, location, created_at) VALUES ('OLDSPACE', 'Photos', 'Photos', 1000)`); err != nil {
		t.Fatalf("seeding a pre-mode vault: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing pre-mode database: %v", err)
	}

	st := openDurable(t, dir, 1<<20)
	vaults, err := st.ListVaults(context.Background())
	if err != nil {
		t.Fatalf("ListVaults after migration: %v", err)
	}
	if len(vaults) != 1 || vaults[0].ID != "OLDSPACE" {
		t.Fatalf("migrated vaults = %+v, want one OLDSPACE", vaults)
	}
	if vaults[0].Mode != ModeVault {
		t.Errorf("pre-mode space migrated to mode %q, want vault", vaults[0].Mode)
	}
	if vaults[0].Name != "Photos" || vaults[0].Location != "Photos" {
		t.Errorf("migration disturbed the row: %+v", vaults[0])
	}
}

func TestDurableSeedsFromRestoredMetadata(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	// Simulate `syncboxd restore` having written metadata.json into an empty data dir.
	src := NewMemory(1 << 20)
	if _, err := src.PutChunk(ctx, "AAAAAAAA1111", strings.NewReader("payload")); err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	if _, err := src.Commit(ctx, Revision{VaultID: "vault", Parent: 0, CipherName: "C"}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	dump, err := src.DumpMetadata(ctx)
	if err != nil {
		t.Fatalf("DumpMetadata: %v", err)
	}
	// A restore also lays down the chunk file itself, not just the metadata.
	if err := os.MkdirAll(filepath.Join(dir, "chunks"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "chunks", "AAAAAAAA1111"), []byte("payload"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, metadataFileName), dump, 0o640); err != nil {
		t.Fatal(err)
	}

	st := openDurable(t, dir, 1<<20)

	// The empty store adopted the snapshot on open.
	if _, head, err := st.RevisionsSince(ctx, "vault", 0, 10); err != nil || head != 1 {
		t.Errorf("store did not seed: head %d err %v", head, err)
	}
	reader, err := st.OpenChunk(ctx, "AAAAAAAA1111")
	if err != nil {
		t.Fatalf("seeded chunk not readable: %v", err)
	}
	reader.Close()

	// The metadata file is retired so a later restart does not re-seed.
	if _, err := os.Stat(filepath.Join(dir, metadataFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Error("metadata.json should be renamed aside after seeding")
	}
	if _, err := os.Stat(filepath.Join(dir, metadataFileName+".imported")); err != nil {
		t.Error("retired metadata.json.imported missing")
	}
}

func TestDurableConcurrentCommitsSerialize(t *testing.T) {
	ctx := context.Background()
	st := openDurable(t, t.TempDir(), 1<<20)

	// Twenty clients each commit their own file against head 0. Exactly one wins
	// the first slot; the rest must conflict — the durable store must not let two
	// racing commits both see head 0.
	const clients = 20
	var won, conflicted int
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := st.Commit(ctx, Revision{VaultID: "vault", Parent: 0, CipherName: string(rune('A' + i))})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				won++
			case errors.Is(err, ErrConflict):
				conflicted++
			default:
				t.Errorf("unexpected Commit error: %v", err)
			}
		}(i)
	}
	wg.Wait()

	if won != 1 {
		t.Errorf("%d commits won the head-0 slot, want 1", won)
	}
	if won+conflicted != clients {
		t.Errorf("%d of %d commits were neither a win nor a conflict", clients-won-conflicted, clients)
	}
}
