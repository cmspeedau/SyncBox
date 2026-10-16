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
