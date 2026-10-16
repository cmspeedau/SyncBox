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

func TestPutChunkStoresOnceAndReportsMissing(t *testing.T) {
	st := NewMemory(1 << 20)
	ctx := context.Background()

	written, err := st.PutChunk(ctx, "ABCDEFGH1234", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("PutChunk: %v", err)
	}
	if written != int64(len("payload")) {
		t.Errorf("written = %d, want %d", written, len("payload"))
	}

	// A second upload of the same content address is a no-op: the id is the
	// content, so the bytes cannot differ.
	again, err := st.PutChunk(ctx, "ABCDEFGH1234", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("PutChunk again: %v", err)
	}
	if again != 0 {
		t.Errorf("re-upload wrote %d bytes, want 0", again)
	}

	missing, err := st.MissingChunks(ctx, []string{"ABCDEFGH1234", "ZZZZZZZZ9999"})
	if err != nil {
		t.Fatalf("MissingChunks: %v", err)
	}
	if len(missing) != 1 || missing[0] != "ZZZZZZZZ9999" {
		t.Errorf("missing = %v, want [ZZZZZZZZ9999]", missing)
	}
}

func TestChunkRoundTrip(t *testing.T) {
	st := NewMemory(1 << 20)
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
		t.Fatalf("reading chunk: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("chunk came back with %d bytes, want %d", len(got), len(body))
	}

	size, err := st.ChunkSize(ctx, "ABCDEFGH1234")
	if err != nil {
		t.Fatalf("ChunkSize: %v", err)
	}
	if size != int64(len(body)) {
		t.Errorf("ChunkSize = %d, want %d", size, len(body))
	}
}

func TestOversizedChunkIsRejected(t *testing.T) {
	st := NewMemory(16)
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
		t.Errorf("a rejected chunk was still stored: %v", missing)
	}
}

func TestChunkIDValidation(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{name: "plain", id: "ABCDEFGH1234", wantErr: false},
		{name: "lowercase", id: "abcdefgh1234", wantErr: false},
		{name: "too short", id: "ABC", wantErr: true},
		{name: "empty", id: "", wantErr: true},
		{name: "path traversal", id: "../../etc/passwd", wantErr: true},
		{name: "nested path", id: "a/b", wantErr: true},
		{name: "punctuation", id: "ABCD-EFGH", wantErr: true},
		{name: "space", id: "ABCD EFGH", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := CheckChunkID(test.id)
			if test.wantErr && err == nil {
				t.Fatalf("CheckChunkID(%q) accepted, want rejection", test.id)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("CheckChunkID(%q) = %v, want acceptance", test.id, err)
			}
			if test.wantErr && !errors.Is(err, ErrBadChunkID) {
				t.Errorf("error is %v, want ErrBadChunkID", err)
			}
		})
	}
}

func TestCommitAssignsSequentialRevisions(t *testing.T) {
	st := NewMemory(1 << 20)
	ctx := context.Background()

	first, err := st.Commit(ctx, Revision{VaultID: "vault", Parent: 0, CipherName: "AAAA"})
	if err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	if first != 1 {
		t.Errorf("first revision = %d, want 1", first)
	}

	second, err := st.Commit(ctx, Revision{VaultID: "vault", Parent: 1, CipherName: "BBBB"})
	if err != nil {
		t.Fatalf("second Commit: %v", err)
	}
	if second != 2 {
		t.Errorf("second revision = %d, want 2", second)
	}
}

func TestCommitAgainstAStaleParentConflicts(t *testing.T) {
	st := NewMemory(1 << 20)
	ctx := context.Background()

	if _, err := st.Commit(ctx, Revision{VaultID: "vault", Parent: 0}); err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	if _, err := st.Commit(ctx, Revision{VaultID: "vault", Parent: 1}); err != nil {
		t.Fatalf("second Commit: %v", err)
	}

	// A client that read revision 1 and then commits must lose the race, which is
	// the server's only means of detecting a conflict without reading a file.
	_, err := st.Commit(ctx, Revision{VaultID: "vault", Parent: 1, CipherName: "CCCC"})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("stale Commit = %v, want ErrConflict", err)
	}
}

func TestRevisionsSincePagesForward(t *testing.T) {
	st := NewMemory(1 << 20)
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
	if head != 5 {
		t.Errorf("head = %d, want 5", head)
	}
	if len(page) != 2 || page[0].Revision != 4 || page[1].Revision != 5 {
		t.Errorf("page = %+v, want revisions 4 and 5", page)
	}

	// Asking from the head must be empty, which is the state a settled client
	// polls into.
	quiet, headAgain, err := st.RevisionsSince(ctx, "vault", head, 10)
	if err != nil {
		t.Fatalf("RevisionsSince from head: %v", err)
	}
	if len(quiet) != 0 || headAgain != 5 {
		t.Errorf("page from head = %+v head %d, want empty and 5", quiet, headAgain)
	}
}

func TestVaultHistoriesAreSeparate(t *testing.T) {
	st := NewMemory(1 << 20)
	ctx := context.Background()

	if _, err := st.Commit(ctx, Revision{VaultID: "one", Parent: 0}); err != nil {
		t.Fatalf("Commit one: %v", err)
	}
	// The same parent number in another vault is legal: revisions are per vault.
	if _, err := st.Commit(ctx, Revision{VaultID: "two", Parent: 0}); err != nil {
		t.Fatalf("Commit two: %v", err)
	}

	one, _, err := st.RevisionsSince(ctx, "two", 0, 10)
	if err != nil {
		t.Fatalf("RevisionsSince: %v", err)
	}
	if len(one) != 1 {
		t.Errorf("vault two has %d revisions, want 1", len(one))
	}
}

func TestOpenChunkReportsNotFound(t *testing.T) {
	st := NewMemory(1 << 20)
	_, err := st.OpenChunk(context.Background(), "ABCDEFGH1234")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("OpenChunk = %v, want ErrNotFound", err)
	}
}

func TestDumpMetadataIsStableAndHoldsNoContent(t *testing.T) {
	st := NewMemory(1 << 20)
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
		t.Error("two dumps of the same state differ, so a restore cannot be verified by hash")
	}

	var decoded struct {
		Chunks []struct {
			ID   string `json:"id"`
			Size int64  `json:"size"`
		} `json:"chunks"`
	}
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("metadata is not the JSON it claims to be: %v", err)
	}
	if len(decoded.Chunks) != 2 {
		t.Fatalf("metadata lists %d chunks, want 2", len(decoded.Chunks))
	}
	// Sorted ids, so the first entry is the alphabetically earlier one.
	if decoded.Chunks[0].ID != "AAAAAAAA1111" {
		t.Errorf("chunks are not sorted: %+v", decoded.Chunks)
	}
	if strings.Contains(string(first), "opaque") {
		t.Error("metadata leaked a manifest body")
	}
}

func TestCancelledContextStopsWork(t *testing.T) {
	st := NewMemory(1 << 20)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := st.PutChunk(ctx, "ABCDEFGH1234", strings.NewReader("x")); err == nil {
		t.Error("PutChunk ignored a cancelled context")
	}
	if _, err := st.ChunkIDs(ctx); err == nil {
		t.Error("ChunkIDs ignored a cancelled context")
	}
}
