package target

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newTarget(t *testing.T) (*Local, string) {
	t.Helper()

	base := t.TempDir()
	root := filepath.Join(base, "bundles")
	tgt, err := NewLocal(root)
	if err != nil {
		t.Fatalf("NewLocal: %v", err)
	}

	// Sealed objects are mode 0440 under a 0550 directory, which t.TempDir cannot
	// remove. Clearing the bits afterwards mirrors what a maintenance pass does.
	t.Cleanup(func() { unsealTree(t, base) })
	return tgt, root
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

func TestWriteReadRoundTrip(t *testing.T) {
	tgt, _ := newTarget(t)
	ctx := context.Background()

	written, err := tgt.Write(ctx, "snapshots/one/metadata.json", strings.NewReader(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if written != int64(len(`{"hello":"world"}`)) {
		t.Errorf("wrote %d bytes, want %d", written, len(`{"hello":"world"}`))
	}

	exists, err := tgt.Exists(ctx, "snapshots/one/metadata.json")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("Exists says the object is missing")
	}

	size, err := tgt.Size(ctx, "snapshots/one/metadata.json")
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if size != written {
		t.Errorf("Size = %d, want %d", size, written)
	}

	reader, err := tgt.Read(ctx, "snapshots/one/metadata.json")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	defer reader.Close()

	body, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(body) != `{"hello":"world"}` {
		t.Errorf("read back %q", body)
	}
}

func TestWriteReplacesAndLeavesNoTempFiles(t *testing.T) {
	tgt, root := newTarget(t)
	ctx := context.Background()

	if _, err := tgt.Write(ctx, "a/b/obj", strings.NewReader("first")); err != nil {
		t.Fatalf("first Write: %v", err)
	}
	if _, err := tgt.Write(ctx, "a/b/obj", strings.NewReader("second")); err != nil {
		t.Fatalf("second Write: %v", err)
	}

	reader, err := tgt.Read(ctx, "a/b/obj")
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	body, _ := io.ReadAll(reader)
	reader.Close()
	if string(body) != "second" {
		t.Errorf("object holds %q, want second", body)
	}

	entries, err := os.ReadDir(filepath.Join(root, "a", "b"))
	if err != nil {
		t.Fatalf("reading directory: %v", err)
	}
	if len(entries) != 1 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("directory holds %v, want only obj", names)
	}
}

func TestPathsCannotEscapeTheRoot(t *testing.T) {
	tgt, root := newTarget(t)
	ctx := context.Background()

	outside := filepath.Join(filepath.Dir(root), "escaped")
	for _, rel := range []string{"../escaped", "../../escaped", "/../escaped", "a/../../escaped"} {
		if _, err := tgt.Write(ctx, rel, strings.NewReader("x")); err != nil {
			// A refusal is the good outcome either way.
			continue
		}
		if _, err := os.Stat(outside); err == nil {
			t.Fatalf("writing %q escaped the target root", rel)
		}
	}
}

func TestEntriesAreSortedAndMissingDirsAreEmpty(t *testing.T) {
	tgt, _ := newTarget(t)
	ctx := context.Background()

	for _, rel := range []string{"s/c/manifest.json", "s/a/manifest.json", "s/b/manifest.json"} {
		if _, err := tgt.Write(ctx, rel, strings.NewReader("{}")); err != nil {
			t.Fatalf("Write %s: %v", rel, err)
		}
	}

	names, err := tgt.Entries(ctx, "s")
	if err != nil {
		t.Fatalf("Entries: %v", err)
	}
	if len(names) != 3 || names[0] != "a" || names[2] != "c" {
		t.Errorf("Entries = %v, want [a b c]", names)
	}

	missing, err := tgt.Entries(ctx, "does-not-exist")
	if err != nil {
		t.Fatalf("Entries of a missing directory: %v", err)
	}
	if len(missing) != 0 {
		t.Errorf("missing directory listed %v, want nothing", missing)
	}
}

func TestReadOnlyBlocksLaterWritesButNotReads(t *testing.T) {
	tgt, _ := newTarget(t)
	ctx := context.Background()

	if _, err := tgt.Write(ctx, "s/one/manifest.json", strings.NewReader("{}")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := tgt.Write(ctx, "s/one/chunk", strings.NewReader("bytes")); err != nil {
		t.Fatalf("Write chunk: %v", err)
	}
	if err := tgt.ReadOnly(ctx, "s/one"); err != nil {
		t.Fatalf("ReadOnly: %v", err)
	}

	_, err := tgt.Write(ctx, "s/one/manifest.json", strings.NewReader("tampered"))
	if !errors.Is(err, ErrReadOnly) {
		t.Errorf("write into a sealed snapshot = %v, want ErrReadOnly", err)
	}

	// Sealed must not mean unreadable; a restore has to be able to read it.
	reader, err := tgt.Read(ctx, "s/one/manifest.json")
	if err != nil {
		t.Fatalf("Read after sealing: %v", err)
	}
	reader.Close()
}

func TestRemoveAllClearsTheSeal(t *testing.T) {
	tgt, root := newTarget(t)
	ctx := context.Background()

	if _, err := tgt.Write(ctx, "s/one/manifest.json", strings.NewReader("{}")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := tgt.ReadOnly(ctx, "s/one"); err != nil {
		t.Fatalf("ReadOnly: %v", err)
	}
	if err := tgt.RemoveAll(ctx, "s/one"); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}

	if _, err := os.Stat(filepath.Join(root, "s", "one")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("removed snapshot still present: %v", err)
	}
}

func TestReadReportsNotFound(t *testing.T) {
	tgt, _ := newTarget(t)

	_, err := tgt.Read(context.Background(), "nope")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("Read of a missing object = %v, want ErrNotFound", err)
	}
}

func TestEmptyRootIsRefused(t *testing.T) {
	if _, err := NewLocal("   "); err == nil {
		t.Fatal("an empty target directory was accepted")
	}
}

func TestLocationIsAbsolute(t *testing.T) {
	tgt, root := newTarget(t)
	if !filepath.IsAbs(tgt.Location()) {
		t.Errorf("Location = %q, want an absolute path", tgt.Location())
	}
	if tgt.Location() != root {
		t.Errorf("Location = %q, want %q", tgt.Location(), root)
	}
}
