package target

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Local writes bundles into a directory, which is where v1 keeps them: a second
// disk or a NAS mount.
//
// The immutability story here is honest and limited. ReadOnly flips a snapshot to
// mode 0444 under a read-only tree, which stops the server process (running as an
// unprivileged user) from altering a backup after the fact, and stops most
// accidents. It does not stop root. Object storage with object lock, in a later
// milestone, is what makes the guarantee real.
type Local struct {
	root string
}

// compile-time check.
var _ Target = (*Local)(nil)

// NewLocal returns a target rooted at dir, creating it if needed.
func NewLocal(dir string) (*Local, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, fmt.Errorf("snapshot target: empty directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("snapshot target %s: %w", dir, err)
	}
	if err := os.MkdirAll(abs, 0o750); err != nil {
		return nil, fmt.Errorf("creating snapshot target %s: %w", abs, err)
	}
	return &Local{root: abs}, nil
}

// Location returns the root directory.
func (l *Local) Location() string { return l.root }

// resolve joins rel under the root, refusing anything that would escape it.
func (l *Local) resolve(rel string) (string, error) {
	cleaned := filepath.Clean("/" + rel)
	full := filepath.Join(l.root, cleaned)
	if full != l.root && !strings.HasPrefix(full, l.root+string(os.PathSeparator)) {
		return "", fmt.Errorf("snapshot target: %q escapes %s", rel, l.root)
	}
	return full, nil
}

// checkWritable refuses writes into a sealed subtree.
func (l *Local) checkWritable(full string) error {
	for path := full; path != l.root && strings.HasPrefix(path, l.root); {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			path = filepath.Dir(path)
			continue
		}
		if info.Mode().Perm()&0o200 == 0 {
			return fmt.Errorf("%w: %s", ErrReadOnly, strings.TrimPrefix(path, l.root))
		}
		path = filepath.Dir(path)
	}
	return nil
}

// Write stores r at rel by writing a temporary file and renaming it into place,
// so a crash mid-write cannot leave a half-written manifest.
func (l *Local) Write(ctx context.Context, rel string, r io.Reader) (int64, error) {
	full, err := l.resolve(rel)
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("writing %s: %w", rel, err)
	}
	if err := l.checkWritable(full); err != nil {
		return 0, err
	}

	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return 0, fmt.Errorf("creating directory for %s: %w", rel, err)
	}

	tmp, err := os.CreateTemp(dir, ".syncbox-tmp-*")
	if err != nil {
		return 0, fmt.Errorf("creating temporary file for %s: %w", rel, err)
	}
	tmpName := tmp.Name()

	// Anything that goes wrong from here leaves the temporary file behind, so it
	// is removed on every failure path rather than accumulating in the target.
	written, err := io.Copy(tmp, r)
	if err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return 0, fmt.Errorf("writing %s: %w", rel, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return 0, fmt.Errorf("syncing %s: %w", rel, err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("closing %s: %w", rel, err)
	}
	if err := os.Chmod(tmpName, 0o640); err != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("setting mode on %s: %w", rel, err)
	}
	if err := os.Rename(tmpName, full); err != nil {
		os.Remove(tmpName)
		return 0, fmt.Errorf("installing %s: %w", rel, err)
	}
	return written, nil
}

// Read opens rel.
func (l *Local) Read(ctx context.Context, rel string) (io.ReadCloser, error) {
	full, err := l.resolve(rel)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", rel, err)
	}
	file, err := os.Open(full)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNotFound, rel)
		}
		return nil, fmt.Errorf("opening %s: %w", rel, err)
	}
	return file, nil
}

// Exists reports whether rel is present.
func (l *Local) Exists(ctx context.Context, rel string) (bool, error) {
	full, err := l.resolve(rel)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, fmt.Errorf("checking %s: %w", rel, err)
	}
	if _, err := os.Stat(full); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("checking %s: %w", rel, err)
	}
	return true, nil
}

// Size returns the length of rel.
func (l *Local) Size(ctx context.Context, rel string) (int64, error) {
	full, err := l.resolve(rel)
	if err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("sizing %s: %w", rel, err)
	}
	info, err := os.Stat(full)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, fmt.Errorf("%w: %s", ErrNotFound, rel)
		}
		return 0, fmt.Errorf("sizing %s: %w", rel, err)
	}
	return info.Size(), nil
}

// Entries lists the immediate children of rel, sorted, without a trailing slash.
func (l *Local) Entries(ctx context.Context, rel string) ([]string, error) {
	full, err := l.resolve(rel)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("listing %s: %w", rel, err)
	}
	entries, err := os.ReadDir(full)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("listing %s: %w", rel, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	sort.Strings(names)
	return names, nil
}

// ReadOnly seals rel recursively.
func (l *Local) ReadOnly(ctx context.Context, rel string) error {
	full, err := l.resolve(rel)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("sealing %s: %w", rel, err)
	}

	// Children first, then the directory: sealing a directory before its
	// contents would make the contents unreachable.
	err = filepath.WalkDir(full, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("walking %s: %w", rel, err)
		}
		if path == full {
			return nil
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o550)
		}
		return os.Chmod(path, 0o440)
	})
	if err != nil {
		return err
	}
	return os.Chmod(full, 0o550)
}

// RemoveAll deletes rel, clearing the seal first.
func (l *Local) RemoveAll(ctx context.Context, rel string) error {
	full, err := l.resolve(rel)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("removing %s: %w", rel, err)
	}

	err = filepath.WalkDir(full, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			// A partially removed tree is fine; the RemoveAll below decides
			// whether the operation actually succeeded.
			return nil //nolint:nilerr // walk continues, removal decides
		}
		if entry.IsDir() {
			return os.Chmod(path, 0o750)
		}
		return os.Chmod(path, 0o640)
	})
	if err != nil {
		return fmt.Errorf("clearing modes under %s: %w", rel, err)
	}
	if err := os.RemoveAll(full); err != nil {
		return fmt.Errorf("removing %s: %w", rel, err)
	}
	return nil
}
