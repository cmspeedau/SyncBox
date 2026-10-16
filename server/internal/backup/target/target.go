// Package target is where snapshot bundles are written.
//
// One interface covers a second disk, an S3 bucket, and a restic repository, so
// the backup engine does not change when a deployment moves off the local
// filesystem. What each implementation owes the engine is the interesting part:
// paths are relative and cannot escape the target, and ReadOnly is the hook that
// makes a finalized snapshot something a compromised server cannot rewrite.
package target

import (
	"context"
	"errors"
	"io"
)

// ErrNotFound means a path does not exist in the target.
var ErrNotFound = errors.New("snapshot target: not found")

// ErrReadOnly means a write was refused because the path was finalized.
var ErrReadOnly = errors.New("snapshot target: read only")

// ErrRetained means a delete was refused because the bytes are under
// immutability retention — object-lock doing its job, not a fault. Maintenance
// paths treat it as "not yet" and try again on a later pass.
var ErrRetained = errors.New("snapshot target: retained until its retention date")

// Target stores snapshot bundles under relative paths.
type Target interface {
	// Write stores r at rel, replacing any existing object, and reports the
	// number of bytes written.
	Write(ctx context.Context, rel string, r io.Reader) (int64, error)
	// Read opens rel for reading. It is the caller's to close.
	Read(ctx context.Context, rel string) (io.ReadCloser, error)
	// Exists reports whether rel is present.
	Exists(ctx context.Context, rel string) (bool, error)
	// Size returns the length of rel.
	Size(ctx context.Context, rel string) (int64, error)
	// Entries lists the immediate children of a directory, sorted.
	Entries(ctx context.Context, rel string) ([]string, error)
	// ReadOnly seals rel so later writes and deletes through this interface are
	// refused. How strongly depends on the target: on a plain filesystem it is a
	// permission change that root can undo, on object storage it is an object
	// lock that nobody can.
	ReadOnly(ctx context.Context, rel string) error
	// RemoveAll deletes rel. It is the maintenance path, and the only way to
	// retire a sealed snapshot; the running server never calls it on live data.
	RemoveAll(ctx context.Context, rel string) error
	// Location describes the target for logs and command output.
	Location() string
}
