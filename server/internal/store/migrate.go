package store

import (
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
)

// The schema is applied by running these files in numeric order, so the durable
// store upgrades itself on open rather than assuming an operator ran something by
// hand. Each file is one logical change; a forward-only ladder is enough for an
// embedded database where the file itself is the backup.
//
//go:embed migrations/*.sql
var migrationsFS embed.FS

// migrate brings db up to the newest migration, recording progress in
// PRAGMA user_version. It applies nothing when the database is already current,
// which is the common case: every open after the first.
//
// Foreign keys are set per connection by the caller (SQLite defaults them off),
// not here, because PRAGMA foreign_keys is a no-op inside a transaction.
func migrate(db *sql.DB) error {
	applied, err := userVersion(db)
	if err != nil {
		return err
	}

	files, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return fmt.Errorf("listing migrations: %w", err)
	}
	sort.Strings(files)

	for _, name := range files {
		version, err := migrationVersion(name)
		if err != nil {
			return err
		}
		if version <= applied {
			continue
		}
		body, err := migrationsFS.ReadFile(name)
		if err != nil {
			return fmt.Errorf("reading migration %s: %w", name, err)
		}
		if err := applyMigration(db, name, version, string(body)); err != nil {
			return err
		}
	}
	return nil
}

// applyMigration runs one file in a transaction and stamps user_version, so a
// file either fully lands or does not at all.
func applyMigration(db *sql.DB, name string, version int, body string) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("starting migration %s: %w", name, err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(body); err != nil {
		return fmt.Errorf("applying migration %s: %w", name, err)
	}
	// user_version takes a literal, not a placeholder; version is an int parsed
	// from the filename, never user input, so formatting it in is safe.
	if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", version)); err != nil {
		return fmt.Errorf("stamping version %d after %s: %w", version, name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing migration %s: %w", name, err)
	}
	return nil
}

// userVersion reads PRAGMA user_version, the schema version last applied.
func userVersion(db *sql.DB) (int, error) {
	var version int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil {
		return 0, fmt.Errorf("reading user_version: %w", err)
	}
	return version, nil
}

// migrationVersion parses the leading number out of "migrations/0001_init.sql".
func migrationVersion(name string) (int, error) {
	base := name[strings.LastIndex(name, "/")+1:]
	digits := base
	if underscore := strings.IndexByte(digits, '_'); underscore >= 0 {
		digits = digits[:underscore]
	}
	version, err := strconv.Atoi(digits)
	if err != nil {
		return 0, fmt.Errorf("migration %q does not start with a version number", name)
	}
	if version <= 0 {
		return 0, fmt.Errorf("migration %q has a non-positive version %d", name, version)
	}
	return version, nil
}
