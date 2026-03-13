// Package state manages the SQLite WAL state database for the agent.
// It stores certificate inventory, renewal tracking, audit events,
// last-known-good config hash, and CA connectivity status.
package state

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	"github.com/GraceSolutions/StepCAAgent/internal/logging"
	"github.com/GraceSolutions/StepCAAgent/internal/permissions"

	_ "modernc.org/sqlite"
)

const (
	DefaultDBName = "stepcaagent.db"
)

// DB wraps the SQLite database connection.
type DB struct {
	db   *sql.DB
	path string
}

// Open opens (or creates) the state database at the given directory.
// If dir is empty, the directory of the running binary is used.
// The database is opened in WAL mode and restrictive file permissions are applied.
func Open(dir string) (*DB, error) {
	log := logging.Logger()

	resolved, err := resolveDir(dir)
	if err != nil {
		return nil, fmt.Errorf("state: resolve directory: %w", err)
	}

	if err := os.MkdirAll(resolved, permissions.RestrictiveDirMode); err != nil {
		return nil, fmt.Errorf("state: create directory %s: %w", resolved, err)
	}

	dbPath := filepath.Join(resolved, DefaultDBName)
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)", dbPath)

	sqlDB, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("state: open %s: %w", dbPath, err)
	}

	// Verify WAL mode is active.
	var mode string
	if err := sqlDB.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("state: check journal_mode: %w", err)
	}
	if mode != "wal" {
		log.Warn("SQLite journal_mode is not WAL", "mode", mode)
	}

	s := &DB{db: sqlDB, path: dbPath}

	// Apply restrictive file permissions to the database file.
	if err := permissions.EnforceRestrictive(dbPath); err != nil {
		log.Warn("could not enforce permissions on state DB", "path", dbPath, "error", err)
	}
	// Also enforce on WAL and SHM files if they exist.
	for _, suffix := range []string{"-wal", "-shm"} {
		p := dbPath + suffix
		if _, err := os.Stat(p); err == nil {
			_ = permissions.EnforceRestrictive(p)
		}
	}

	if err := s.migrate(); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("state: migrate: %w", err)
	}

	log.Info("state database opened", "path", dbPath, "mode", mode)
	return s, nil
}

// Close closes the database connection.
func (s *DB) Close() error {
	return s.db.Close()
}

// Path returns the full path to the database file.
func (s *DB) Path() string {
	return s.path
}

func resolveDir(configured string) (string, error) {
	if configured != "" {
		return configured, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

