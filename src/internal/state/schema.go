package state

import "fmt"

// migrate applies the database schema. It uses IF NOT EXISTS so it's
// safe to run on every startup.
func (s *DB) migrate() error {
	statements := []string{
		`CREATE TABLE IF NOT EXISTS certificates (
			id            INTEGER PRIMARY KEY AUTOINCREMENT,
			name          TEXT NOT NULL UNIQUE,
			thumbprint    TEXT,
			serial        TEXT,
			subject       TEXT,
			issuer        TEXT,
			not_before    TEXT,
			not_after     TEXT,
			storage_type  TEXT,
			storage_path  TEXT,
			created_at    TEXT NOT NULL DEFAULT (datetime('now')),
			updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS renewal_tracking (
			id              INTEGER PRIMARY KEY AUTOINCREMENT,
			cert_name       TEXT NOT NULL UNIQUE REFERENCES certificates(name),
			last_attempt    TEXT,
			last_success    TEXT,
			next_scheduled  TEXT,
			retry_count     INTEGER NOT NULL DEFAULT 0,
			last_error      TEXT,
			updated_at      TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS audit_events (
			id         INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp  TEXT NOT NULL DEFAULT (datetime('now')),
			event_type TEXT NOT NULL,
			cert_name  TEXT,
			detail     TEXT,
			result     TEXT
		)`,
		`CREATE TABLE IF NOT EXISTS config_state (
			id           INTEGER PRIMARY KEY CHECK (id = 1),
			config_hash  TEXT,
			config_ver   INTEGER,
			loaded_at    TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		`CREATE TABLE IF NOT EXISTS ca_status (
			id             INTEGER PRIMARY KEY CHECK (id = 1),
			reachable      INTEGER NOT NULL DEFAULT 0,
			last_check     TEXT,
			last_error     TEXT,
			updated_at     TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		// Ensure the singleton rows exist.
		`INSERT OR IGNORE INTO config_state (id, config_hash, config_ver) VALUES (1, '', 0)`,
		`INSERT OR IGNORE INTO ca_status (id, reachable) VALUES (1, 0)`,
	}

	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("exec %q: %w", stmt[:40], err)
		}
	}
	return nil
}

