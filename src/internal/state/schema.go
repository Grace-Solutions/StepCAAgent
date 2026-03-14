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
			id               INTEGER PRIMARY KEY CHECK (id = 1),
			reachable        INTEGER NOT NULL DEFAULT 0,
			roots_installed  INTEGER NOT NULL DEFAULT 0,
			last_check       TEXT,
			last_error       TEXT,
			updated_at       TEXT NOT NULL DEFAULT (datetime('now'))
		)`,
		// Ensure the singleton rows exist.
		`INSERT OR IGNORE INTO config_state (id, config_hash, config_ver) VALUES (1, '', 0)`,
		`INSERT OR IGNORE INTO ca_status (id, reachable, roots_installed) VALUES (1, 0, 0)`,

		// Schema migrations for existing databases
		// Add installed_to_store column if missing
		`CREATE TABLE IF NOT EXISTS _migration_check (id INTEGER PRIMARY KEY)`,
	}

	// Conditional ALTER TABLE migrations — these are no-ops if the column already exists.
	alterMigrations := []struct {
		table  string
		column string
		ddl    string
	}{
		{"certificates", "installed_to_store", `ALTER TABLE certificates ADD COLUMN installed_to_store INTEGER NOT NULL DEFAULT 0`},
		{"ca_status", "roots_installed", `ALTER TABLE ca_status ADD COLUMN roots_installed INTEGER NOT NULL DEFAULT 0`},
	}

	for _, stmt := range statements {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("exec %q: %w", stmt[:40], err)
		}
	}

	// Apply ALTER TABLE migrations (ignore "duplicate column" errors)
	for _, m := range alterMigrations {
		if !s.columnExists(m.table, m.column) {
			if _, err := s.db.Exec(m.ddl); err != nil {
				return fmt.Errorf("migrate %s.%s: %w", m.table, m.column, err)
			}
		}
	}

	return nil
}

// columnExists checks if a column exists in the given table.
func (s *DB) columnExists(table, column string) bool {
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull int
		var dfltValue interface{}
		var pk int
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk); err != nil {
			continue
		}
		if name == column {
			return true
		}
	}
	return false
}

