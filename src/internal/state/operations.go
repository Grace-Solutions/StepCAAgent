package state

import (
	"database/sql"
	"fmt"
	"time"
)

// CertRecord represents a row in the certificates table.
type CertRecord struct {
	Name             string
	Thumbprint       string
	Serial           string
	Subject          string
	Issuer           string
	NotBefore        time.Time
	NotAfter         time.Time
	StorageType      string
	StoragePath      string
	InstalledToStore bool
	CreatedAt        time.Time
	UpdatedAt        time.Time
}

// UpsertCertificate inserts or updates a certificate record.
func (s *DB) UpsertCertificate(r CertRecord) error {
	its := 0
	if r.InstalledToStore {
		its = 1
	}
	_, err := s.db.Exec(`
		INSERT INTO certificates (name, thumbprint, serial, subject, issuer, not_before, not_after, storage_type, storage_path, installed_to_store, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
		ON CONFLICT(name) DO UPDATE SET
			thumbprint=excluded.thumbprint, serial=excluded.serial, subject=excluded.subject,
			issuer=excluded.issuer, not_before=excluded.not_before, not_after=excluded.not_after,
			storage_type=excluded.storage_type, storage_path=excluded.storage_path,
			installed_to_store=excluded.installed_to_store,
			updated_at=datetime('now')`,
		r.Name, r.Thumbprint, r.Serial, r.Subject, r.Issuer,
		r.NotBefore.Format(time.RFC3339), r.NotAfter.Format(time.RFC3339),
		r.StorageType, r.StoragePath, its,
	)
	return err
}

// GetCertificate retrieves a certificate record by name.
func (s *DB) GetCertificate(name string) (*CertRecord, error) {
	row := s.db.QueryRow(`SELECT name, thumbprint, serial, subject, issuer, not_before, not_after, storage_type, storage_path, installed_to_store FROM certificates WHERE name=?`, name)
	var r CertRecord
	var nb, na string
	var its int
	err := row.Scan(&r.Name, &r.Thumbprint, &r.Serial, &r.Subject, &r.Issuer, &nb, &na, &r.StorageType, &r.StoragePath, &its)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	r.NotBefore, _ = time.Parse(time.RFC3339, nb)
	r.NotAfter, _ = time.Parse(time.RFC3339, na)
	r.InstalledToStore = its == 1
	return &r, nil
}

// ListCertificates returns all certificate records.
func (s *DB) ListCertificates() ([]CertRecord, error) {
	rows, err := s.db.Query(`SELECT name, thumbprint, serial, subject, issuer, not_before, not_after, storage_type, storage_path, installed_to_store FROM certificates ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []CertRecord
	for rows.Next() {
		var r CertRecord
		var nb, na string
		var its int
		if err := rows.Scan(&r.Name, &r.Thumbprint, &r.Serial, &r.Subject, &r.Issuer, &nb, &na, &r.StorageType, &r.StoragePath, &its); err != nil {
			return nil, err
		}
		r.NotBefore, _ = time.Parse(time.RFC3339, nb)
		r.NotAfter, _ = time.Parse(time.RFC3339, na)
		r.InstalledToStore = its == 1
		result = append(result, r)
	}
	return result, rows.Err()
}

// RecordAuditEvent writes an audit event to the database.
func (s *DB) RecordAuditEvent(eventType, certName, detail, result string) error {
	_, err := s.db.Exec(
		`INSERT INTO audit_events (event_type, cert_name, detail, result) VALUES (?, ?, ?, ?)`,
		eventType, certName, detail, result,
	)
	return err
}

// UpdateConfigState records the current config hash and version.
func (s *DB) UpdateConfigState(hash string, version int) error {
	_, err := s.db.Exec(
		`UPDATE config_state SET config_hash=?, config_ver=?, loaded_at=datetime('now') WHERE id=1`,
		hash, version,
	)
	return err
}

// UpdateCAStatus updates the CA connectivity status.
func (s *DB) UpdateCAStatus(reachable bool, lastErr string) error {
	r := 0
	if reachable {
		r = 1
	}
	_, err := s.db.Exec(
		`UPDATE ca_status SET reachable=?, last_check=datetime('now'), last_error=?, updated_at=datetime('now') WHERE id=1`,
		r, lastErr,
	)
	return err
}

// UpdateRenewalTracking updates renewal tracking for a certificate.
func (s *DB) UpdateRenewalTracking(certName string, success bool, nextScheduled time.Time, lastErr string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	next := nextScheduled.UTC().Format(time.RFC3339)

	if success {
		_, err := s.db.Exec(`
			INSERT INTO renewal_tracking (cert_name, last_attempt, last_success, next_scheduled, retry_count, updated_at)
			VALUES (?, ?, ?, ?, 0, ?)
			ON CONFLICT(cert_name) DO UPDATE SET
				last_attempt=?, last_success=?, next_scheduled=?, retry_count=0, last_error='', updated_at=?`,
			certName, now, now, next, now,
			now, now, next, now,
		)
		return err
	}
	_, err := s.db.Exec(`
		INSERT INTO renewal_tracking (cert_name, last_attempt, next_scheduled, retry_count, last_error, updated_at)
		VALUES (?, ?, ?, 1, ?, ?)
		ON CONFLICT(cert_name) DO UPDATE SET
			last_attempt=?, next_scheduled=?, retry_count=renewal_tracking.retry_count+1, last_error=?, updated_at=?`,
		certName, now, next, lastErr, now,
		now, next, lastErr, now,
	)
	return err
}

// GetNextScheduled returns the next scheduled renewal time for a provisioner.
// Returns zero time if no tracking record exists.
func (s *DB) GetNextScheduled(certName string) (time.Time, error) {
	var next string
	err := s.db.QueryRow(`SELECT next_scheduled FROM renewal_tracking WHERE cert_name=?`, certName).Scan(&next)
	if err == sql.ErrNoRows {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, err
	}
	t, _ := time.Parse(time.RFC3339, next)
	return t, nil
}

// GetRetryCount returns the current retry count for a provisioner.
func (s *DB) GetRetryCount(certName string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT retry_count FROM renewal_tracking WHERE cert_name=?`, certName).Scan(&count)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return count, err
}

// ListTrackedCertNames returns all cert names in renewal_tracking.
func (s *DB) ListTrackedCertNames() ([]string, error) {
	rows, err := s.db.Query(`SELECT cert_name FROM renewal_tracking`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		names = append(names, n)
	}
	return names, rows.Err()
}

// DeleteRenewalTracking removes a renewal tracking record.
func (s *DB) DeleteRenewalTracking(certName string) error {
	_, err := s.db.Exec(`DELETE FROM renewal_tracking WHERE cert_name=?`, certName)
	return err
}

// AuditEvent represents a row from the audit_events table.
type AuditEvent struct {
	ID        int64
	Timestamp string
	EventType string
	CertName  string
	Detail    string
	Result    string
}

// RecentAuditEvents returns the last n audit events.
func (s *DB) RecentAuditEvents(n int) ([]AuditEvent, error) {
	rows, err := s.db.Query(`SELECT id, timestamp, event_type, cert_name, detail, result FROM audit_events ORDER BY id DESC LIMIT ?`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []AuditEvent
	for rows.Next() {
		var e AuditEvent
		if err := rows.Scan(&e.ID, &e.Timestamp, &e.EventType, &e.CertName, &e.Detail, &e.Result); err != nil {
			return nil, err
		}
		result = append(result, e)
	}
	return result, rows.Err()
}

// GetConfigState returns the stored config hash and version.
func (s *DB) GetConfigState() (hash string, version int, err error) {
	err = s.db.QueryRow(`SELECT config_hash, config_ver FROM config_state WHERE id=1`).Scan(&hash, &version)
	if err == sql.ErrNoRows {
		return "", 0, nil
	}
	return
}

// GetCAStatus returns the CA connectivity status.
func (s *DB) GetCAStatus() (reachable bool, lastCheck, lastErr string, err error) {
	var r int
	err = s.db.QueryRow(`SELECT reachable, COALESCE(last_check,''), COALESCE(last_error,'') FROM ca_status WHERE id=1`).Scan(&r, &lastCheck, &lastErr)
	if err == sql.ErrNoRows {
		return false, "", "", nil
	}
	reachable = r == 1
	return
}

// Exec exposes raw SQL execution for advanced use cases.
func (s *DB) Exec(query string, args ...interface{}) (sql.Result, error) {
	return s.db.Exec(query, args...)
}

// Query exposes raw SQL queries for advanced use cases.
func (s *DB) Query(query string, args ...interface{}) (*sql.Rows, error) {
	return s.db.Query(query, args...)
}

// SetInstalledToStore updates the installed_to_store flag for a certificate.
func (s *DB) SetInstalledToStore(name string, installed bool) error {
	v := 0
	if installed {
		v = 1
	}
	_, err := s.db.Exec(`UPDATE certificates SET installed_to_store=?, updated_at=datetime('now') WHERE name=?`, v, name)
	return err
}

// GetRootsInstalled returns whether the root CA was previously installed to the store.
func (s *DB) GetRootsInstalled() (bool, error) {
	var v int
	err := s.db.QueryRow(`SELECT roots_installed FROM ca_status WHERE id=1`).Scan(&v)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return v == 1, nil
}

// SetRootsInstalled records whether the root CA is installed in the store.
func (s *DB) SetRootsInstalled(installed bool) error {
	v := 0
	if installed {
		v = 1
	}
	_, err := s.db.Exec(`UPDATE ca_status SET roots_installed=?, updated_at=datetime('now') WHERE id=1`, v)
	return err
}

// DeleteCertificate removes a certificate record by name.
func (s *DB) DeleteCertificate(name string) error {
	_, err := s.db.Exec(`DELETE FROM certificates WHERE name=?`, name)
	if err != nil {
		return fmt.Errorf("delete certificate %q: %w", name, err)
	}
	_, _ = s.db.Exec(`DELETE FROM renewal_tracking WHERE cert_name=?`, name)
	return nil
}

