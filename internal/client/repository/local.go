package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/alikhanturusbekov/gophkeeper/internal/domain"
)

// LocalDB is a local SQLite store for the GophKeeper client
type LocalDB struct {
	conn *sql.DB
}

// NewLocalDB opens (or creates) the client-side SQLite database at path and applies the schema migrations
func NewLocalDB(path string) (*LocalDB, error) {
	conn, err := sql.Open("sqlite3", path+"?_journal_mode=WAL")
	if err != nil {
		return nil, fmt.Errorf("client repo: open: %w", err)
	}
	db := &LocalDB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("client repo: migrate: %w", err)
	}
	return db, nil
}

// migrate creates local tables if they do not yet exist.
func (db *LocalDB) migrate() error {
	_, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS secrets (
			id             TEXT    PRIMARY KEY,
			user_id        TEXT    NOT NULL,
			name           TEXT    NOT NULL,
			kind           TEXT    NOT NULL,
			encrypted_data BLOB    NOT NULL,
			metadata       TEXT    NOT NULL DEFAULT '',
			version        INTEGER NOT NULL DEFAULT 0,
			created_at     INTEGER NOT NULL,
			updated_at     INTEGER NOT NULL,
			deleted        INTEGER NOT NULL DEFAULT 0
		);

		CREATE TABLE IF NOT EXISTS meta (
			key   TEXT PRIMARY KEY,
			value TEXT NOT NULL
		);
	`)
	return err
}

// Close releases the database connection
func (db *LocalDB) Close() error { return db.conn.Close() }

// Save creates or replaces a Secret in the local cache
func (db *LocalDB) Save(_ context.Context, s *domain.Secret) error {
	_, err := db.conn.Exec(`
		INSERT INTO secrets
			(id, user_id, name, kind, encrypted_data, metadata, version, created_at, updated_at, deleted)
		VALUES (?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			name=excluded.name, kind=excluded.kind,
			encrypted_data=excluded.encrypted_data, metadata=excluded.metadata,
			version=excluded.version, updated_at=excluded.updated_at, deleted=excluded.deleted`,
		s.ID, s.UserID, s.Name, string(s.Kind),
		s.EncryptedData, s.Metadata, s.Version,
		s.CreatedAt.UnixNano(), s.UpdatedAt.UnixNano(), boolInt(s.Deleted),
	)
	if err != nil {
		return fmt.Errorf("client repo: save: %w", err)
	}
	return nil
}

// SoftDelete marks a secret as deleted in the local cache
func (db *LocalDB) SoftDelete(_ context.Context, userID, secretID string) error {
	res, err := db.conn.Exec(
		`UPDATE secrets SET deleted=1 WHERE id=? AND user_id=?`, secretID, userID)
	if err != nil {
		return fmt.Errorf("client repo: soft delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// FindAllByUser returns all live (non-deleted) cached secrets for a user
func (db *LocalDB) FindAllByUser(_ context.Context, userID string) ([]*domain.Secret, error) {
	rows, err := db.conn.Query(
		`SELECT id, user_id, name, kind, encrypted_data, metadata, version, created_at, updated_at, deleted
		 FROM secrets WHERE user_id=? AND deleted=0 ORDER BY created_at`, userID)
	if err != nil {
		return nil, fmt.Errorf("client repo: find all: %w", err)
	}
	defer rows.Close()
	return scanSecrets(rows)
}

// FindByID returns a single cached secret for a user
func (db *LocalDB) FindByID(_ context.Context, userID, secretID string) (*domain.Secret, error) {
	var s domain.Secret
	var cn, un int64
	var del int
	err := db.conn.QueryRow(
		`SELECT id, user_id, name, kind, encrypted_data, metadata, version, created_at, updated_at, deleted
		 FROM secrets WHERE id=? AND user_id=?`, secretID, userID).
		Scan(&s.ID, &s.UserID, &s.Name, (*string)(&s.Kind),
			&s.EncryptedData, &s.Metadata, &s.Version, &cn, &un, &del)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("client repo: find by id: %w", err)
	}
	s.CreatedAt = time.Unix(0, cn)
	s.UpdatedAt = time.Unix(0, un)
	s.Deleted = del != 0
	return &s, nil
}

// FindUpdatedAfter returns cached secrets with version > after
func (db *LocalDB) FindUpdatedAfter(_ context.Context, userID string, after int64) ([]*domain.Secret, error) {
	rows, err := db.conn.Query(
		`SELECT id, user_id, name, kind, encrypted_data, metadata, version, created_at, updated_at, deleted
		 FROM secrets WHERE user_id=? AND version>? ORDER BY version`, userID, after)
	if err != nil {
		return nil, fmt.Errorf("client repo: find updated after: %w", err)
	}
	defer rows.Close()
	return scanSecrets(rows)
}

// GetMeta reads a metadata value by key
func (db *LocalDB) GetMeta(key string) (string, error) {
	var val string
	err := db.conn.QueryRow(`SELECT value FROM meta WHERE key=?`, key).Scan(&val)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return val, err
}

// SetMeta persists a metadata key/value pair
func (db *LocalDB) SetMeta(key, value string) error {
	_, err := db.conn.Exec(
		`INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,
		key, value)
	return err
}

func scanSecrets(rows *sql.Rows) ([]*domain.Secret, error) {
	var out []*domain.Secret
	for rows.Next() {
		var s domain.Secret
		var cn, un int64
		var del int
		if err := rows.Scan(&s.ID, &s.UserID, &s.Name, (*string)(&s.Kind),
			&s.EncryptedData, &s.Metadata, &s.Version, &cn, &un, &del); err != nil {
			return nil, fmt.Errorf("client repo: scan: %w", err)
		}
		s.CreatedAt = time.Unix(0, cn)
		s.UpdatedAt = time.Unix(0, un)
		s.Deleted = del != 0
		out = append(out, &s)
	}
	return out, rows.Err()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Compile-time interface satisfaction check
var _ domain.SecretRepository = (*LocalDB)(nil)
