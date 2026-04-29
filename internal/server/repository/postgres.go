package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // pgx database/sql driver registration.

	"github.com/alikhanturusbekov/gophkeeper/internal/domain"
)

// DB is the shared PostgreSQL handle
type DB struct {
	conn *sql.DB
}

// NewDB opens a connection pool to the PostgreSQL server at dsn
func NewDB(dsn string) (*DB, error) {
	conn, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("repository: open: %w", err)
	}
	conn.SetMaxOpenConns(25)
	conn.SetMaxIdleConns(5)
	conn.SetConnMaxLifetime(5 * time.Minute)

	db := &DB{conn: conn}
	if err := db.migrate(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("repository: migrate: %w", err)
	}
	return db, nil
}

// migrate creates tables and indexes when they do not yet exist
func (db *DB) migrate() error {
	_, err := db.conn.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id            TEXT        PRIMARY KEY,
			login         TEXT        UNIQUE NOT NULL,
			password_hash TEXT        NOT NULL,
			created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);

		CREATE TABLE IF NOT EXISTS secrets (
			id             TEXT        PRIMARY KEY,
			user_id        TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			name           TEXT        NOT NULL,
			kind           TEXT        NOT NULL,
			encrypted_data BYTEA       NOT NULL,
			metadata       TEXT        NOT NULL DEFAULT '',
			version        BIGINT      NOT NULL DEFAULT 0,
			created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
			deleted        BOOLEAN     NOT NULL DEFAULT FALSE
		);

		CREATE INDEX IF NOT EXISTS idx_secrets_user    ON secrets (user_id);
		CREATE INDEX IF NOT EXISTS idx_secrets_version ON secrets (user_id, version);
	`)
	return err
}

// Close releases the database connection pool
func (db *DB) Close() error { return db.conn.Close() }

// UserRepo implements domain.UserRepository on top of a shared PostgreSQL DB
type UserRepo struct{ db *DB }

// NewUserRepo constructs a UserRepo backed by db
func NewUserRepo(db *DB) *UserRepo { return &UserRepo{db: db} }

// Save persists a new User
func (r *UserRepo) Save(ctx context.Context, u *domain.User) error {
	_, err := r.db.conn.ExecContext(ctx,
		`INSERT INTO users (id, login, password_hash, created_at)
		 VALUES ($1, $2, $3, $4)`,
		u.ID, u.Login, u.PasswordHash, u.CreatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return domain.ErrConflict
		}
		return fmt.Errorf("user repo: save: %w", err)
	}
	return nil
}

// FindByLogin retrieves the User with the given login
func (r *UserRepo) FindByLogin(ctx context.Context, login string) (*domain.User, error) {
	row := r.db.conn.QueryRowContext(ctx,
		`SELECT id, login, password_hash, created_at FROM users WHERE login = $1`, login)
	return scanUser(row)
}

// FindByID retrieves the User with the given ID
func (r *UserRepo) FindByID(ctx context.Context, id string) (*domain.User, error) {
	row := r.db.conn.QueryRowContext(ctx,
		`SELECT id, login, password_hash, created_at FROM users WHERE id = $1`, id)
	return scanUser(row)
}

func scanUser(row *sql.Row) (*domain.User, error) {
	var u domain.User
	if err := row.Scan(&u.ID, &u.Login, &u.PasswordHash, &u.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, fmt.Errorf("user repo: scan: %w", err)
	}
	return &u, nil
}

// SecretRepo implements domain.SecretRepository on top of a shared PostgreSQL DB
type SecretRepo struct{ db *DB }

// NewSecretRepo constructs a SecretRepo backed by db
func NewSecretRepo(db *DB) *SecretRepo { return &SecretRepo{db: db} }

// Save upserts a Secret, stamping Version (Unix nanoseconds) and UpdatedAt
func (r *SecretRepo) Save(ctx context.Context, s *domain.Secret) error {
	now := time.Now()
	s.UpdatedAt = now
	s.Version = now.UnixNano()

	_, err := r.db.conn.ExecContext(ctx, `
		INSERT INTO secrets
			(id, user_id, name, kind, encrypted_data, metadata, version, created_at, updated_at, deleted)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (id) DO UPDATE SET
			name           = EXCLUDED.name,
			kind           = EXCLUDED.kind,
			encrypted_data = EXCLUDED.encrypted_data,
			metadata       = EXCLUDED.metadata,
			version        = EXCLUDED.version,
			updated_at     = EXCLUDED.updated_at,
			deleted        = EXCLUDED.deleted`,
		s.ID, s.UserID, s.Name, string(s.Kind),
		s.EncryptedData, s.Metadata, s.Version,
		s.CreatedAt, s.UpdatedAt, s.Deleted,
	)
	if err != nil {
		return fmt.Errorf("secret repo: save: %w", err)
	}
	return nil
}

// SoftDelete marks a secret as deleted without physically removing the row
func (r *SecretRepo) SoftDelete(ctx context.Context, userID, secretID string) error {
	now := time.Now()
	res, err := r.db.conn.ExecContext(ctx,
		`UPDATE secrets
		 SET deleted = TRUE, version = $1, updated_at = $2
		 WHERE id = $3 AND user_id = $4`,
		now.UnixNano(), now, secretID, userID,
	)
	if err != nil {
		return fmt.Errorf("secret repo: soft delete: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

// FindAllByUser returns all live (non-deleted) secrets for a user
func (r *SecretRepo) FindAllByUser(ctx context.Context, userID string) ([]*domain.Secret, error) {
	rows, err := r.db.conn.QueryContext(ctx, `
		SELECT id, user_id, name, kind, encrypted_data, metadata, version, created_at, updated_at, deleted
		FROM secrets
		WHERE user_id = $1 AND deleted = FALSE
		ORDER BY created_at`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("secret repo: find all: %w", err)
	}
	defer rows.Close()
	return scanSecrets(rows)
}

// FindByID returns one secret scoped to the given user
func (r *SecretRepo) FindByID(ctx context.Context, userID, secretID string) (*domain.Secret, error) {
	return r.findByIDDirect(ctx, userID, secretID)
}

// FindUpdatedAfter returns secrets (including tombstones) with version > after
func (r *SecretRepo) FindUpdatedAfter(ctx context.Context, userID string, after int64) ([]*domain.Secret, error) {
	rows, err := r.db.conn.QueryContext(ctx, `
		SELECT id, user_id, name, kind, encrypted_data, metadata, version, created_at, updated_at, deleted
		FROM secrets
		WHERE user_id = $1 AND version > $2
		ORDER BY version`, userID, after,
	)
	if err != nil {
		return nil, fmt.Errorf("secret repo: find updated after: %w", err)
	}
	defer rows.Close()
	return scanSecrets(rows)
}

// findByIDDirect performs the single-row query for FindByID
func (r *SecretRepo) findByIDDirect(ctx context.Context, userID, secretID string) (*domain.Secret, error) {
	var s domain.Secret
	err := r.db.conn.QueryRowContext(ctx, `
		SELECT id, user_id, name, kind, encrypted_data, metadata, version, created_at, updated_at, deleted
		FROM secrets WHERE id = $1 AND user_id = $2`, secretID, userID).
		Scan(&s.ID, &s.UserID, &s.Name, (*string)(&s.Kind),
			&s.EncryptedData, &s.Metadata, &s.Version,
			&s.CreatedAt, &s.UpdatedAt, &s.Deleted)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("secret repo: find by id: %w", err)
	}
	return &s, nil
}

func scanSecrets(rows *sql.Rows) ([]*domain.Secret, error) {
	if rows == nil {
		return nil, nil
	}
	var out []*domain.Secret
	for rows.Next() {
		var s domain.Secret
		if err := rows.Scan(&s.ID, &s.UserID, &s.Name, (*string)(&s.Kind),
			&s.EncryptedData, &s.Metadata, &s.Version,
			&s.CreatedAt, &s.UpdatedAt, &s.Deleted); err != nil {
			return nil, fmt.Errorf("secret repo: scan: %w", err)
		}
		out = append(out, &s)
	}
	return out, rows.Err()
}

// isUniqueViolation reports whether err is a PostgreSQL unique-constraint violation (SQLSTATE 23505).
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	// pgx wraps the PgError; check the SQLSTATE code in the error message as a
	// fallback that works regardless of whether the caller used pgx directly or
	// via database/sql.
	return strings.Contains(err.Error(), "23505") ||
		strings.Contains(err.Error(), "unique constraint") ||
		strings.Contains(err.Error(), "unique_violation")
}

// Compile-time interface satisfaction checks
var (
	_ domain.UserRepository   = (*UserRepo)(nil)
	_ domain.SecretRepository = (*SecretRepo)(nil)
)
