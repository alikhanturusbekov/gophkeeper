package domain

import "context"

// UserRepository defines persistence operations for User entities
type UserRepository interface {
	// Save persists a new User
	Save(ctx context.Context, user *User) error

	// FindByLogin retrieves a User by their login name
	FindByLogin(ctx context.Context, login string) (*User, error)

	// FindByID retrieves a User by their unique identifier
	FindByID(ctx context.Context, id string) (*User, error)
}

// SecretRepository defines persistence operations for Secret entities
type SecretRepository interface {
	// Save creates or fully replaces a Secret
	Save(ctx context.Context, secret *Secret) error

	// SoftDelete marks the Secret identified by (userID, secretID)
	SoftDelete(ctx context.Context, userID, secretID string) error

	// FindAllByUser returns all non-deleted secrets owned by userID
	FindAllByUser(ctx context.Context, userID string) ([]*Secret, error)

	// FindByID returns the Secret with the given id belonging to userID
	FindByID(ctx context.Context, userID, secretID string) (*Secret, error)

	// FindUpdatedAfter returns all secrets whose Version is greater than afterVersion
	FindUpdatedAfter(ctx context.Context, userID string, afterVersion int64) ([]*Secret, error)
}
