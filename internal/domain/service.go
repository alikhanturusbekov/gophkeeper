package domain

import "context"

// AuthService defines authentication and authorisation operations
type AuthService interface {
	// GenerateToken creates a signed JWT for the given userID.
	GenerateToken(userID string) (string, error)

	// ValidateToken parses and verifies a JWT, returning the embedded userID
	ValidateToken(token string) (userID string, err error)

	// HashPassword produces a bcrypt digest of plaintext
	HashPassword(plaintext string) (string, error)

	// CheckPassword reports whether plaintext matches the stored hash
	CheckPassword(hash, plaintext string) bool
}

// UserUseCase defines the application-level operations on User entities.
type UserUseCase interface {
	// Register creates a new user account
	Register(ctx context.Context, login, password string) (token string, err error)

	// Login authenticates the user and returns a signed JWT
	Login(ctx context.Context, login, password string) (token string, err error)
}

// SecretUseCase defines the application-level operations on Secret entities
type SecretUseCase interface {
	// Create stores a new encrypted secret and returns the persisted entity
	Create(ctx context.Context, userID string, s *Secret) (*Secret, error)

	// Update replaces an existing secret's mutable fields
	Update(ctx context.Context, userID string, s *Secret) (*Secret, error)

	// Delete soft-deletes a secret so the tombstone propagates to clients
	Delete(ctx context.Context, userID, secretID string) error

	// List returns all non-deleted secrets owned by userID
	List(ctx context.Context, userID string) ([]*Secret, error)

	// Get returns a single secret by its ID
	Get(ctx context.Context, userID, secretID string) (*Secret, error)

	// Sync reconciles a set of client-side secrets with the server
	Sync(ctx context.Context, userID string, clientSecrets []*Secret) ([]*Secret, error)
}
