package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/alikhanturusbekov/gophkeeper/internal/domain"
)

// SecretUseCase implements domain.SecretUseCase
type SecretUseCase struct {
	secrets domain.SecretRepository
}

// NewSecretUseCase constructs a SecretUseCase backed by the given repository
func NewSecretUseCase(secrets domain.SecretRepository) *SecretUseCase {
	return &SecretUseCase{secrets: secrets}
}

// Create stores a new encrypted secret and returns the persisted entity
func (uc *SecretUseCase) Create(ctx context.Context, userID string, s *domain.Secret) (*domain.Secret, error) {
	s.ID = uuid.NewString()
	s.UserID = userID
	s.CreatedAt = time.Now()

	if err := uc.secrets.Save(ctx, s); err != nil {
		return nil, fmt.Errorf("secret use-case: create: %w", err)
	}
	return s, nil
}

// Update replaces mutable fields of an existing secret
func (uc *SecretUseCase) Update(ctx context.Context, userID string, s *domain.Secret) (*domain.Secret, error) {
	existing, err := uc.secrets.FindByID(ctx, userID, s.ID)
	if err != nil {
		return nil, err
	}

	existing.Name = s.Name
	existing.Kind = s.Kind
	existing.EncryptedData = s.EncryptedData
	existing.Metadata = s.Metadata

	if err := uc.secrets.Save(ctx, existing); err != nil {
		return nil, fmt.Errorf("secret use-case: update: %w", err)
	}
	return existing, nil
}

// Delete soft-deletes a secret so the tombstone propagates to all clients
func (uc *SecretUseCase) Delete(ctx context.Context, userID, secretID string) error {
	if err := uc.secrets.SoftDelete(ctx, userID, secretID); err != nil {
		return fmt.Errorf("secret use-case: delete: %w", err)
	}
	return nil
}

// List returns all live secrets owned by userID
func (uc *SecretUseCase) List(ctx context.Context, userID string) ([]*domain.Secret, error) {
	secrets, err := uc.secrets.FindAllByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("secret use-case: list: %w", err)
	}
	return secrets, nil
}

// Get returns a single secret. Returns domain.ErrNotFound when absent
func (uc *SecretUseCase) Get(ctx context.Context, userID, secretID string) (*domain.Secret, error) {
	s, err := uc.secrets.FindByID(ctx, userID, secretID)
	if err != nil {
		return nil, fmt.Errorf("secret use-case: get: %w", err)
	}
	return s, nil
}

// Sync reconciles a batch of client-side secrets with the server state
func (uc *SecretUseCase) Sync(ctx context.Context, userID string, clientSecrets []*domain.Secret) ([]*domain.Secret, error) {
	for _, cl := range clientSecrets {
		cl.UserID = userID

		srv, err := uc.secrets.FindByID(ctx, userID, cl.ID)
		if err == domain.ErrNotFound || (err == nil && cl.Version >= srv.Version) {
			if cl.CreatedAt.IsZero() {
				cl.CreatedAt = time.Now()
			}
			if saveErr := uc.secrets.Save(ctx, cl); saveErr != nil {
				return nil, fmt.Errorf("secret use-case: sync save: %w", saveErr)
			}
		}
	}

	all, err := uc.secrets.FindAllByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("secret use-case: sync list: %w", err)
	}
	return all, nil
}

// Compile-time interface satisfaction check
var _ domain.SecretUseCase = (*SecretUseCase)(nil)
