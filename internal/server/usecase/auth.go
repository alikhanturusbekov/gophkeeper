package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/alikhanturusbekov/gophkeeper/internal/domain"
	jwtpkg "github.com/alikhanturusbekov/gophkeeper/pkg/jwt"
)

// AuthUseCase implements domain.AuthService and domain.UserUseCase
type AuthUseCase struct {
	users domain.UserRepository
	jwt   *jwtpkg.Manager
}

// NewAuthUseCase constructs an AuthUseCase with the given repository and JWT manager.
func NewAuthUseCase(users domain.UserRepository, jwt *jwtpkg.Manager) *AuthUseCase {
	return &AuthUseCase{users: users, jwt: jwt}
}

// Register creates a new user account
func (uc *AuthUseCase) Register(ctx context.Context, login, password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("auth: hash password: %w", err)
	}

	u := &domain.User{
		ID:           uuid.NewString(),
		Login:        login,
		PasswordHash: string(hash),
		CreatedAt:    time.Now(),
	}

	if err := uc.users.Save(ctx, u); err != nil {
		return "", err // domain.ErrConflict bubbles up unchanged.
	}

	token, err := uc.jwt.Generate(u.ID)
	if err != nil {
		return "", fmt.Errorf("auth: generate token: %w", err)
	}
	return token, nil
}

// Login authenticates the user and returns a signed JWT
func (uc *AuthUseCase) Login(ctx context.Context, login, password string) (string, error) {
	u, err := uc.users.FindByLogin(ctx, login)
	if err != nil {
		return "", domain.ErrUnauthorized
	}
	if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) != nil {
		return "", domain.ErrUnauthorized
	}

	token, err := uc.jwt.Generate(u.ID)
	if err != nil {
		return "", fmt.Errorf("auth: generate token: %w", err)
	}
	return token, nil
}

// GenerateToken creates a signed JWT for the given userID
func (uc *AuthUseCase) GenerateToken(userID string) (string, error) {
	return uc.jwt.Generate(userID)
}

// ValidateToken parses and verifies a JWT, returning the embedded userID
func (uc *AuthUseCase) ValidateToken(token string) (string, error) {
	uid, err := uc.jwt.Validate(token)
	if err != nil {
		return "", domain.ErrUnauthorized
	}
	return uid, nil
}

// HashPassword produces a bcrypt digest of plaintext.
func (uc *AuthUseCase) HashPassword(plaintext string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// CheckPassword reports whether plaintext matches the stored hash.
func (uc *AuthUseCase) CheckPassword(hash, plaintext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}

// Compile-time interface satisfaction checks.
var (
	_ domain.UserUseCase = (*AuthUseCase)(nil)
	_ domain.AuthService = (*AuthUseCase)(nil)
)
