package jwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// DefaultTTL is the lifetime of a freshly issued token.
	DefaultTTL = 24 * time.Hour
)

// ErrInvalidToken is returned by Manager.Validate
var ErrInvalidToken = errors.New("jwt: invalid or expired token")

// Claims embeds the standard JWT registered claims
type Claims struct {
	jwt.RegisteredClaims

	// UserID is the authenticated user's unique identifier.
	UserID string `json:"uid"`
}

// Manager signs and validates JWTs using HMAC-SHA256.
type Manager struct {
	secret []byte
	ttl    time.Duration
}

// NewManager creates a Manager that signs tokens with the provided secret
// The token TTL defaults to DefaultTTL.
func NewManager(secret string) *Manager {
	return &Manager{secret: []byte(secret), ttl: DefaultTTL}
}

// NewManagerWithTTL creates a Manager with a custom token lifetime
func NewManagerWithTTL(secret string, ttl time.Duration) *Manager {
	return &Manager{secret: []byte(secret), ttl: ttl}
}

// Generate creates a signed JWT embedding userID
func (m *Manager) Generate(userID string) (string, error) {
	now := time.Now()
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(m.ttl)),
		},
		UserID: userID,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(m.secret)
	if err != nil {
		return "", fmt.Errorf("jwt: sign: %w", err)
	}
	return signed, nil
}

// Validate parses and verifies tokenStr, returning the embedded userID
func (m *Manager) Validate(tokenStr string) (string, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secret, nil
	})

	if err != nil {
		return "", ErrInvalidToken
	}
	claims, ok := token.Claims.(*Claims)

	if !ok || !token.Valid {
		return "", ErrInvalidToken
	}

	return claims.UserID, nil
}
