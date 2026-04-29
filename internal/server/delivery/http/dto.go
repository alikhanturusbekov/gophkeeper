package delivery

import (
	"github.com/alikhanturusbekov/gophkeeper/internal/domain"
)

// RegisterRequest is the JSON body for POST /api/v1/register.
type RegisterRequest struct {
	// Login is the desired account name.
	Login string `json:"login"`
	// Password is the desired master password (plaintext over TLS).
	Password string `json:"password"`
}

// LoginRequest is the JSON body for POST /api/v1/login.
type LoginRequest struct {
	// Login is the account name.
	Login string `json:"login"`
	// Password is the master password.
	Password string `json:"password"`
}

// TokenResponse is the JSON body returned after successful auth.
type TokenResponse struct {
	// Token is a signed JWT valid for 24 h.
	Token string `json:"token"`
}

// SecretRequest is the JSON body for create / update secret endpoints.
type SecretRequest struct {
	// Name is a short human-readable label.
	Name string `json:"name"`
	// Kind is one of "credential", "text", "binary", "card".
	Kind domain.SecretKind `json:"kind"`
	// EncryptedData is the AES-256-GCM ciphertext produced by the client.
	EncryptedData []byte `json:"encrypted_data"`
	// Metadata is optional freeform text attached to the secret.
	Metadata string `json:"metadata,omitempty"`
}

// SyncRequest is the JSON body for POST /api/v1/sync.
type SyncRequest struct {
	// Secrets is the list of client-side secrets to reconcile.
	Secrets []domain.Secret `json:"secrets"`
}

// SyncResponse is the JSON body returned by POST /api/v1/sync.
type SyncResponse struct {
	// Secrets is the full authoritative list after reconciliation.
	Secrets []*domain.Secret `json:"secrets"`
}

// ErrorResponse is the standard JSON error envelope.
type ErrorResponse struct {
	// Error is a human-readable description of the failure.
	Error string `json:"error"`
}
