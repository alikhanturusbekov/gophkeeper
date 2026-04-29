package usecase

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/alikhanturusbekov/gophkeeper/internal/domain"
	pkgcrypto "github.com/alikhanturusbekov/gophkeeper/pkg/crypto"
	"github.com/google/uuid"
)

// ServerClient is the interface that wraps the HTTP calls made to the GophKeeper server
type ServerClient interface {
	// Register creates a new account on the server
	Register(ctx context.Context, login, password string) (token string, err error)

	// Login authenticates and returns a JWT
	Login(ctx context.Context, login, password string) (token string, err error)

	// ListSecrets fetches all live secrets from the server
	ListSecrets(ctx context.Context, token string) ([]*domain.Secret, error)

	// CreateSecret stores a new secret on the server
	CreateSecret(ctx context.Context, token string, s *domain.Secret) (*domain.Secret, error)

	// UpdateSecret replaces a secret on the server
	UpdateSecret(ctx context.Context, token string, s *domain.Secret) (*domain.Secret, error)

	// DeleteSecret soft-deletes a secret on the server
	DeleteSecret(ctx context.Context, token, secretID string) error

	// Sync sends the local secrets list and returns the server's authoritative list
	Sync(ctx context.Context, token string, secrets []*domain.Secret) ([]*domain.Secret, error)
}

// LocalRepository is the subset of domain.SecretRepository
type LocalRepository interface {
	Save(ctx context.Context, s *domain.Secret) error
	SoftDelete(ctx context.Context, userID, secretID string) error
	FindAllByUser(ctx context.Context, userID string) ([]*domain.Secret, error)
	FindByID(ctx context.Context, userID, secretID string) (*domain.Secret, error)
	FindUpdatedAfter(ctx context.Context, userID string, after int64) ([]*domain.Secret, error)
}

// SecretUseCase provides the client-side secret management operations
type SecretUseCase struct {
	local  LocalRepository
	server ServerClient
	key    []byte        // AES-256 key derived from master password
	userID string        // set after successful login/register
	token  string        // JWT for server requests
	auth   AuthValidator // used by CLI to extract userID from server token
}

// NewSecretUseCase creates a SecretUseCase
func NewSecretUseCase(local LocalRepository, server ServerClient, masterPassword string) *SecretUseCase {
	return &SecretUseCase{
		local:  local,
		server: server,
		key:    pkgcrypto.DeriveKey(masterPassword),
	}
}

// SetSession stores the authenticated user's ID and JWT
func (uc *SecretUseCase) SetSession(userID, token string) {
	uc.userID = userID
	uc.token = token
}

// Encrypt encrypts plaintext JSON payload with the user's master key
func (uc *SecretUseCase) Encrypt(payload interface{}) ([]byte, error) {
	plain, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("client uc: marshal payload: %w", err)
	}
	ct, err := pkgcrypto.Encrypt(uc.key, plain)
	if err != nil {
		return nil, fmt.Errorf("client uc: encrypt: %w", err)
	}
	return ct, nil
}

// Decrypt decrypts a ciphertext and unmarshals it into dst
func (uc *SecretUseCase) Decrypt(ciphertext []byte, dst interface{}) error {
	plain, err := pkgcrypto.Decrypt(uc.key, ciphertext)
	if err != nil {
		return fmt.Errorf("client uc: decrypt: %w", err)
	}
	return json.Unmarshal(plain, dst)
}

// AddCredential encrypts and stores a login/password pair
func (uc *SecretUseCase) AddCredential(ctx context.Context, name, login, password, metadata string) (*domain.Secret, error) {
	ct, err := uc.Encrypt(domain.Credential{Login: login, Password: password})
	if err != nil {
		return nil, err
	}
	return uc.create(ctx, name, domain.KindCredential, ct, metadata)
}

// AddText encrypts and stores arbitrary text data
func (uc *SecretUseCase) AddText(ctx context.Context, name, content, metadata string) (*domain.Secret, error) {
	ct, err := uc.Encrypt(domain.TextData{Content: content})
	if err != nil {
		return nil, err
	}
	return uc.create(ctx, name, domain.KindText, ct, metadata)
}

// AddBinary encrypts and stores arbitrary binary data
func (uc *SecretUseCase) AddBinary(ctx context.Context, name, filename string, data []byte, metadata string) (*domain.Secret, error) {
	ct, err := uc.Encrypt(domain.BinaryData{Data: data, Filename: filename})
	if err != nil {
		return nil, err
	}
	return uc.create(ctx, name, domain.KindBinary, ct, metadata)
}

// AddCard encrypts and stores bank card details
func (uc *SecretUseCase) AddCard(ctx context.Context, name, number, holder, expiry, cvv, metadata string) (*domain.Secret, error) {
	ct, err := uc.Encrypt(domain.CardData{Number: number, Holder: holder, Expiry: expiry, CVV: cvv})
	if err != nil {
		return nil, err
	}
	return uc.create(ctx, name, domain.KindCard, ct, metadata)
}

// create is the shared helper used by all Add* methods
func (uc *SecretUseCase) create(ctx context.Context, name string, kind domain.SecretKind, ct []byte, metadata string) (*domain.Secret, error) {
	s := &domain.Secret{
		ID:            uuid.NewString(),
		UserID:        uc.userID,
		Name:          name,
		Kind:          kind,
		EncryptedData: ct,
		Metadata:      metadata,
		CreatedAt:     time.Now(),
	}

	// Persist locally first for offline resilience
	if err := uc.local.Save(ctx, s); err != nil {
		return nil, fmt.Errorf("client uc: local save: %w", err)
	}

	// Best-effort server push; offline users can sync later.
	if uc.token != "" {
		if srv, err := uc.server.CreateSecret(ctx, uc.token, s); err == nil {
			s.Version = srv.Version
			_ = uc.local.Save(ctx, s)
		}
	}
	return s, nil
}

// List returns all live locally-cached secrets for the current user
func (uc *SecretUseCase) List(ctx context.Context) ([]*domain.Secret, error) {
	return uc.local.FindAllByUser(ctx, uc.userID)
}

// Delete removes a secret locally and pushes the deletion to the server
func (uc *SecretUseCase) Delete(ctx context.Context, secretID string) error {
	if err := uc.local.SoftDelete(ctx, uc.userID, secretID); err != nil {
		return fmt.Errorf("client uc: local delete: %w", err)
	}
	if uc.token != "" {
		_ = uc.server.DeleteSecret(ctx, uc.token, secretID)
	}
	return nil
}

// Sync synchronises the local cache with the server
func (uc *SecretUseCase) Sync(ctx context.Context) error {
	local, err := uc.local.FindAllByUser(ctx, uc.userID)
	if err != nil {
		return fmt.Errorf("client uc: sync read local: %w", err)
	}

	merged, err := uc.server.Sync(ctx, uc.token, local)
	if err != nil {
		return fmt.Errorf("client uc: sync server: %w", err)
	}

	for _, s := range merged {
		if err := uc.local.Save(ctx, s); err != nil {
			return fmt.Errorf("client uc: sync write local: %w", err)
		}
	}
	return nil
}

// HTTPClient implements ServerClient against a live GophKeeper HTTP server
type HTTPClient struct {
	base   string
	client *http.Client
}

// NewHTTPClient creates an HTTPClient that talks to the server at baseURL
func NewHTTPClient(baseURL string) *HTTPClient {
	return &HTTPClient{base: baseURL, client: &http.Client{Timeout: 30 * time.Second}}
}

// Register calls POST /api/v1/register
func (c *HTTPClient) Register(ctx context.Context, login, password string) (string, error) {
	return c.postAuth(ctx, "/api/v1/register", map[string]string{"login": login, "password": password}, "")
}

// Login calls POST /api/v1/login
func (c *HTTPClient) Login(ctx context.Context, login, password string) (string, error) {
	return c.postAuth(ctx, "/api/v1/login", map[string]string{"login": login, "password": password}, "")
}

// ListSecrets calls GET /api/v1/secrets
func (c *HTTPClient) ListSecrets(ctx context.Context, token string) ([]*domain.Secret, error) {
	resp, err := c.doRequest(ctx, http.MethodGet, "/api/v1/secrets", nil, token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp); err != nil {
		return nil, err
	}
	var out []*domain.Secret
	return out, json.NewDecoder(resp.Body).Decode(&out)
}

// CreateSecret calls POST /api/v1/secrets
func (c *HTTPClient) CreateSecret(ctx context.Context, token string, s *domain.Secret) (*domain.Secret, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, "/api/v1/secrets", s, token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp); err != nil {
		return nil, err
	}
	var out domain.Secret
	return &out, json.NewDecoder(resp.Body).Decode(&out)
}

// UpdateSecret calls PUT /api/v1/secrets/{id}
func (c *HTTPClient) UpdateSecret(ctx context.Context, token string, s *domain.Secret) (*domain.Secret, error) {
	resp, err := c.doRequest(ctx, http.MethodPut, "/api/v1/secrets/"+s.ID, s, token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp); err != nil {
		return nil, err
	}
	var out domain.Secret
	return &out, json.NewDecoder(resp.Body).Decode(&out)
}

// DeleteSecret calls DELETE /api/v1/secrets/{id}
func (c *HTTPClient) DeleteSecret(ctx context.Context, token, secretID string) error {
	resp, err := c.doRequest(ctx, http.MethodDelete, "/api/v1/secrets/"+secretID, nil, token)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return checkStatus(resp)
}

// Sync calls POST /api/v1/sync
func (c *HTTPClient) Sync(ctx context.Context, token string, secrets []*domain.Secret) ([]*domain.Secret, error) {
	type syncReq struct {
		Secrets []*domain.Secret `json:"secrets"`
	}
	type syncResp struct {
		Secrets []*domain.Secret `json:"secrets"`
	}
	resp, err := c.doRequest(ctx, http.MethodPost, "/api/v1/sync", syncReq{Secrets: secrets}, token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp); err != nil {
		return nil, err
	}
	var out syncResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, err
	}
	return out.Secrets, nil
}

// doRequest performs an HTTP request, JSON-encoding body when non-nil
func (c *HTTPClient) doRequest(ctx context.Context, method, path string, body interface{}, token string) (*http.Response, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, r)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return c.client.Do(req)
}

// postAuth is a helper for the register/login endpoints that return a token
func (c *HTTPClient) postAuth(ctx context.Context, path string, payload interface{}, token string) (string, error) {
	resp, err := c.doRequest(ctx, http.MethodPost, path, payload, token)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if err := checkStatus(resp); err != nil {
		return "", err
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.Token, nil
}

// checkStatus returns an error if the HTTP status is not 2xx
func checkStatus(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(body))
}
