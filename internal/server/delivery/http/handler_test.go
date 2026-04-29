package delivery

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alikhanturusbekov/gophkeeper/internal/domain"
	"github.com/alikhanturusbekov/gophkeeper/internal/server/usecase"
	jwtpkg "github.com/alikhanturusbekov/gophkeeper/pkg/jwt"
	"github.com/google/uuid"
)

// ─── in-memory repository stubs ──────────────────────────────────────────────

type memUserRepo struct {
	byLogin map[string]*domain.User
	byID    map[string]*domain.User
}

func newMemUserRepo() *memUserRepo {
	return &memUserRepo{byLogin: map[string]*domain.User{}, byID: map[string]*domain.User{}}
}

func (r *memUserRepo) Save(_ context.Context, u *domain.User) error {
	if _, ok := r.byLogin[u.Login]; ok {
		return domain.ErrConflict
	}
	cp := *u
	r.byLogin[u.Login] = &cp
	r.byID[u.ID] = &cp
	return nil
}

func (r *memUserRepo) FindByLogin(_ context.Context, l string) (*domain.User, error) {
	u, ok := r.byLogin[l]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (r *memUserRepo) FindByID(_ context.Context, id string) (*domain.User, error) {
	u, ok := r.byID[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

type memSecretRepo struct {
	data map[string]*domain.Secret
}

func newMemSecretRepo() *memSecretRepo {
	return &memSecretRepo{data: map[string]*domain.Secret{}}
}

func (r *memSecretRepo) Save(_ context.Context, s *domain.Secret) error {
	cp := *s
	cp.Version = time.Now().UnixNano()
	r.data[s.ID] = &cp
	s.Version = cp.Version
	return nil
}

func (r *memSecretRepo) SoftDelete(_ context.Context, uid, id string) error {
	s, ok := r.data[id]
	if !ok || s.UserID != uid {
		return domain.ErrNotFound
	}
	s.Deleted = true
	return nil
}

func (r *memSecretRepo) FindAllByUser(_ context.Context, uid string) ([]*domain.Secret, error) {
	var out []*domain.Secret
	for _, s := range r.data {
		if s.UserID == uid && !s.Deleted {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *memSecretRepo) FindByID(_ context.Context, uid, id string) (*domain.Secret, error) {
	s, ok := r.data[id]
	if !ok || s.UserID != uid {
		return nil, domain.ErrNotFound
	}
	cp := *s
	return &cp, nil
}

func (r *memSecretRepo) FindUpdatedAfter(_ context.Context, uid string, after int64) ([]*domain.Secret, error) {
	var out []*domain.Secret
	for _, s := range r.data {
		if s.UserID == uid && s.Version > after {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out, nil
}

// ─── test builder ─────────────────────────────────────────────────────────────

func newTestRouter(t *testing.T) http.Handler {
	t.Helper()
	jm := jwtpkg.NewManager("test-secret")
	authUC := usecase.NewAuthUseCase(newMemUserRepo(), jm)
	secretUC := usecase.NewSecretUseCase(newMemSecretRepo())
	nop := slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewHandler(authUC, authUC, secretUC, nop).Router()
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func doReq(t *testing.T, h http.Handler, method, path string, body interface{}, token string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func mustRegister(t *testing.T, h http.Handler, login, pass string) string {
	t.Helper()
	rr := doReq(t, h, http.MethodPost, "/api/v1/register",
		RegisterRequest{Login: login, Password: pass}, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("register: expected 201, got %d: %s", rr.Code, rr.Body)
	}
	var resp TokenResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	return resp.Token
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestHandler_Register_Success(t *testing.T) {
	h := newTestRouter(t)
	rr := doReq(t, h, http.MethodPost, "/api/v1/register",
		RegisterRequest{Login: "alice", Password: "pw"}, "")
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rr.Code, rr.Body)
	}
	var resp TokenResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Token == "" {
		t.Fatal("expected token in response")
	}
}

func TestHandler_Register_MissingFields(t *testing.T) {
	h := newTestRouter(t)
	rr := doReq(t, h, http.MethodPost, "/api/v1/register",
		RegisterRequest{Login: ""}, "")
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestHandler_Register_Duplicate(t *testing.T) {
	h := newTestRouter(t)
	mustRegister(t, h, "alice", "pw")
	rr := doReq(t, h, http.MethodPost, "/api/v1/register",
		RegisterRequest{Login: "alice", Password: "pw"}, "")
	if rr.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", rr.Code)
	}
}

func TestHandler_Login_Success(t *testing.T) {
	h := newTestRouter(t)
	mustRegister(t, h, "bob", "secret")
	rr := doReq(t, h, http.MethodPost, "/api/v1/login",
		LoginRequest{Login: "bob", Password: "secret"}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body)
	}
}

func TestHandler_Login_BadCredentials(t *testing.T) {
	h := newTestRouter(t)
	mustRegister(t, h, "bob", "correct")
	rr := doReq(t, h, http.MethodPost, "/api/v1/login",
		LoginRequest{Login: "bob", Password: "wrong"}, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandler_Secrets_RequiresAuth(t *testing.T) {
	h := newTestRouter(t)
	rr := doReq(t, h, http.MethodGet, "/api/v1/secrets", nil, "")
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestHandler_CreateAndListSecrets(t *testing.T) {
	h := newTestRouter(t)
	tok := mustRegister(t, h, "carol", "pw")

	rr := doReq(t, h, http.MethodPost, "/api/v1/secrets", SecretRequest{
		Name: "github", Kind: domain.KindCredential, EncryptedData: []byte("enc"),
	}, tok)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d: %s", rr.Code, rr.Body)
	}

	rr = doReq(t, h, http.MethodGet, "/api/v1/secrets", nil, tok)
	if rr.Code != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", rr.Code)
	}
	var list []*domain.Secret
	json.NewDecoder(rr.Body).Decode(&list)
	if len(list) != 1 || list[0].Name != "github" {
		t.Fatalf("unexpected list: %+v", list)
	}
}

func TestHandler_UpdateSecret(t *testing.T) {
	h := newTestRouter(t)
	tok := mustRegister(t, h, "dave", "pw")

	rr := doReq(t, h, http.MethodPost, "/api/v1/secrets", SecretRequest{
		Name: "old-name", Kind: domain.KindText, EncryptedData: []byte("e"),
	}, tok)
	var sec domain.Secret
	json.NewDecoder(rr.Body).Decode(&sec)

	rr = doReq(t, h, http.MethodPut, "/api/v1/secrets/"+sec.ID, SecretRequest{
		Name: "new-name", Kind: domain.KindText, EncryptedData: []byte("e2"),
	}, tok)
	if rr.Code != http.StatusOK {
		t.Fatalf("update: expected 200, got %d: %s", rr.Code, rr.Body)
	}
	var updated domain.Secret
	json.NewDecoder(rr.Body).Decode(&updated)
	if updated.Name != "new-name" {
		t.Fatalf("expected name 'new-name', got %q", updated.Name)
	}
}

func TestHandler_DeleteSecret(t *testing.T) {
	h := newTestRouter(t)
	tok := mustRegister(t, h, "eve", "pw")

	rr := doReq(t, h, http.MethodPost, "/api/v1/secrets", SecretRequest{
		Name: "bye", Kind: domain.KindBinary, EncryptedData: []byte("e"),
	}, tok)
	var sec domain.Secret
	json.NewDecoder(rr.Body).Decode(&sec)

	rr = doReq(t, h, http.MethodDelete, "/api/v1/secrets/"+sec.ID, nil, tok)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("delete: expected 204, got %d", rr.Code)
	}

	rr = doReq(t, h, http.MethodGet, "/api/v1/secrets", nil, tok)
	var list []*domain.Secret
	json.NewDecoder(rr.Body).Decode(&list)
	if len(list) != 0 {
		t.Fatalf("expected 0 after delete, got %d", len(list))
	}
}

func TestHandler_Sync(t *testing.T) {
	h := newTestRouter(t)
	tok := mustRegister(t, h, "frank", "pw")

	rr := doReq(t, h, http.MethodPost, "/api/v1/sync", SyncRequest{
		Secrets: []domain.Secret{
			{ID: newID(), Name: "note", Kind: domain.KindText, EncryptedData: []byte("e"), CreatedAt: time.Now()},
		},
	}, tok)
	if rr.Code != http.StatusOK {
		t.Fatalf("sync: expected 200, got %d: %s", rr.Code, rr.Body)
	}
	var resp SyncResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if len(resp.Secrets) != 1 {
		t.Fatalf("expected 1 in sync response, got %d", len(resp.Secrets))
	}
}

func TestHandler_GetSecret(t *testing.T) {
	h := newTestRouter(t)
	tok := mustRegister(t, h, "grace", "pw")

	rr := doReq(t, h, http.MethodPost, "/api/v1/secrets", SecretRequest{
		Name: "my-card", Kind: domain.KindCard, EncryptedData: []byte("e"),
	}, tok)
	var sec domain.Secret
	json.NewDecoder(rr.Body).Decode(&sec)

	rr = doReq(t, h, http.MethodGet, "/api/v1/secrets/"+sec.ID, nil, tok)
	if rr.Code != http.StatusOK {
		t.Fatalf("get: expected 200, got %d: %s", rr.Code, rr.Body)
	}
	var got domain.Secret
	json.NewDecoder(rr.Body).Decode(&got)
	if got.ID != sec.ID {
		t.Fatalf("got wrong secret: %s", got.ID)
	}
}

// newID generates a fresh UUID string for use in tests.
func newID() string { return uuid.NewString() }
