package delivery

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/alikhanturusbekov/gophkeeper/internal/domain"
)

// contextKey is a private type used for request-context values
type contextKey string

// ctxUserID is the context key that stores the authenticated user's ID after the bearer token middleware has validated the JWT.
const ctxUserID contextKey = "user_id"

// Handler holds the use-case dependencies for all HTTP handlers
type Handler struct {
	auth    domain.UserUseCase
	authSvc domain.AuthService
	secrets domain.SecretUseCase
	log     *slog.Logger
}

// NewHandler constructs a Handler wiring the provided use-cases
func NewHandler(
	auth domain.UserUseCase,
	authSvc domain.AuthService,
	secrets domain.SecretUseCase,
	log *slog.Logger,
) *Handler {
	return &Handler{auth: auth, authSvc: authSvc, secrets: secrets, log: log}
}

// Router builds and returns the HTTP mux with all routes registered
func (h *Handler) Router() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/register", h.Register)
	mux.HandleFunc("POST /api/v1/login", h.Login)

	mux.Handle("GET /api/v1/secrets", h.auth_(http.HandlerFunc(h.ListSecrets)))
	mux.Handle("POST /api/v1/secrets", h.auth_(http.HandlerFunc(h.CreateSecret)))
	mux.Handle("GET /api/v1/secrets/{id}", h.auth_(http.HandlerFunc(h.GetSecret)))
	mux.Handle("PUT /api/v1/secrets/{id}", h.auth_(http.HandlerFunc(h.UpdateSecret)))
	mux.Handle("DELETE /api/v1/secrets/{id}", h.auth_(http.HandlerFunc(h.DeleteSecret)))
	mux.Handle("POST /api/v1/sync", h.auth_(http.HandlerFunc(h.Sync)))

	return mux
}

// Register creates a new user account and returns a JWT on success
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if req.Login == "" || req.Password == "" {
		h.writeError(w, http.StatusBadRequest, "login and password are required")
		return
	}

	token, err := h.auth.Register(r.Context(), req.Login, req.Password)
	if err == domain.ErrConflict {
		h.writeError(w, http.StatusConflict, "login already taken")
		return
	}
	if err != nil {
		h.log.Error("register", slog.String("err", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.writeJSON(w, http.StatusCreated, TokenResponse{Token: token})
}

// Login authenticates an existing user and returns a JWT
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if !h.decodeJSON(w, r, &req) {
		return
	}

	token, err := h.auth.Login(r.Context(), req.Login, req.Password)
	if err == domain.ErrUnauthorized {
		h.writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	if err != nil {
		h.log.Error("login", slog.String("err", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.writeJSON(w, http.StatusOK, TokenResponse{Token: token})
}

// ListSecrets returns the full list of live secrets for the authenticated user
func (h *Handler) ListSecrets(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	secrets, err := h.secrets.List(r.Context(), userID)
	if err != nil {
		h.log.Error("list secrets", slog.String("err", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if secrets == nil {
		secrets = []*domain.Secret{}
	}
	h.writeJSON(w, http.StatusOK, secrets)
}

// GetSecret returns a single secret by its ID
func (h *Handler) GetSecret(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	s, err := h.secrets.Get(r.Context(), userID, r.PathValue("id"))
	if err == domain.ErrNotFound {
		h.writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		h.log.Error("get secret", slog.String("err", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.writeJSON(w, http.StatusOK, s)
}

// CreateSecret stores a new encrypted secret
func (h *Handler) CreateSecret(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	var req SecretRequest
	if !h.decodeJSON(w, r, &req) {
		return
	}
	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	s := &domain.Secret{
		Name:          req.Name,
		Kind:          req.Kind,
		EncryptedData: req.EncryptedData,
		Metadata:      req.Metadata,
		CreatedAt:     time.Now(),
	}

	created, err := h.secrets.Create(r.Context(), userID, s)
	if err != nil {
		h.log.Error("create secret", slog.String("err", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.writeJSON(w, http.StatusCreated, created)
}

// UpdateSecret replaces the mutable fields of an existing secret
func (h *Handler) UpdateSecret(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	var req SecretRequest
	if !h.decodeJSON(w, r, &req) {
		return
	}

	s := &domain.Secret{
		ID:            r.PathValue("id"),
		Name:          req.Name,
		Kind:          req.Kind,
		EncryptedData: req.EncryptedData,
		Metadata:      req.Metadata,
	}

	updated, err := h.secrets.Update(r.Context(), userID, s)
	if err == domain.ErrNotFound {
		h.writeError(w, http.StatusNotFound, "secret not found")
		return
	}
	if err != nil {
		h.log.Error("update secret", slog.String("err", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.writeJSON(w, http.StatusOK, updated)
}

// DeleteSecret soft-deletes the secret so the tombstone propagates to all clients
func (h *Handler) DeleteSecret(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	if err := h.secrets.Delete(r.Context(), userID, r.PathValue("id")); err != nil {
		if err == domain.ErrNotFound {
			h.writeError(w, http.StatusNotFound, "secret not found")
			return
		}
		h.log.Error("delete secret", slog.String("err", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// Sync accepts the client's current secret list, applies last-write-wins reconciliation, and returns the full list
func (h *Handler) Sync(w http.ResponseWriter, r *http.Request) {
	userID := userIDFromCtx(r.Context())
	var req SyncRequest
	if !h.decodeJSON(w, r, &req) {
		return
	}

	ptrs := make([]*domain.Secret, len(req.Secrets))
	for i := range req.Secrets {
		ptrs[i] = &req.Secrets[i]
	}

	all, err := h.secrets.Sync(r.Context(), userID, ptrs)
	if err != nil {
		h.log.Error("sync", slog.String("err", err.Error()))
		h.writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.writeJSON(w, http.StatusOK, SyncResponse{Secrets: all})
}

// auth_ is the bearer-token authentication middleware. It validates the JWT
// from the Authorization header and injects the user ID into the context.
func (h *Handler) auth_(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		if !strings.HasPrefix(header, "Bearer ") {
			h.writeError(w, http.StatusUnauthorized, "missing bearer token")
			return
		}

		uid, err := h.authSvc.ValidateToken(strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			h.writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}

		ctx := context.WithValue(r.Context(), ctxUserID, uid)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// userIDFromCtx extracts the authenticated user ID from the context
func userIDFromCtx(ctx context.Context) string {
	id, _ := ctx.Value(ctxUserID).(string)
	return id
}

// decodeJSON reads and decodes the request body into dst
func (h *Handler) decodeJSON(w http.ResponseWriter, r *http.Request, dst interface{}) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		h.writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

// writeJSON encodes v as JSON with the given status code
func (h *Handler) writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError sends a JSON error envelope
func (h *Handler) writeError(w http.ResponseWriter, status int, msg string) {
	h.writeJSON(w, status, ErrorResponse{Error: msg})
}
