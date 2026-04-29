package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/alikhanturusbekov/gophkeeper/internal/domain"
	jwtpkg "github.com/alikhanturusbekov/gophkeeper/pkg/jwt"
)

// ─── in-memory UserRepository stub ──────────────────────────────────────────

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

func (r *memUserRepo) FindByLogin(_ context.Context, login string) (*domain.User, error) {
	u, ok := r.byLogin[login]
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

// ─── tests ───────────────────────────────────────────────────────────────────

func newTestAuthUseCase() *AuthUseCase {
	return NewAuthUseCase(newMemUserRepo(), jwtpkg.NewManager("test-secret"))
}

func TestRegister_Success(t *testing.T) {
	uc := newTestAuthUseCase()
	token, err := uc.Register(context.Background(), "alice", "password")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestRegister_DuplicateLogin(t *testing.T) {
	uc := newTestAuthUseCase()
	uc.Register(context.Background(), "alice", "pw")
	_, err := uc.Register(context.Background(), "alice", "other")
	if err != domain.ErrConflict {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestLogin_Success(t *testing.T) {
	uc := newTestAuthUseCase()
	uc.Register(context.Background(), "bob", "secret")
	token, err := uc.Login(context.Background(), "bob", "secret")
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token")
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	uc := newTestAuthUseCase()
	uc.Register(context.Background(), "bob", "correct")
	_, err := uc.Login(context.Background(), "bob", "wrong")
	if err != domain.ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestLogin_UnknownUser(t *testing.T) {
	uc := newTestAuthUseCase()
	_, err := uc.Login(context.Background(), "nobody", "pw")
	if err != domain.ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestValidateToken_Valid(t *testing.T) {
	uc := newTestAuthUseCase()
	token, _ := uc.Register(context.Background(), "carol", "pw")
	uid, err := uc.ValidateToken(token)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if uid == "" {
		t.Fatal("expected non-empty userID")
	}
}

func TestValidateToken_Invalid(t *testing.T) {
	uc := newTestAuthUseCase()
	_, err := uc.ValidateToken("garbage")
	if err != domain.ErrUnauthorized {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

func TestHashAndCheckPassword(t *testing.T) {
	uc := newTestAuthUseCase()
	hash, err := uc.HashPassword("mypassword")
	if err != nil {
		t.Fatal(err)
	}
	if !uc.CheckPassword(hash, "mypassword") {
		t.Fatal("CheckPassword returned false for correct password")
	}
	if uc.CheckPassword(hash, "wrong") {
		t.Fatal("CheckPassword returned true for wrong password")
	}
}

// ─── in-memory SecretRepository stub ─────────────────────────────────────────

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

func (r *memSecretRepo) SoftDelete(_ context.Context, userID, id string) error {
	s, ok := r.data[id]
	if !ok || s.UserID != userID {
		return domain.ErrNotFound
	}
	s.Deleted = true
	return nil
}

func (r *memSecretRepo) FindAllByUser(_ context.Context, userID string) ([]*domain.Secret, error) {
	var out []*domain.Secret
	for _, s := range r.data {
		if s.UserID == userID && !s.Deleted {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (r *memSecretRepo) FindByID(_ context.Context, userID, id string) (*domain.Secret, error) {
	s, ok := r.data[id]
	if !ok || s.UserID != userID {
		return nil, domain.ErrNotFound
	}
	cp := *s
	return &cp, nil
}

func (r *memSecretRepo) FindUpdatedAfter(_ context.Context, userID string, after int64) ([]*domain.Secret, error) {
	var out []*domain.Secret
	for _, s := range r.data {
		if s.UserID == userID && s.Version > after {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out, nil
}

// ─── secret use-case tests ───────────────────────────────────────────────────

func TestSecretCreate(t *testing.T) {
	uc := NewSecretUseCase(newMemSecretRepo())
	s := &domain.Secret{Name: "github", Kind: domain.KindCredential, EncryptedData: []byte("enc")}
	got, err := uc.Create(context.Background(), "user-1", s)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID == "" || got.UserID != "user-1" {
		t.Fatalf("unexpected secret: %+v", got)
	}
}

func TestSecretList(t *testing.T) {
	uc := NewSecretUseCase(newMemSecretRepo())
	uc.Create(context.Background(), "u1", &domain.Secret{Name: "a", Kind: domain.KindText, EncryptedData: []byte("x")})
	uc.Create(context.Background(), "u1", &domain.Secret{Name: "b", Kind: domain.KindText, EncryptedData: []byte("y")})
	uc.Create(context.Background(), "u2", &domain.Secret{Name: "c", Kind: domain.KindText, EncryptedData: []byte("z")})

	list, err := uc.List(context.Background(), "u1")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 secrets for u1, got %d", len(list))
	}
}

func TestSecretDelete(t *testing.T) {
	uc := NewSecretUseCase(newMemSecretRepo())
	s, _ := uc.Create(context.Background(), "u1", &domain.Secret{Name: "x", Kind: domain.KindText, EncryptedData: []byte("e")})

	if err := uc.Delete(context.Background(), "u1", s.ID); err != nil {
		t.Fatal(err)
	}
	list, _ := uc.List(context.Background(), "u1")
	if len(list) != 0 {
		t.Fatalf("expected 0 secrets after delete, got %d", len(list))
	}
}

func TestSecretUpdate(t *testing.T) {
	uc := NewSecretUseCase(newMemSecretRepo())
	s, _ := uc.Create(context.Background(), "u1", &domain.Secret{Name: "old", Kind: domain.KindText, EncryptedData: []byte("e")})

	s.Name = "new"
	updated, err := uc.Update(context.Background(), "u1", s)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "new" {
		t.Fatalf("expected name 'new', got %q", updated.Name)
	}
}

func TestSecretSync_LastWriteWins(t *testing.T) {
	repo := newMemSecretRepo()
	uc := NewSecretUseCase(repo)

	srv, _ := uc.Create(context.Background(), "u1", &domain.Secret{Name: "srv", Kind: domain.KindText, EncryptedData: []byte("server")})

	// Client has a newer version of the same secret.
	clientVersion := srv.Version + 1
	clientSecret := &domain.Secret{
		ID:            srv.ID,
		UserID:        "u1",
		Name:          "client-updated",
		Kind:          domain.KindText,
		EncryptedData: []byte("client"),
		Version:       clientVersion,
		CreatedAt:     srv.CreatedAt,
	}

	all, err := uc.Sync(context.Background(), "u1", []*domain.Secret{clientSecret})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 {
		t.Fatalf("expected 1 secret, got %d", len(all))
	}
	if all[0].Name != "client-updated" {
		t.Fatalf("expected client version to win, got name=%q", all[0].Name)
	}
}
