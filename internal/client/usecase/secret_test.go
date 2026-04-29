package usecase

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/alikhanturusbekov/gophkeeper/internal/domain"
)

// ─── stubs ───────────────────────────────────────────────────────────────────

type memLocal struct {
	data map[string]*domain.Secret
}

func newMemLocal() *memLocal {
	return &memLocal{data: map[string]*domain.Secret{}}
}

func (m *memLocal) Save(_ context.Context, s *domain.Secret) error {
	cp := *s
	m.data[s.ID] = &cp
	return nil
}

func (m *memLocal) SoftDelete(_ context.Context, uid, id string) error {
	s, ok := m.data[id]
	if !ok || s.UserID != uid {
		return domain.ErrNotFound
	}
	s.Deleted = true
	return nil
}

func (m *memLocal) FindAllByUser(_ context.Context, uid string) ([]*domain.Secret, error) {
	var out []*domain.Secret
	for _, s := range m.data {
		if s.UserID == uid && !s.Deleted {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out, nil
}

func (m *memLocal) FindByID(_ context.Context, uid, id string) (*domain.Secret, error) {
	s, ok := m.data[id]
	if !ok || s.UserID != uid {
		return nil, domain.ErrNotFound
	}
	cp := *s
	return &cp, nil
}

func (m *memLocal) FindUpdatedAfter(_ context.Context, uid string, after int64) ([]*domain.Secret, error) {
	var out []*domain.Secret
	for _, s := range m.data {
		if s.UserID == uid && s.Version > after {
			cp := *s
			out = append(out, &cp)
		}
	}
	return out, nil
}

type stubServer struct {
	synced []*domain.Secret
}

func (s *stubServer) Register(_ context.Context, _, _ string) (string, error) {
	return "token", nil
}
func (s *stubServer) Login(_ context.Context, _, _ string) (string, error) {
	return "token", nil
}
func (s *stubServer) ListSecrets(_ context.Context, _ string) ([]*domain.Secret, error) {
	return nil, nil
}
func (s *stubServer) CreateSecret(_ context.Context, _ string, sec *domain.Secret) (*domain.Secret, error) {
	cp := *sec
	cp.Version = time.Now().UnixNano()
	return &cp, nil
}
func (s *stubServer) UpdateSecret(_ context.Context, _ string, sec *domain.Secret) (*domain.Secret, error) {
	return sec, nil
}
func (s *stubServer) DeleteSecret(_ context.Context, _, _ string) error { return nil }
func (s *stubServer) Sync(_ context.Context, _ string, in []*domain.Secret) ([]*domain.Secret, error) {
	s.synced = in
	return in, nil
}

// ─── tests ───────────────────────────────────────────────────────────────────

func newUC() *SecretUseCase {
	uc := NewSecretUseCase(newMemLocal(), &stubServer{}, "master-password")
	uc.SetSession("user-1", "tok")
	return uc
}

func TestAddCredential(t *testing.T) {
	uc := newUC()
	s, err := uc.AddCredential(context.Background(), "github", "alice", "secret", "work")
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind != domain.KindCredential {
		t.Fatalf("expected credential kind, got %s", s.Kind)
	}
	if s.UserID != "user-1" {
		t.Fatalf("expected user-1, got %s", s.UserID)
	}

	// Decrypt and verify.
	var cred domain.Credential
	if err := uc.Decrypt(s.EncryptedData, &cred); err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if cred.Login != "alice" || cred.Password != "secret" {
		t.Fatalf("unexpected credential: %+v", cred)
	}
}

func TestAddText(t *testing.T) {
	uc := newUC()
	s, err := uc.AddText(context.Background(), "note", "hello world", "personal")
	if err != nil {
		t.Fatal(err)
	}

	var td domain.TextData
	if err := uc.Decrypt(s.EncryptedData, &td); err != nil {
		t.Fatal(err)
	}
	if td.Content != "hello world" {
		t.Fatalf("expected 'hello world', got %q", td.Content)
	}
}

func TestAddBinary(t *testing.T) {
	uc := newUC()
	data := []byte{0x00, 0xFF, 0xAB}
	s, err := uc.AddBinary(context.Background(), "key.bin", "key.bin", data, "ssh key")
	if err != nil {
		t.Fatal(err)
	}

	var bd domain.BinaryData
	if err := uc.Decrypt(s.EncryptedData, &bd); err != nil {
		t.Fatal(err)
	}
	if string(bd.Data) != string(data) {
		t.Fatalf("binary data mismatch")
	}
}

func TestAddCard(t *testing.T) {
	uc := newUC()
	s, err := uc.AddCard(context.Background(), "visa", "4111111111111111", "Alice", "12/28", "123", "main card")
	if err != nil {
		t.Fatal(err)
	}

	var cd domain.CardData
	if err := uc.Decrypt(s.EncryptedData, &cd); err != nil {
		t.Fatal(err)
	}
	if cd.Number != "4111111111111111" || cd.CVV != "123" {
		t.Fatalf("unexpected card: %+v", cd)
	}
}

func TestList(t *testing.T) {
	uc := newUC()
	uc.AddText(context.Background(), "a", "aaa", "")
	uc.AddText(context.Background(), "b", "bbb", "")

	list, err := uc.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2, got %d", len(list))
	}
}

func TestDelete(t *testing.T) {
	uc := newUC()
	s, _ := uc.AddText(context.Background(), "tmp", "x", "")

	if err := uc.Delete(context.Background(), s.ID); err != nil {
		t.Fatal(err)
	}
	list, _ := uc.List(context.Background())
	if len(list) != 0 {
		t.Fatalf("expected 0 after delete, got %d", len(list))
	}
}

func TestSync(t *testing.T) {
	srv := &stubServer{}
	uc := NewSecretUseCase(newMemLocal(), srv, "pw")
	uc.SetSession("user-1", "tok")
	uc.AddText(context.Background(), "note", "hello", "")

	if err := uc.Sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(srv.synced) != 1 {
		t.Fatalf("expected 1 synced secret, got %d", len(srv.synced))
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	uc := newUC()
	payload := map[string]string{"key": "value"}

	ct, err := uc.Encrypt(payload)
	if err != nil {
		t.Fatal(err)
	}

	var got map[string]string
	if err := uc.Decrypt(ct, &got); err != nil {
		t.Fatal(err)
	}
	b1, _ := json.Marshal(payload)
	b2, _ := json.Marshal(got)
	if string(b1) != string(b2) {
		t.Fatalf("round-trip mismatch: %s vs %s", b1, b2)
	}
}

func TestEncryptDecrypt_WrongKey(t *testing.T) {
	uc1 := NewSecretUseCase(newMemLocal(), &stubServer{}, "key1")
	uc2 := NewSecretUseCase(newMemLocal(), &stubServer{}, "key2")

	ct, _ := uc1.Encrypt("secret")
	var out string
	err := uc2.Decrypt(ct, &out)
	if err == nil {
		t.Fatal("expected decryption failure with wrong key")
	}
}
