package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alikhanturusbekov/gophkeeper/internal/client/usecase"
	"github.com/alikhanturusbekov/gophkeeper/internal/domain"
	jwtpkg "github.com/alikhanturusbekov/gophkeeper/pkg/jwt"
	"github.com/alikhanturusbekov/gophkeeper/pkg/version"
)

// ─── stubs ───────────────────────────────────────────────────────────────────

type memLocal struct{ data map[string]*domain.Secret }

func newML() *memLocal { return &memLocal{data: map[string]*domain.Secret{}} }

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
	return nil, nil
}

type stubServer struct{}

func (s *stubServer) Register(_ context.Context, l, p string) (string, error) {
	return jwtpkg.NewManager("secret").Generate("test-uid")
}
func (s *stubServer) Login(_ context.Context, l, p string) (string, error) {
	return jwtpkg.NewManager("secret").Generate("test-uid")
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
	return in, nil
}

// jwtValidator satisfies usecase.AuthValidator.
type jwtValidator struct{ m *jwtpkg.Manager }

func (v *jwtValidator) Validate(tok string) (string, error) { return v.m.Validate(tok) }

// ─── test builder ─────────────────────────────────────────────────────────────

func newTestApp() *App {
	jm := jwtpkg.NewManager("secret")
	uc := usecase.NewSecretUseCase(newML(), &stubServer{}, "master")
	uc.SetAuth(&jwtValidator{m: jm})
	uc.SetSession("test-uid", "tok")
	return NewApp(uc)
}

func runCmd(a *App, args ...string) (string, error) {
	var buf bytes.Buffer
	a.root.SetOut(&buf)
	a.root.SetErr(&buf)
	a.root.SetArgs(args)
	err := a.root.Execute()
	return buf.String(), err
}

// ─── tests ───────────────────────────────────────────────────────────────────

func TestVersionCommand(t *testing.T) {
	version.Version = "1.0.0"
	version.BuildDate = "2024-01-01"
	a := newTestApp()
	out, err := runCmd(a, "version")
	if err != nil {
		t.Fatalf("version: %v", err)
	}
	if !strings.Contains(out, "1.0.0") {
		t.Fatalf("expected version in output: %q", out)
	}
}

func TestAddCredentialCommand(t *testing.T) {
	a := newTestApp()
	_, err := runCmd(a, "add", "credential",
		"--name", "github",
		"--login", "alice",
		"--password", "secret",
		"--meta", "work")
	if err != nil {
		t.Fatalf("add credential: %v", err)
	}
}

func TestAddTextCommand(t *testing.T) {
	a := newTestApp()
	_, err := runCmd(a, "add", "text",
		"--name", "note",
		"--content", "hello world")
	if err != nil {
		t.Fatalf("add text: %v", err)
	}
}

func TestAddCardCommand(t *testing.T) {
	a := newTestApp()
	_, err := runCmd(a, "add", "card",
		"--name", "visa",
		"--number", "4111111111111111",
		"--holder", "Alice",
		"--expiry", "12/28",
		"--cvv", "123")
	if err != nil {
		t.Fatalf("add card: %v", err)
	}
}

func TestListCommand(t *testing.T) {
	a := newTestApp()
	runCmd(a, "add", "text", "--name", "secret1", "--content", "abc")

	out, err := runCmd(a, "list")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(out, "secret1") {
		t.Fatalf("expected secret1 in list output: %q", out)
	}
}

func TestListCommand_Empty(t *testing.T) {
	a := newTestApp()
	out, err := runCmd(a, "list")
	if err != nil {
		t.Fatalf("list empty: %v", err)
	}

	t.Logf("out raw: %q", out)
	t.Logf("out bytes: %v", []byte(out))
	t.Logf("contains: %v", strings.Contains(out, "No secrets"))

	if !strings.Contains(out, "No secrets") {
		t.Fatalf("expected 'No secrets' message: %q", out)
	}
}

func TestDeleteCommand(t *testing.T) {
	a := newTestApp()
	runCmd(a, "add", "text", "--name", "tmp", "--content", "x")

	secrets, _ := a.uc.List(context.Background())
	if len(secrets) == 0 {
		t.Skip("no secrets to delete")
	}
	id := secrets[0].ID

	_, err := runCmd(a, "delete", id)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}

	remaining, _ := a.uc.List(context.Background())
	for _, s := range remaining {
		if s.ID == id {
			t.Fatal("secret still present after delete")
		}
	}
}

func TestSyncCommand(t *testing.T) {
	a := newTestApp()
	_, err := runCmd(a, "sync")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
}
