package jwt

import (
	"testing"
	"time"
)

func TestGenerate_Validate_RoundTrip(t *testing.T) {
	m := NewManager("supersecret")
	token, err := m.Generate("user-42")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	uid, err := m.Validate(token)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if uid != "user-42" {
		t.Fatalf("expected user-42, got %s", uid)
	}
}

func TestValidate_WrongSecret(t *testing.T) {
	m1 := NewManager("secret1")
	m2 := NewManager("secret2")
	tok, _ := m1.Generate("u1")
	_, err := m2.Validate(tok)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestValidate_Malformed(t *testing.T) {
	m := NewManager("s")
	_, err := m.Validate("not.a.jwt")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken, got %v", err)
	}
}

func TestValidate_Expired(t *testing.T) {
	m := NewManagerWithTTL("secret", -time.Second)
	tok, _ := m.Generate("u")
	_, err := m.Validate(tok)
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for expired token, got %v", err)
	}
}

func TestValidate_Empty(t *testing.T) {
	m := NewManager("s")
	_, err := m.Validate("")
	if err != ErrInvalidToken {
		t.Fatalf("expected ErrInvalidToken for empty token, got %v", err)
	}
}
