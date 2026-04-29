package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKey_Length(t *testing.T) {
	key := DeriveKey("password")
	if len(key) != 32 {
		t.Fatalf("expected 32-byte key, got %d", len(key))
	}
}

func TestDeriveKey_Deterministic(t *testing.T) {
	if !bytes.Equal(DeriveKey("pw"), DeriveKey("pw")) {
		t.Fatal("DeriveKey must be deterministic for the same input")
	}
}

func TestDeriveKey_DifferentPasswords(t *testing.T) {
	if bytes.Equal(DeriveKey("a"), DeriveKey("b")) {
		t.Fatal("different passwords must produce different keys")
	}
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	key := DeriveKey("secret")
	plain := []byte("hello gophkeeper")

	ct, err := Encrypt(key, plain)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(key, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plain) {
		t.Fatalf("round-trip mismatch: want %q got %q", plain, got)
	}
}

func TestEncrypt_ProducesNonDeterministicOutput(t *testing.T) {
	key := DeriveKey("secret")
	c1, _ := Encrypt(key, []byte("data"))
	c2, _ := Encrypt(key, []byte("data"))
	if bytes.Equal(c1, c2) {
		t.Fatal("each Encrypt call must use a fresh random nonce")
	}
}

func TestDecrypt_WrongKey(t *testing.T) {
	ct, _ := Encrypt(DeriveKey("right"), []byte("payload"))
	_, err := Decrypt(DeriveKey("wrong"), ct)
	if err != ErrInvalidCiphertext {
		t.Fatalf("expected ErrInvalidCiphertext, got %v", err)
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	key := DeriveKey("k")
	ct, _ := Encrypt(key, []byte("data"))
	ct[len(ct)-1] ^= 0xFF
	_, err := Decrypt(key, ct)
	if err != ErrInvalidCiphertext {
		t.Fatalf("expected ErrInvalidCiphertext for tampered data, got %v", err)
	}
}

func TestDecrypt_TooShort(t *testing.T) {
	_, err := Decrypt(DeriveKey("k"), []byte("short"))
	if err != ErrInvalidCiphertext {
		t.Fatalf("expected ErrInvalidCiphertext for too-short input, got %v", err)
	}
}

func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	key := DeriveKey("k")
	ct, err := Encrypt(key, []byte{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(key, ct)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %v", got)
	}
}
