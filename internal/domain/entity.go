package domain

import (
	"errors"
	"time"
)

// ErrNotFound is returned by repository methods when the requested resource does not exist
var ErrNotFound = errors.New("not found")

// ErrConflict is returned when a uniqueness constraint is violated
var ErrConflict = errors.New("conflict")

// ErrUnauthorized is returned when authentication credentials are invalid
var ErrUnauthorized = errors.New("unauthorized")

// ErrForbidden is returned when an authenticated user attempts to access a resource they do not own
var ErrForbidden = errors.New("forbidden")

// SecretKind enumerates every category of private data GophKeeper can store
type SecretKind string

const (
	// KindCredential stores a login / password pair
	KindCredential SecretKind = "credential"

	// KindText stores arbitrary text content
	KindText SecretKind = "text"

	// KindBinary stores arbitrary binary content (files, keys, …)
	KindBinary SecretKind = "binary"

	// KindCard stores bank-card details
	KindCard SecretKind = "card"
)

// User represents a registered GophKeeper account
type User struct {
	// ID is the globally unique identifier, a UUID v4 string
	ID string

	// Login is the unique human-readable account name
	Login string

	// PasswordHash is the bcrypt digest of the user's master password
	PasswordHash string

	// CreatedAt is the wall-clock time the account was first registered
	CreatedAt time.Time
}

// Secret is the central entity that wraps every piece of private data
type Secret struct {
	// ID is the globally unique identifier, a UUID v4 string
	ID string

	// UserID is the owning user's ID
	UserID string

	// Name is a short human-readable label chosen by the user
	Name string

	// Kind describes what the encrypted payload represents
	Kind SecretKind

	// EncryptedData is the AES-256-GCM ciphertext of the marshalled payload
	EncryptedData []byte

	// Metadata is unencrypted, freeform text the user can attach to any secret
	Metadata string

	// Version is a monotonically increasing timestamp (Unix nanoseconds)
	Version int64

	// CreatedAt is the wall-clock time the secret was first created.
	CreatedAt time.Time

	// UpdatedAt is the wall-clock time of the most recent modification.
	UpdatedAt time.Time

	// Deleted marks a soft-deleted secret
	Deleted bool
}

// Credential holds a username / password pair
type Credential struct {
	// Login is the account username or e-mail address
	Login string `json:"login"`

	// Password is the plaintext account password
	Password string `json:"password"`
}

// TextData holds arbitrary text
type TextData struct {
	// Content is the full text payload
	Content string `json:"content"`
}

// BinaryData holds arbitrary binary content
type BinaryData struct {
	// Data is the raw byte payload
	Data []byte `json:"data"`

	// Filename is an optional original file name hint
	Filename string `json:"filename,omitempty"`
}

// CardData holds payment-card details
type CardData struct {
	// Number is the full card number (PAN)
	Number string `json:"number"`

	// Holder is the cardholder name as printed on the card
	Holder string `json:"holder"`

	// Expiry is the card expiry date in "MM/YY" format
	Expiry string `json:"expiry"`

	// CVV is the card verification value
	CVV string `json:"cvv"`
}
