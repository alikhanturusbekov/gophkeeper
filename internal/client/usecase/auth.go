package usecase

// AuthValidator is a minimal interface for validating a JWT on the client side
type AuthValidator interface {
	// Validate parses and verifies tokenStr, returning the embedded userID.
	Validate(tokenStr string) (userID string, err error)
}

// SetAuth stores an AuthValidator so the CLI can extract the userID from a server-issued token during login/register
func (uc *SecretUseCase) SetAuth(a AuthValidator) {
	uc.auth = a
}

// GetAuth returns the AuthValidator, or nil if none was set
func (uc *SecretUseCase) GetAuth() AuthValidator {
	return uc.auth
}

// GetServer returns the underlying ServerClient and true, or nil, false if the use-case was constructed without one
func (uc *SecretUseCase) GetServer() (ServerClient, bool) {
	if uc.server == nil {
		return nil, false
	}
	return uc.server, true
}
