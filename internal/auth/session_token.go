package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

const sessionTokenBytes = 32 // 256 bits

// NewSessionToken returns a URL-safe opaque token and its SHA-256 digest for storage.
// The digest covers the cookie value (encoded string), matching HashSessionToken.
func NewSessionToken() (rawToken string, tokenHash []byte, err error) {
	buf := make([]byte, sessionTokenBytes)
	if _, err = rand.Read(buf); err != nil {
		return "", nil, fmt.Errorf("generate session token: %w", err)
	}
	rawToken = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(rawToken))
	return rawToken, sum[:], nil
}

// HashSessionToken digests a client-provided raw session token (cookie value).
func HashSessionToken(rawToken string) []byte {
	sum := sha256.Sum256([]byte(rawToken))
	return sum[:]
}
