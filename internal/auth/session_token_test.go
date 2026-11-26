package auth

import (
	"encoding/base64"
	"testing"
)

func TestNewSessionTokenUniqueAndHashed(t *testing.T) {
	raw1, hash1, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	raw2, hash2, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if raw1 == raw2 {
		t.Fatal("tokens must be unique")
	}
	if len(hash1) != 32 || len(hash2) != 32 {
		t.Fatalf("hash length want 32, got %d and %d", len(hash1), len(hash2))
	}
	decoded, err := base64.RawURLEncoding.DecodeString(raw1)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) < 32 {
		t.Fatalf("token entropy too small: %d bytes", len(decoded))
	}
	rehash := HashSessionToken(raw1)
	for i := range hash1 {
		if hash1[i] != rehash[i] {
			t.Fatal("HashSessionToken mismatch")
		}
	}
}
