package auth

import (
	"strings"
	"testing"
)

func TestHashPasswordAndVerify(t *testing.T) {
	const password = "correct-horse-battery"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Fatalf("unexpected hash prefix: %s", hash)
	}
	if err := VerifyPassword(password, hash); err != nil {
		t.Fatalf("VerifyPassword correct: %v", err)
	}
	if err := VerifyPassword("wrong-password-xx", hash); err == nil {
		t.Fatal("expected mismatch for wrong password")
	}
}

func TestHashPasswordDifferentSalts(t *testing.T) {
	const password = "same-password-value"
	h1, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	if h1 == h2 {
		t.Fatal("identical hashes for independent salts")
	}
	if err := VerifyPassword(password, h1); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPassword(password, h2); err != nil {
		t.Fatal(err)
	}
}
