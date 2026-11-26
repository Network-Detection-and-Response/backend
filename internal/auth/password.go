package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// OWASP recommended minimum for Argon2id (as of 2024 guidance used by this project).
const (
	argonTime    = 2
	argonMemory  = 19 * 1024 // KiB = 19 MiB
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16
)

var (
	ErrInvalidPasswordHash = errors.New("invalid password hash")
	ErrPasswordMismatch    = errors.New("password mismatch")
)

// HashPassword returns a PHC-encoded Argon2id hash with a fresh random salt.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return encodePHC(salt, hash, argonTime, argonMemory, argonThreads), nil
}

// VerifyPassword compares password against a PHC Argon2id hash using constant-time compare.
func VerifyPassword(password, encodedHash string) error {
	salt, hash, timeCost, memory, threads, err := decodePHC(encodedHash)
	if err != nil {
		return err
	}
	computed := argon2.IDKey([]byte(password), salt, timeCost, memory, threads, uint32(len(hash)))
	if subtle.ConstantTimeCompare(computed, hash) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

func encodePHC(salt, hash []byte, timeCost, memory uint32, threads uint8) string {
	return fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		memory,
		timeCost,
		threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)
}

func decodePHC(encoded string) (salt, hash []byte, timeCost, memory uint32, threads uint8, err error) {
	parts := strings.Split(encoded, "$")
	// "", "argon2id", "v=19", "m=...,t=...,p=...", salt, hash
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, 0, 0, 0, ErrInvalidPasswordHash
	}
	var version int
	if _, err = fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return nil, nil, 0, 0, 0, ErrInvalidPasswordHash
	}
	var p int
	if _, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &timeCost, &p); err != nil || p < 1 || p > 255 {
		return nil, nil, 0, 0, 0, ErrInvalidPasswordHash
	}
	threads = uint8(p)
	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) < argonSaltLen {
		return nil, nil, 0, 0, 0, ErrInvalidPasswordHash
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(hash) == 0 {
		return nil, nil, 0, 0, 0, ErrInvalidPasswordHash
	}
	return salt, hash, timeCost, memory, threads, nil
}
