package config

import (
	"strings"
	"testing"
)

func TestLoadMissingRequired(t *testing.T) {
	t.Setenv("DATABASE_URL", "")
	t.Setenv("SENSOR_API_KEY", "")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for missing required config")
	}
	msg := err.Error()
	if !strings.Contains(msg, "DATABASE_URL") || !strings.Contains(msg, "SENSOR_API_KEY") {
		t.Fatalf("error should mention missing keys, got: %s", msg)
	}
	if strings.Contains(strings.ToLower(msg), "password") {
		t.Fatalf("error must not leak secrets: %s", msg)
	}
}

func TestLoadOptionalServicesDoNotBlock(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://ndr:ndr@localhost:5432/ndr?sslmode=disable")
	t.Setenv("SENSOR_API_KEY", "test-sensor-key")
	t.Setenv("TELEGRAM_BOT_TOKEN", "")
	t.Setenv("TELEGRAM_CHAT_ID", "")
	t.Setenv("LLM_API_KEY", "")
	t.Setenv("ML_SERVICE_URL", "")
	t.Setenv("ML_ENABLED", "")
	t.Setenv("ATTACK_THRESHOLD", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.TelegramEnabled() {
		t.Fatal("Telegram should be disabled when unset")
	}
	if cfg.LLMEnabled() {
		t.Fatal("LLM should be disabled when unset")
	}
	if cfg.MLConfigured() {
		t.Fatal("ML should be disabled when ML_SERVICE_URL is empty")
	}
	if cfg.AttackThreshold != 0.60 {
		t.Fatalf("default ATTACK_THRESHOLD = %v, want 0.60", cfg.AttackThreshold)
	}
	if cfg.PersistMaxAttempts != 3 {
		t.Fatalf("default PERSIST_MAX_ATTEMPTS = %d, want 3", cfg.PersistMaxAttempts)
	}
	if cfg.PersistRetryBaseDelay.String() != "100ms" {
		t.Fatalf("default PERSIST_RETRY_BASE_DELAY = %s, want 100ms", cfg.PersistRetryBaseDelay)
	}
	origins := strings.Join(cfg.CORSAllowedOrigins, ",")
	if !strings.Contains(origins, "127.0.0.1:5173") {
		t.Fatalf("default CORS should include 127.0.0.1:5173, got %v", cfg.CORSAllowedOrigins)
	}
}

func TestLoadMLEnabledFalseDisablesEvenWithURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://ndr:ndr@localhost:5432/ndr?sslmode=disable")
	t.Setenv("SENSOR_API_KEY", "test-sensor-key")
	t.Setenv("ML_SERVICE_URL", "http://ml:8000")
	t.Setenv("ML_ENABLED", "false")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if cfg.MLConfigured() {
		t.Fatal("ML_ENABLED=false must disable ML even when URL is set")
	}
	if cfg.MLServiceURL != "" {
		t.Fatalf("disabled ML should clear MLServiceURL, got %q", cfg.MLServiceURL)
	}
}

func TestLoadMLEnabledWithURL(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://ndr:ndr@localhost:5432/ndr?sslmode=disable")
	t.Setenv("SENSOR_API_KEY", "test-sensor-key")
	t.Setenv("ML_SERVICE_URL", "http://ml:8000")
	t.Setenv("ML_ENABLED", "true")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}
	if !cfg.MLConfigured() {
		t.Fatal("ML should be configured when URL set and ML_ENABLED=true")
	}
	if cfg.MLServiceURL != "http://ml:8000" {
		t.Fatalf("MLServiceURL = %q, want http://ml:8000", cfg.MLServiceURL)
	}
}

func TestLoadRejectsInvalidThreshold(t *testing.T) {
	t.Setenv("DATABASE_URL", "postgres://ndr:ndr@localhost:5432/ndr?sslmode=disable")
	t.Setenv("SENSOR_API_KEY", "test-sensor-key")
	t.Setenv("ATTACK_THRESHOLD", "1.5")

	_, err := Load()
	if err == nil {
		t.Fatal("expected error for invalid ATTACK_THRESHOLD")
	}
}
