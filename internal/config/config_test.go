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
	if cfg.AttackThreshold != 0.60 {
		t.Fatalf("default ATTACK_THRESHOLD = %v, want 0.60", cfg.AttackThreshold)
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
