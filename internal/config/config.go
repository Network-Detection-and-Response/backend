package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds runtime settings loaded from the environment.
type Config struct {
	HTTPAddr              string
	ReadTimeout           time.Duration
	WriteTimeout          time.Duration
	IdleTimeout           time.Duration
	ShutdownTimeout       time.Duration
	DatabaseURL           string
	SensorAPIKey          string
	MLServiceURL          string
	MLTimeout             time.Duration
	AttackThreshold       float64
	DDoSCriticalThreshold float64
	CORSAllowedOrigins    []string
	MaxBodyBytes          int64
	MaxFlowsPerBatch      int
	QueueCapacity         int
	WorkerCount           int
	TelegramBotToken      string
	TelegramChatID        string
	LLMAPIKey             string
	LLMBaseURL            string
	AttackWindow          time.Duration
	LogLevel              string
}

// Load reads configuration from environment variables.
// Optional .env in the working directory is loaded first if present (does not override existing env).
func Load() (Config, error) {
	_ = loadDotEnv(".env")

	cfg := Config{
		HTTPAddr:              getEnv("HTTP_ADDR", ":8080"),
		ReadTimeout:           getDuration("HTTP_READ_TIMEOUT", 10*time.Second),
		WriteTimeout:          getDuration("HTTP_WRITE_TIMEOUT", 30*time.Second),
		IdleTimeout:           getDuration("HTTP_IDLE_TIMEOUT", 60*time.Second),
		ShutdownTimeout:       getDuration("SHUTDOWN_TIMEOUT", 15*time.Second),
		DatabaseURL:           strings.TrimSpace(os.Getenv("DATABASE_URL")),
		SensorAPIKey:          os.Getenv("SENSOR_API_KEY"),
		MLServiceURL:          strings.TrimRight(strings.TrimSpace(os.Getenv("ML_SERVICE_URL")), "/"),
		MLTimeout:             getDuration("ML_TIMEOUT", 5*time.Second),
		AttackThreshold:       getFloat("ATTACK_THRESHOLD", 0.60),
		DDoSCriticalThreshold: getFloat("DDOS_CRITICAL_THRESHOLD", 0.85),
		CORSAllowedOrigins:    splitCSV(getEnv("CORS_ALLOWED_ORIGINS", "http://localhost:5173,http://localhost:3000")),
		MaxBodyBytes:          getInt64("MAX_BODY_BYTES", 1<<20), // 1 MiB
		MaxFlowsPerBatch:      getInt("MAX_FLOWS_PER_BATCH", 500),
		QueueCapacity:         getInt("QUEUE_CAPACITY", 100),
		WorkerCount:           getInt("WORKER_COUNT", 2),
		TelegramBotToken:      os.Getenv("TELEGRAM_BOT_TOKEN"),
		TelegramChatID:        os.Getenv("TELEGRAM_CHAT_ID"),
		LLMAPIKey:             os.Getenv("LLM_API_KEY"),
		LLMBaseURL:            strings.TrimSpace(os.Getenv("LLM_BASE_URL")),
		AttackWindow:          getDuration("ATTACK_WINDOW", 15*time.Minute),
		LogLevel:              getEnv("LOG_LEVEL", "info"),
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) validate() error {
	var missing []string
	if c.DatabaseURL == "" {
		missing = append(missing, "DATABASE_URL")
	}
	if c.SensorAPIKey == "" {
		missing = append(missing, "SENSOR_API_KEY")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}

	if c.AttackThreshold < 0 || c.AttackThreshold > 1 {
		return fmt.Errorf("ATTACK_THRESHOLD must be between 0 and 1")
	}
	if c.DDoSCriticalThreshold < 0 || c.DDoSCriticalThreshold > 1 {
		return fmt.Errorf("DDOS_CRITICAL_THRESHOLD must be between 0 and 1")
	}
	if c.ReadTimeout <= 0 || c.WriteTimeout <= 0 || c.IdleTimeout <= 0 {
		return fmt.Errorf("HTTP timeouts must be positive")
	}
	if c.MLTimeout <= 0 {
		return fmt.Errorf("ML_TIMEOUT must be positive")
	}
	if c.MaxBodyBytes <= 0 {
		return fmt.Errorf("MAX_BODY_BYTES must be positive")
	}
	if c.MaxFlowsPerBatch <= 0 {
		return fmt.Errorf("MAX_FLOWS_PER_BATCH must be positive")
	}
	if c.QueueCapacity <= 0 {
		return fmt.Errorf("QUEUE_CAPACITY must be positive")
	}
	if c.WorkerCount <= 0 {
		return fmt.Errorf("WORKER_COUNT must be positive")
	}
	return nil
}

// TelegramEnabled reports whether Telegram notifications are configured.
func (c Config) TelegramEnabled() bool {
	return c.TelegramBotToken != "" && c.TelegramChatID != ""
}

// LLMEnabled reports whether an optional LLM API is configured.
func (c Config) LLMEnabled() bool {
	return c.LLMAPIKey != ""
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return v
	}
	return fallback
}

func getDuration(key string, fallback time.Duration) time.Duration {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func getFloat(key string, fallback float64) float64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	f, err := strconv.ParseFloat(v, 64)
	if err != nil {
		return fallback
	}
	return f
}

func getInt(key string, fallback int) int {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return fallback
	}
	return n
}

func getInt64(key string, fallback int64) int64 {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return fallback
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}
