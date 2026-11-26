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
	MLEnabled             bool
	MLServiceURL          string
	MLTimeout             time.Duration
	AttackThreshold       float64
	DDoSCriticalThreshold float64
	CORSAllowedOrigins    []string
	MaxBodyBytes          int64
	MaxFlowsPerBatch      int
	QueueCapacity         int
	WorkerCount           int
	PersistMaxAttempts    int
	PersistRetryBaseDelay time.Duration
	TelegramBotToken      string
	TelegramChatID        string
	TelegramAPIBaseURL    string
	TelegramQueueCapacity int
	TelegramMaxAttempts   int
	TelegramRetryBase     time.Duration
	TelegramHTTPTimeout   time.Duration
	TelegramBotURL        string
	LLMAPIKey             string
	LLMBaseURL            string
	AttackWindow          time.Duration
	WSClientBuffer        int
	WSWriteWait           time.Duration
	WSPongWait            time.Duration
	WSPingPeriod          time.Duration
	LogLevel              string
	// Auth / session cookies
	SessionTTL            time.Duration
	AuthCookieSecure      bool
	AuthCookieName        string
	AuthRateLimitRegister int
	AuthRateLimitLogin    int
	AuthRateLimitWindow   time.Duration
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
		CORSAllowedOrigins: splitCSV(getEnv(
			"CORS_ALLOWED_ORIGINS",
			"http://localhost:5173,http://127.0.0.1:5173,http://localhost:3000,http://127.0.0.1:3000",
		)),
		MaxBodyBytes:          getInt64("MAX_BODY_BYTES", 1<<20), // 1 MiB
		MaxFlowsPerBatch:      getInt("MAX_FLOWS_PER_BATCH", 500),
		QueueCapacity:         getInt("QUEUE_CAPACITY", 100),
		WorkerCount:           getInt("WORKER_COUNT", 2),
		PersistMaxAttempts:    getInt("PERSIST_MAX_ATTEMPTS", 3),
		PersistRetryBaseDelay: getDuration("PERSIST_RETRY_BASE_DELAY", 100*time.Millisecond),
		TelegramBotToken:      os.Getenv("TELEGRAM_BOT_TOKEN"),
		TelegramChatID:        os.Getenv("TELEGRAM_CHAT_ID"),
		TelegramAPIBaseURL:    strings.TrimRight(strings.TrimSpace(getEnv("TELEGRAM_API_BASE_URL", "https://api.telegram.org")), "/"),
		TelegramQueueCapacity: getInt("TELEGRAM_QUEUE_CAPACITY", 100),
		TelegramMaxAttempts:   getInt("TELEGRAM_MAX_ATTEMPTS", 3),
		TelegramRetryBase:     getDuration("TELEGRAM_RETRY_BASE_DELAY", 500*time.Millisecond),
		TelegramHTTPTimeout:   getDuration("TELEGRAM_HTTP_TIMEOUT", 10*time.Second),
		TelegramBotURL:        strings.TrimSpace(os.Getenv("TELEGRAM_BOT_URL")),
		LLMAPIKey:             os.Getenv("LLM_API_KEY"),
		LLMBaseURL:            strings.TrimSpace(os.Getenv("LLM_BASE_URL")),
		AttackWindow:          getDuration("ATTACK_WINDOW", 15*time.Minute),
		WSClientBuffer:        getInt("WS_CLIENT_BUFFER", 64),
		WSWriteWait:           getDuration("WS_WRITE_WAIT", 10*time.Second),
		WSPongWait:            getDuration("WS_PONG_WAIT", 60*time.Second),
		WSPingPeriod:          getDuration("WS_PING_PERIOD", 54*time.Second),
		LogLevel:              getEnv("LOG_LEVEL", "info"),
		SessionTTL:            getDuration("SESSION_TTL", 7*24*time.Hour),
		AuthRateLimitRegister: getInt("AUTH_RATE_LIMIT_REGISTER", 5),
		AuthRateLimitLogin:    getInt("AUTH_RATE_LIMIT_LOGIN", 10),
		AuthRateLimitWindow:   getDuration("AUTH_RATE_LIMIT_WINDOW", 15*time.Minute),
	}

	// AUTH_COOKIE_SECURE defaults to true (production-safe). Local HTTP must set AUTH_COOKIE_SECURE=false explicitly.
	cfg.AuthCookieSecure = getBool("AUTH_COOKIE_SECURE", true)
	cfg.AuthCookieName = resolveAuthCookieName(cfg.AuthCookieSecure, strings.TrimSpace(os.Getenv("AUTH_COOKIE_NAME")))

	// ML is optional. ML_ENABLED=false forces disable even if ML_SERVICE_URL is set.
	// When ML_ENABLED is unset, ML is on only if ML_SERVICE_URL is non-empty.
	cfg.MLEnabled = resolveMLEnabled(cfg.MLServiceURL)
	if !cfg.MLEnabled {
		cfg.MLServiceURL = ""
	}

	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// resolveMLEnabled decides whether the ML client should be active.
// Explicit ML_ENABLED=false/0/no/off disables ML; true/1/yes/on enables only with a URL.
// Unset ML_ENABLED follows "URL present ⇒ enabled".
func resolveMLEnabled(mlURL string) bool {
	raw, set := os.LookupEnv("ML_ENABLED")
	if !set || strings.TrimSpace(raw) == "" {
		return mlURL != ""
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "0", "false", "no", "off":
		return false
	case "1", "true", "yes", "on":
		return mlURL != ""
	default:
		return mlURL != ""
	}
}

// MLConfigured reports whether ML scoring is active for this process.
func (c Config) MLConfigured() bool {
	return c.MLEnabled && c.MLServiceURL != ""
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
	if c.PersistMaxAttempts <= 0 {
		return fmt.Errorf("PERSIST_MAX_ATTEMPTS must be positive")
	}
	if c.PersistRetryBaseDelay <= 0 {
		return fmt.Errorf("PERSIST_RETRY_BASE_DELAY must be positive")
	}
	if c.TelegramQueueCapacity <= 0 {
		return fmt.Errorf("TELEGRAM_QUEUE_CAPACITY must be positive")
	}
	if c.TelegramMaxAttempts <= 0 {
		return fmt.Errorf("TELEGRAM_MAX_ATTEMPTS must be positive")
	}
	if c.TelegramRetryBase <= 0 {
		return fmt.Errorf("TELEGRAM_RETRY_BASE_DELAY must be positive")
	}
	if c.TelegramHTTPTimeout <= 0 {
		return fmt.Errorf("TELEGRAM_HTTP_TIMEOUT must be positive")
	}
	if c.WSClientBuffer <= 0 {
		return fmt.Errorf("WS_CLIENT_BUFFER must be positive")
	}
	if c.WSWriteWait <= 0 {
		return fmt.Errorf("WS_WRITE_WAIT must be positive")
	}
	if c.WSPongWait <= 0 {
		return fmt.Errorf("WS_PONG_WAIT must be positive")
	}
	if c.WSPingPeriod <= 0 {
		return fmt.Errorf("WS_PING_PERIOD must be positive")
	}
	if c.WSPingPeriod >= c.WSPongWait {
		return fmt.Errorf("WS_PING_PERIOD must be less than WS_PONG_WAIT")
	}
	if c.SessionTTL <= 0 {
		return fmt.Errorf("SESSION_TTL must be positive")
	}
	if c.AuthCookieName == "" {
		return fmt.Errorf("AUTH_COOKIE_NAME must not be empty")
	}
	if c.AuthRateLimitRegister <= 0 {
		return fmt.Errorf("AUTH_RATE_LIMIT_REGISTER must be positive")
	}
	if c.AuthRateLimitLogin <= 0 {
		return fmt.Errorf("AUTH_RATE_LIMIT_LOGIN must be positive")
	}
	if c.AuthRateLimitWindow <= 0 {
		return fmt.Errorf("AUTH_RATE_LIMIT_WINDOW must be positive")
	}
	return nil
}

// resolveAuthCookieName picks a cookie name. __Host- requires Secure and is used only then.
func resolveAuthCookieName(secure bool, override string) string {
	if override != "" {
		return override
	}
	if secure {
		return "__Host-ndr_session"
	}
	return "ndr_session"
}

func getBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return fallback
	}
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
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
