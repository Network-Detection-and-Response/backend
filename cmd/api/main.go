package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Network-Detection-and-Response/backend/internal/agent"
	"github.com/Network-Detection-and-Response/backend/internal/config"
	httpapi "github.com/Network-Detection-and-Response/backend/internal/http"
	"github.com/Network-Detection-and-Response/backend/internal/integrations/ml"
	"github.com/Network-Detection-and-Response/backend/internal/notifications"
	"github.com/Network-Detection-and-Response/backend/internal/observability"
	"github.com/Network-Detection-and-Response/backend/internal/realtime"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
	authsvc "github.com/Network-Detection-and-Response/backend/internal/service/auth"
	"github.com/Network-Detection-and-Response/backend/internal/service/flows"
	"github.com/Network-Detection-and-Response/backend/internal/service/incidents"
	"github.com/Network-Detection-and-Response/backend/internal/service/ingestion"
	"github.com/Network-Detection-and-Response/backend/internal/service/stats"
	"github.com/Network-Detection-and-Response/backend/internal/service/topology"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slogTemp := observability.NewLogger("error")
		slogTemp.Error("config_load_failed", "error", err.Error())
		os.Exit(1)
	}

	log := observability.NewLogger(cfg.LogLevel)
	log.Info("starting",
		"http_addr", cfg.HTTPAddr,
		"queue_capacity", cfg.QueueCapacity,
		"worker_count", cfg.WorkerCount,
		"persist_max_attempts", cfg.PersistMaxAttempts,
		"persist_retry_base_delay", cfg.PersistRetryBaseDelay.String(),
		"telegram_enabled", cfg.TelegramEnabled(),
		"telegram_bot_url_set", cfg.TelegramBotURL != "",
		"llm_enabled", cfg.LLMEnabled(),
		"ml_enabled", cfg.MLConfigured(),
		"ml_service_url_set", cfg.MLServiceURL != "",
		"attack_threshold", cfg.AttackThreshold,
		"auth_cookie_secure", cfg.AuthCookieSecure,
		"session_ttl", cfg.SessionTTL.String(),
	)
	if !cfg.MLConfigured() {
		log.Warn("ml_disabled",
			"reason", "ML_SERVICE_URL empty or ML_ENABLED=false; flows persist without predictions or ML-driven incidents",
		)
	}

	ctx := context.Background()
	pool, err := postgres.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("db_connect_failed", "error", err.Error())
		os.Exit(1)
	}
	defer pool.Close()

	store := postgres.NewStore(pool)

	var telegramSender notifications.Sender
	if cfg.TelegramEnabled() {
		telegramSender = notifications.NewTelegramSender(
			cfg.TelegramAPIBaseURL,
			cfg.TelegramBotToken,
			cfg.TelegramChatID,
			cfg.TelegramHTTPTimeout,
		)
	}
	notifyQueue := notifications.NewQueue(
		cfg.TelegramEnabled(),
		telegramSender,
		notifications.QueueConfig{
			Capacity:  cfg.TelegramQueueCapacity,
			MaxTries:  cfg.TelegramMaxAttempts,
			BaseDelay: cfg.TelegramRetryBase,
		},
		log,
	)

	var predictor ingestion.Predictor
	if cfg.MLConfigured() {
		predictor = ml.NewClient(cfg.MLServiceURL, cfg.MLTimeout)
		log.Info("ml_client_ready", "url", cfg.MLServiceURL)
	}

	var explainer agent.Explainer = agent.TemplateExplainer{}
	if cfg.LLMEnabled() {
		if llm := agent.NewHTTPLLMClient(cfg.LLMBaseURL, cfg.LLMAPIKey, 5*time.Second); llm != nil {
			explainer = agent.OptionalLLMExplainer{Enabled: true, Inner: llm}
			log.Info("llm_explainer_enabled")
		}
	}
	decisionAgent := agent.New(agent.Config{
		AttackThreshold:       cfg.AttackThreshold,
		DDoSCriticalThreshold: cfg.DDoSCriticalThreshold,
	}, explainer)

	hub := realtime.NewHub(realtime.Config{
		AllowedOrigins: cfg.CORSAllowedOrigins,
		ClientBuffer:   cfg.WSClientBuffer,
		WriteWait:      cfg.WSWriteWait,
		PongWait:       cfg.WSPongWait,
		PingPeriod:     cfg.WSPingPeriod,
	}, log)

	ingestOpts := ingestion.Options{
		Realtime:      hub,
		Log:           log,
		HistoryWindow: cfg.AttackWindow,
		Notifier:      notifyQueue,
	}
	// Wire Decision Agent only when ML is active — no fabricated predictions without ML.
	if predictor != nil {
		ingestOpts.Predictor = predictor
		ingestOpts.DecisionStore = store
		ingestOpts.Agent = decisionAgent
	}

	ingestSvc := ingestion.NewService(store, ingestOpts)
	queue := ingestion.NewQueue(
		cfg.QueueCapacity,
		cfg.WorkerCount,
		ingestion.RetryPolicy{
			MaxAttempts: cfg.PersistMaxAttempts,
			BaseDelay:   cfg.PersistRetryBaseDelay,
		},
		ingestSvc,
		log,
	)

	incidentSvc := incidents.NewService(store)
	topologySvc := topology.NewService(store, cfg.AttackWindow)
	statsSvc := stats.NewService(store)
	flowListSvc := flows.NewService(store)
	authSvc := authsvc.NewService(store, cfg.SessionTTL)
	router := httpapi.NewRouter(httpapi.Dependencies{
		Config:          cfg,
		Log:             log,
		DB:              pool,
		FlowEnqueuer:    queue,
		FlowListService: flowListSvc,
		IncidentService: incidentSvc,
		TopologyService: topologySvc,
		StatsService:    statsSvc,
		AuthService:     authSvc,
		Realtime:        hub,
	})

	srv := &http.Server{
		Addr:         cfg.HTTPAddr,
		Handler:      router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		IdleTimeout:  cfg.IdleTimeout,
	}

	go func() {
		log.Info("http_listen", "addr", cfg.HTTPAddr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http_server_failed", "error", err.Error())
			os.Exit(1)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	sig := <-stop
	log.Info("shutdown_signal", "signal", sig.String())

	httpCtx, httpCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	if err := srv.Shutdown(httpCtx); err != nil {
		log.Error("http_shutdown_failed", "error", err.Error())
	}
	httpCancel()

	hub.Shutdown()

	queueCtx, queueCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	queue.Shutdown(queueCtx)
	queueCancel()

	notifyCtx, notifyCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	notifyQueue.Shutdown(notifyCtx)
	notifyCancel()
	log.Info("shutdown_complete")
}
