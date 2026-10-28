package main

import (
	"context"
	"errors"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/Network-Detection-and-Response/backend/internal/config"
	httpapi "github.com/Network-Detection-and-Response/backend/internal/http"
	"github.com/Network-Detection-and-Response/backend/internal/observability"
	"github.com/Network-Detection-and-Response/backend/internal/repository/postgres"
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
		"telegram_enabled", cfg.TelegramEnabled(),
		"llm_enabled", cfg.LLMEnabled(),
		"ml_configured", cfg.MLServiceURL != "",
	)

	ctx := context.Background()
	pool, err := postgres.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("db_connect_failed", "error", err.Error())
		os.Exit(1)
	}
	defer pool.Close()

	router := httpapi.NewRouter(httpapi.Dependencies{
		Config: cfg,
		Log:    log,
		DB:     pool,
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

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer shutdownCancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("shutdown_failed", "error", err.Error())
		os.Exit(1)
	}
	log.Info("shutdown_complete")
}
