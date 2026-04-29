package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	delivery "github.com/alikhanturusbekov/gophkeeper/internal/server/delivery/http"
	"github.com/alikhanturusbekov/gophkeeper/internal/server/repository"
	"github.com/alikhanturusbekov/gophkeeper/internal/server/usecase"
	"github.com/alikhanturusbekov/gophkeeper/pkg/jwt"
	"github.com/alikhanturusbekov/gophkeeper/pkg/logger"
	"github.com/alikhanturusbekov/gophkeeper/pkg/version"
)

func main() {
	addr := flag.String("addr", envOrDefault("GOPHKEEPER_ADDR", ":8080"), "HTTP listen address")
	dsn := flag.String("dsn", envOrDefault("GOPHKEEPER_DSN", ""), "PostgreSQL DSN")
	secret := flag.String("secret", envOrDefault("GOPHKEEPER_SECRET", ""), "JWT signing secret")
	logLevel := flag.String("log-level", envOrDefault("GOPHKEEPER_LOG_LEVEL", "info"), "Log level (debug|info|warn|error)")
	flag.Parse()

	log := logger.New(*logLevel)
	log.Info("starting server", "version", version.Info())

	if *dsn == "" {
		log.Error("error starting server: --dsn or GOPHKEEPER_DSN must be set")
		os.Exit(1)
	}
	if *secret == "" {
		log.Error("error starting server: --secret or GOPHKEEPER_SECRET must be set")
		os.Exit(1)
	}

	db, err := repository.NewDB(*dsn)
	if err != nil {
		log.Error("open database", "err", err)
		os.Exit(1)
	}
	defer func(db *repository.DB) {
		err := db.Close()
		if err != nil {
			log.Error("error closing database connection", "err", err)
		}
	}(db)

	userRepo := repository.NewUserRepo(db)
	secretRepo := repository.NewSecretRepo(db)

	jwtManager := jwt.NewManager(*secret)
	authUC := usecase.NewAuthUseCase(userRepo, jwtManager)
	secretUC := usecase.NewSecretUseCase(secretRepo)

	handler := delivery.NewHandler(authUC, authUC, secretUC, log)
	srv := &http.Server{
		Addr:         *addr,
		Handler:      handler.Router(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		log.Info("listening", "addr", *addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("listen", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down…")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("graceful shutdown failed", "err", err)
	}
	log.Info("server stopped")
}

// envOrDefault returns the value of the environment variable name, or fallback when the variable is unset or empty
func envOrDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
