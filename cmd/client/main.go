package main

import (
	"flag"
	"os"

	"github.com/alikhanturusbekov/gophkeeper/internal/client/delivery/cli"
	clientrepo "github.com/alikhanturusbekov/gophkeeper/internal/client/repository"
	"github.com/alikhanturusbekov/gophkeeper/internal/client/usecase"
	jwtpkg "github.com/alikhanturusbekov/gophkeeper/pkg/jwt"
	"github.com/alikhanturusbekov/gophkeeper/pkg/logger"
	"github.com/alikhanturusbekov/gophkeeper/pkg/version"
)

func main() {
	serverURL := flag.String("server", envOrDefault("GOPHKEEPER_SERVER", "http://localhost:8080"), "GophKeeper server base URL")
	dbPath := flag.String("db", envOrDefault("GOPHKEEPER_DB", "gophkeeper_client.db"), "Local SQLite cache path")
	masterPW := flag.String("master-password", os.Getenv("GOPHKEEPER_MASTER"), "Master password used to encrypt/decrypt secrets locally")
	jwtSecret := flag.String("jwt-secret", os.Getenv("GOPHKEEPER_SECRET"), "JWT signing secret (must match the server's secret for token validation)")
	logLevel := flag.String("log-level", "warn", "Log level")

	flag.CommandLine.SetOutput(os.Stderr)
	flag.Parse()

	log := logger.New(*logLevel)
	log.Info("GophKeeper client", "version", version.Info())

	if *masterPW == "" {
		log.Error("master password is required")
		os.Exit(1)
	}

	local, err := clientrepo.NewLocalDB(*dbPath)
	if err != nil {
		log.Error("error while opening local db", "err", err)
		os.Exit(1)
	}
	defer func(local *clientrepo.LocalDB) {
		err := local.Close()
		if err != nil {
			log.Error("error while closing local db", "err", err)
		}
	}(local)

	serverClient := usecase.NewHTTPClient(*serverURL)

	uc := usecase.NewSecretUseCase(local, serverClient, *masterPW)

	uc.SetAuth(jwtpkg.NewManager(*jwtSecret))

	app := cli.NewApp(uc)
	if err := app.Execute(); err != nil {
		os.Exit(1)
	}
}

// envOrDefault returns the value of the environment variable name, or fallback if the variable is unset or empty
func envOrDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
