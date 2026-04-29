# GophKeeper Makefile — Go 1.26
# ───────────────────────────────────────────────────────────────────────────────
# Quick start (runs everything locally):
#
#   make postgres       # start PostgreSQL in Docker (background)
#   make run-server     # build & run the server against local postgres
#
#   make build-client
#   GOPHKEEPER_MASTER=secret GOPHKEEPER_SECRET=secret ./bin/gophkeeper register -l alice -p password
#   GOPHKEEPER_MASTER=secret GOPHKEEPER_SECRET=secret ./bin/gophkeeper --master-password=secret add credential -n github -l alice -p hunter2
#   GOPHKEEPER_MASTER=secret GOPHKEEPER_SECRET=secret ./bin/gophkeeper --master-password=secret list
#

MODULE  := github.com/alikhanturusbekov/gophkeeper
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD   ?= $(shell date -I)
LDFLAGS := -ldflags="-X $(MODULE)/pkg/version.Version=$(VERSION) \
                     -X $(MODULE)/pkg/version.BuildDate=$(BUILD)"

# Load .env if it exists so make targets inherit the variables.
-include .env
export

.PHONY: all deps postgres postgres-stop run-server \
        build build-server build-client \
        test cover lint clean help

all: build

deps:
	go mod download
	go mod tidy

## postgres: start PostgreSQL in Docker (detached)
postgres:
	docker compose up -d postgres
	@echo ""
	@echo "  PostgreSQL is starting…"
	@echo "  DSN: postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable"
	@echo "  Wait a few seconds, then run: make run-server"

## postgres-stop: stop and remove the PostgreSQL container
postgres-stop:
	docker compose down

## postgres-reset: stop, remove container AND data volume
postgres-reset:
	docker compose down -v

## run-server: build and run the server
run-server:
	@if [ -z "$$GOPHKEEPER_DSN" ]; then \
		echo ""; \
		echo "  ERROR: GOPHKEEPER_DSN is not set."; \
		echo "  Run 'make postgres' first, then 'make run-server'."; \
		echo "  Or copy .env.example to .env and adjust values."; \
		echo ""; \
		exit 1; \
	fi
	CGO_ENABLED=0 go run $(LDFLAGS) ./cmd/server \
		--addr="$${GOPHKEEPER_ADDR:-:8080}" \
		--dsn="$$GOPHKEEPER_DSN" \
		--secret="$${GOPHKEEPER_SECRET:-dev-secret-change-me}" \
		--log-level="$${GOPHKEEPER_LOG_LEVEL:-info}"

## build: build both server and client binaries into bin/
build: build-server build-client

## build-server: build the server binary
build-server:
	CGO_ENABLED=0 go build $(LDFLAGS) -o bin/server ./cmd/server
	@echo "  → bin/server"

## build-client: build the CLI client binary
build-client:
	CGO_ENABLED=1 go build $(LDFLAGS) -o bin/gophkeeper ./cmd/client
	@echo "  → bin/gophkeeper"

## test: run all unit tests (no real database required — stubs used)
test:
	go test -race ./...

## cover: generate an HTML coverage report (opens coverage.html)
cover:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "  Coverage report: coverage.html"

## lint: run go vet over the whole module
lint:
	go vet ./...

## clean: remove compiled binaries and coverage reports
clean:
	rm -rf bin/ coverage.out coverage.html

## help: list available targets
help:
	@grep -E '^##' Makefile | sed 's/## /  /'
