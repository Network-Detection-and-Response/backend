APP=api
GO?=go
GOOSE?=goose
DATABASE_URL?=postgres://ndr:ndr@localhost:5432/ndr?sslmode=disable
MIGRATIONS_DIR?=migrations

.PHONY: run test vet fmt check migrate-up migrate-down migrate-status migrate-reset-dev docker-up docker-down tidy

run:
	$(GO) run ./cmd/api

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

check: fmt vet test

tidy:
	$(GO) mod tidy

migrate-up:
	$(GOOSE) -dir $(MIGRATIONS_DIR) postgres "$(DATABASE_URL)" up

migrate-down:
	$(GOOSE) -dir $(MIGRATIONS_DIR) postgres "$(DATABASE_URL)" down

migrate-status:
	$(GOOSE) -dir $(MIGRATIONS_DIR) postgres "$(DATABASE_URL)" status

# Rolls back one version then re-applies. Does NOT delete Docker volumes.
migrate-reset-dev:
	$(GOOSE) -dir $(MIGRATIONS_DIR) postgres "$(DATABASE_URL)" down
	$(GOOSE) -dir $(MIGRATIONS_DIR) postgres "$(DATABASE_URL)" up

docker-up:
	docker compose up --build -d

docker-down:
	docker compose down
