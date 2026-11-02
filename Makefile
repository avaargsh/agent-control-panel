.PHONY: test test-unit run migrate fmt

test:
	go test ./...

test-unit:
	go test ./internal/...

fmt:
	gofmt -w $$(find ./cmd ./internal -name '*.go' -type f)

migrate:
	psql "$(DATABASE_URL)" -v ON_ERROR_STOP=1 -f migrations/001_init.sql

run:
	go run ./cmd/agent-control-plane
