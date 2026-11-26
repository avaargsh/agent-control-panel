# Local helpers for a checkout of this repository.
#
# These targets mirror the cluster-free static steps in
# .github/workflows/go.yml (gofmt, go vet, go mod verify, and
# `go test -race -count=1 ./...`). They do not start PostgreSQL, JetStream,
# or apply migrations. PostgreSQL integration tests skip when PGTEST_DSN is
# unset, so `make test` is not the full Go validation job.
#
# GitHub Actions pins Go 1.27.4 with GOTOOLCHAIN=local. go.mod states the
# minimum Go version. This Makefile uses only the installed toolchain and
# does not download one.
#
# Main packages under ./cmd, compiled by `make build`:
#   agent-control-panel, acp-authority-api, acp-goal-api, acp-goal,
#   acp-evidence-verify, acp-postfault-verify.

.PHONY: help lint test build run clean require-go

# Recipes, and any Go command they invoke, stay on the installed toolchain.
export GOTOOLCHAIN := local

# Keep build and clean inside the documented repository-local output directory.
override BIN_DIR := bin

.DEFAULT_GOAL := help

help:
	@echo "Targets:"
	@echo "  make help   - list targets (default)"
	@echo "  make lint   - gofmt -l . must be empty, go vet ./..., and go mod verify (no database, no JetStream)"
	@echo "  make test   - go test -race -count=1 ./... (PostgreSQL tests skip without PGTEST_DSN; does not start PostgreSQL or JetStream)"
	@echo "  make build  - compile agent-control-panel, acp-authority-api, acp-goal-api, acp-goal, acp-evidence-verify, and acp-postfault-verify into $(BIN_DIR)/"
	@echo "  make run    - build and run $(BIN_DIR)/agent-control-panel (honors LISTEN_ADDR)"
	@echo "  make clean  - delete $(BIN_DIR)/ only; does not clear the Go build cache"

require-go:
	@if ! command -v go >/dev/null 2>&1; then \
		printf '%s\n' "error: go is not installed or not on PATH. Install the Go version required by go.mod or a newer version. This Makefile sets GOTOOLCHAIN=local and does not download a toolchain." >&2; \
		exit 1; \
	fi
	@if ! command -v gofmt >/dev/null 2>&1; then \
		printf '%s\n' "error: gofmt is not installed or not on PATH. It ships with the Go toolchain. This Makefile sets GOTOOLCHAIN=local and does not download a toolchain." >&2; \
		exit 1; \
	fi
	@need=$$(sed -n 's/^go \([0-9][0-9]*\(\.[0-9][0-9]*\)*\).*/\1/p' go.mod | head -n 1); \
	if [ -z "$$need" ]; then \
		printf '%s\n' "error: could not read the required Go version from go.mod." >&2; \
		exit 1; \
	fi; \
	raw=$$(go env GOVERSION 2>/dev/null || true); \
	have=$$(printf '%s\n' "$$raw" | sed -n 's/^go\([0-9][0-9]*\(\.[0-9][0-9]*\)*\).*/\1/p' | head -n 1); \
	if [ -z "$$have" ]; then \
		printf '%s\n' "error: could not parse the local Go version from 'go env GOVERSION' (got: $${raw:-empty}). This Makefile sets GOTOOLCHAIN=local and does not download a toolchain." >&2; \
		exit 1; \
	fi; \
	version_at_least() { \
		have_v="$$1"; need_v="$$2"; \
		while [ -n "$$have_v" ] || [ -n "$$need_v" ]; do \
			h="$${have_v%%.*}"; n="$${need_v%%.*}"; \
			if [ "$$have_v" = "$$h" ]; then have_v=""; else have_v="$${have_v#*.}"; fi; \
			if [ "$$need_v" = "$$n" ]; then need_v=""; else need_v="$${need_v#*.}"; fi; \
			h="$${h%%[!0-9]*}"; n="$${n%%[!0-9]*}"; \
			h="$${h:-0}"; n="$${n:-0}"; \
			if [ "$$h" -gt "$$n" ]; then return 0; fi; \
			if [ "$$h" -lt "$$n" ]; then return 1; fi; \
		done; \
		return 0; \
	}; \
	if ! version_at_least "$$have" "$$need"; then \
		printf '%s\n' "error: local Go $$have is older than go.mod requires Go $$need. Install Go $$need or newer. This Makefile sets GOTOOLCHAIN=local and does not download a toolchain." >&2; \
		exit 1; \
	fi

lint: require-go
	unformatted=$$(gofmt -l .) || exit $$?; \
	if [ -n "$$unformatted" ]; then \
		printf 'Unformatted Go files:\n%s\n' "$$unformatted"; \
		exit 1; \
	fi
	go vet ./...
	go mod verify

test: require-go
	go test -race -count=1 ./...

build: require-go
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/agent-control-panel ./cmd/agent-control-panel
	go build -o $(BIN_DIR)/acp-authority-api ./cmd/acp-authority-api
	go build -o $(BIN_DIR)/acp-goal-api ./cmd/acp-goal-api
	go build -o $(BIN_DIR)/acp-goal ./cmd/acp-goal
	go build -o $(BIN_DIR)/acp-evidence-verify ./cmd/acp-evidence-verify
	go build -o $(BIN_DIR)/acp-postfault-verify ./cmd/acp-postfault-verify

run: build
	./$(BIN_DIR)/agent-control-panel

clean:
	rm -rf $(BIN_DIR)
