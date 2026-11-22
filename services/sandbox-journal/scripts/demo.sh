#!/usr/bin/env bash
# Single-command, non-production demo: launch ephemeral PostgreSQL,
# read PRE-PERMIT facts, prove all effect/finality flags are false, tear down.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if ! command -v docker >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
  echo "REQUIRES_DOCKER_COMPOSE: install Docker + docker compose v2" >&2
  exit 2
fi
if ! command -v go >/dev/null 2>&1; then
  echo "REQUIRES_GO: install the repository Go toolchain (Go 1.27.4)" >&2
  exit 2
fi

port="${SANDBOX_DEMO_PORT:-55439}"
if ! [[ "$port" =~ ^[0-9]{1,5}$ ]] || ((10#$port < 1024 || 10#$port > 65535)); then
  echo "INVALID_DEMO_PORT: choose an unprivileged TCP port (1024-65535)" >&2
  exit 2
fi

# A unique Compose project and immediate down -v keep test data isolated.
project="acp-sandbox-demo-$$"
compose=(docker compose -f "$root/compose.demo.yaml" -p "$project")
cleanup() {
  original=$?
  trap - EXIT
  if ! "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1; then
    echo "SANDBOX_DEMO_CLEANUP_FAILED: inspect disposable Compose resources for project $project" >&2
    if (( original == 0 )); then original=4; fi
  fi
  exit "$original"
}
trap cleanup EXIT

echo "Starting disposable, loopback-only PostgreSQL demo (never production)..."
"${compose[@]}" up -d --wait db

dsn="postgres://sandbox_demo_reader:demo-reader-only@127.0.0.1:${port}/sandbox_demo?sslmode=disable"
cd "$root"
# Source-owned migration 0010 must be installed in this disposable DB,
# but the untrusted read-only LOGIN cannot execute its DBA verifier.
# This is a migration/ACL smoke check, NOT actual revocation attestation.
proof_present="$("${compose[@]}" exec -T -e PGPASSWORD=sandbox-demo-only db \
  psql -h 127.0.0.1 -U sandbox_demo -d sandbox_demo -v ON_ERROR_STOP=1 -tAc \
  "SELECT to_regprocedure('public.sandbox_verify_lease_login_revocation(name,oid)') IS NOT NULL
      AND NOT has_function_privilege('sandbox_demo_reader',
        'public.sandbox_verify_lease_login_revocation(name,oid)'::regprocedure, 'EXECUTE')")"
if [[ "${proof_present//[[:space:]]/}" != "t" ]]; then
  echo "DEMO_ASSERTION_FAILED: migration 0010 missing or revocation verifier exposed to reader" >&2
  exit 1
fi

# The demo reader must be unable to perform even a harmless-looking UPDATE.
# This checks PostgreSQL grants, not just the CLI's read-only query shape.
if "${compose[@]}" exec -T -e PGPASSWORD=demo-reader-only db \
  psql -h 127.0.0.1 -U sandbox_demo_reader -d sandbox_demo -v ON_ERROR_STOP=1 \
  -c "UPDATE sandbox_lease_intents SET state='WAITING_FOR_PERMIT' WHERE tenant_id='sandboxctl-smoke'" >/dev/null 2>&1; then
  echo "DEMO_ASSERTION_FAILED: database reader has write privileges" >&2
  exit 1
fi
SANDBOX_JOURNAL_READ_DSN="$dsn" go test -count=1 -v -run '^TestSandboxctlRealScopedReaderFixture$' ./cmd/sandboxctl
json="$(SANDBOX_JOURNAL_READ_DSN="$dsn" go run ./cmd/sandboxctl inspect \
  --tenant sandboxctl-smoke --lease-intent lease-smoke-1 \
  --sandbox-uid sandbox-smoke-1 --command-id command-smoke-1 --format json)"
text_report="$(SANDBOX_JOURNAL_READ_DSN="$dsn" go run ./cmd/sandboxctl inspect \
  --tenant sandboxctl-smoke --lease-intent lease-smoke-1 --format text)"

# Behavioral assertions against real ephemeral PostgreSQL rows.
for marker in \
  '"source": "UNATTESTED_DB_SNAPSHOT"' \
  '"state": "WAITING_FOR_PERMIT"' \
  '"state": "PERMIT_UNAVAILABLE"' \
  '"next_action": "HOLD"' \
  '"can_dispatch": false' \
  '"can_retry": false' \
  '"can_declare_success": false' \
  '"can_declare_released": false'; do
  if [[ "$json" != *"$marker"* ]]; then
    echo "DEMO_ASSERTION_FAILED: missing $marker" >&2
    exit 1
  fi
done
if [[ "$text_report" != *"Dispatch: DENIED"* || "$text_report" != *"Release: UNVERIFIED"* ]]; then
  echo "DEMO_ASSERTION_FAILED: text report promoted effect or finality" >&2
  exit 1
fi
# Unknown lease must fail closed.
if SANDBOX_JOURNAL_READ_DSN="$dsn" go run ./cmd/sandboxctl inspect \
  --tenant sandboxctl-smoke --lease-intent missing-lease --format json >/dev/null 2>&1; then
  echo "DEMO_ASSERTION_FAILED: missing lease incorrectly accepted" >&2
  exit 1
fi

printf '%s\n' "=== Safe Sandbox inspection (unattested, read-only) ==="
printf '%s\n' "$json" "$text_report"
printf '%s\n' "SANDBOX_DEMO_PASS: no dispatch, retry, success or release authority"
