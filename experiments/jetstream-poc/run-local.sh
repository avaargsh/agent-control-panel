#!/usr/bin/env bash
# Disposable local integration demo. Never points at an existing database.
set -Eeuo pipefail
umask 077
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

die() { printf '%s\n' "$*" >&2; exit 1; }
for command in docker go openssl; do
    command -v "$command" >/dev/null || die "Missing prerequisite: $command"
done
docker info >/dev/null 2>&1 || die "Docker daemon is not accessible; start Docker and grant local access."
export GOTOOLCHAIN=local
[[ "$(go env GOVERSION)" == "go1.27.4" ]] || die "Install Go 1.27.4 (the audited CI toolchain)."
[[ "$(go env CGO_ENABLED)" == "1" ]] || die "Enable CGO and install a C compiler for go test -race."

pg_id=
nats_id=
log="$(mktemp)"
cleanup() {
    local rc=$?
    trap - EXIT
    if (( rc != 0 )); then
        [[ -z "$pg_id" ]] || docker logs --tail 50 "$pg_id" >&2 || true
        [[ -z "$nats_id" ]] || docker logs --tail 50 "$nats_id" >&2 || true
    fi
    [[ -z "$nats_id" ]] || docker rm -fv "$nats_id" >/dev/null || rc=1
    [[ -z "$pg_id" ]] || docker rm -fv "$pg_id" >/dev/null || rc=1
    rm -f -- "$log"
    exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Explicit local-only fixtures; generated credentials and random loopback ports.
password="$(openssl rand -hex 24)"
pg_id="$(POSTGRES_PASSWORD="$password" docker run -d -e POSTGRES_PASSWORD \
    -e POSTGRES_USER=postgres -e POSTGRES_DB=postgres \
    -p 127.0.0.1::5432 postgres:16-alpine)"
nats_id="$(docker run -d -p 127.0.0.1::4222 \
    nats:2.15.2@sha256:b6c40dcfe5ae9174dcafa9c43f800afb93b8b0ffcde02ac00efc6b66031d9a50 \
    -js -sd /data)"

port_for() {
    local mapping
    mapping="$(docker port "$1" "$2/tcp")" || return 1
    [[ "$mapping" =~ ^127\.0\.0\.1:([0-9]+)$ ]] || die "Unexpected Docker port mapping."
    printf '%s' "${BASH_REMATCH[1]}"
}
pg_port="$(port_for "$pg_id" 5432)"
nats_port="$(port_for "$nats_id" 4222)"
ready=0
for ((attempt=0; attempt<60; attempt++)); do
    if docker exec "$pg_id" pg_isready -h 127.0.0.1 -U postgres -d postgres >/dev/null 2>&1 &&
        (exec 3<>"/dev/tcp/127.0.0.1/$nats_port") 2>/dev/null; then
        ready=1
        break
    fi
    sleep 1
done
((ready == 1)) || die "Disposable PostgreSQL or NATS failed readiness."

# Never trust inherited external DSNs. Do not print the generated password.
export PGTEST_DSN="postgres://postgres:$password@127.0.0.1:$pg_port/postgres?sslmode=disable"
export NATS_POC_URL="nats://127.0.0.1:$nats_port"
unset ACP_JS_POC_CHILD ACP_JS_DLQ_CHILD
printf 'Running isolated JetStream/PostgreSQL integration suite\n'
go mod verify
go test -mod=readonly -race -count=1 -v ./... | tee "$log"
if grep -Fq -- '--- SKIP:' "$log"; then
    die "Integration suite unexpectedly skipped a test; inspect the output."
fi
for test in TestJetStreamRealBrokerAckLossConflictAndDLQFailure \
    TestRealJetStreamCrashAfterPGCommitBeforeBrokerACK \
    TestRealJetStreamCrashAfterConfirmedDLQBeforeSourceACK \
    TestRealJetStreamCompetingDeliveriesSinglePublishThenRecovery \
    TestDispositionJournalGrantsOnlyOnePublishClaim \
    TestRealJetStreamBrokerRestartPreservesConfirmedDLQ \
    TestRealJetStreamRejectsVolatileDLQBeforeClaimAndACK \
    TestRealJetStreamMTLSAndTenantIsolation/AuthenticatedInboxDLQRecovery \
    TestRealDispositionInspectionIsReadOnlyAndDistinguishesEvidence \
    TestRealDispositionInspectorWithRestrictedRoleAndAmbiguousPublish; do
    grep -Fq -- "--- PASS: $test (" "$log" || die "Required test did not pass: $test"
done
printf 'JETSTREAM_LOCAL_REPRO_PASS\n'
