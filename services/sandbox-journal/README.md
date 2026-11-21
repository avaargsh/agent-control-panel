# Sandbox-owned Command Journal — pre-Permit, non-dispatch candidate

Status: **draft, non-production**. Tracked by [ACP #70](https://github.com/avaargsh/agent-control-panel/issues/70). This is an independent Go module + independent PostgreSQL database, located within this repository for review. It is NOT compiled into the ACP API module. Sandbox Service is sole writer for this database; do not run its migration against ACP's RunIntent DB.

The only callable mutation is `RecordPermitUnavailable` for a fully bound tenant/Run/RuntimeAttempt/SandboxUID/CommandID/request-digest identity. It writes one durable `PERMIT_UNAVAILABLE` row and one immutable Outbox fact **atomically**. Same identity+digest replays the record without a second event. Different digest, Run or Runtime Attempt conflicts. No executor attempt ID is created until an authorized dispatch actually exists. PostgreSQL unique constraints fence concurrent writers and deny immutable command rebinding. Reopening a fresh DB pool recovers the same record. The module deliberately has **no** command start, PREPARED/DISPATCHING/UNKNOWN transition, Permit claim, AgentD client, provider calls, credential access, or Sandbox Lease writer.

The separate database is not a production permit ledger; the module doesn't authenticate user-facing API calls. It is not wired to ACP, Runtime, Guard or an external sandbox process. Its opaque identifiers confer no authorization.

## Verification

GitHub Actions `Sandbox-owned Command Journal (non-dispatch)` provisions an isolated `sandbox_journal_ci` PostgreSQL 16 database and executes:

````
cd services/sandbox-journal
go mod verify
go test -race -count=1 ./...
go vet ./...
```

Tests cover 20 concurrent duplicate submissions, immutable digest and original Run conflict, foreign tenant denial, separate DB-pool read after reconnect, single Outbox insertion, and injected Outbox insert failure causing full journal rollback. `go test` skips database cases if `SANDBOX_JOURNAL_TEST_DSN` is absent; **only the actual hosted PostgreSQL job counts as database evidence**.

## Blockers and next work

1. EngageGuard #34: independently reviewed trusted Scoped Permit issuer, atomic claim, revocation and executor PEP.
2. Sandbox source-owned and owner-reviewed CommandJournal protocol, separate deployment principal, lease generation CAS and least-privilege schema role.
3. Implement real `UNKNOWN → inspect authoritative provider attempt → reconcile` only after a legitimately dispatched attempt exists; never infer failed/no-effect from a missing ACK or missing journal row.
4. ACP #71 credential broker and network egress deny-by-default; ACP #72 independent evidence, actual sandbox UID absence and cost finalization.

This standalone migration is a candidate internal service schema, not the ratified cross-service wire format. No real commands are authorized or executed by it.

## Pre-Permit lease-intent CAS (candidate migration 0002)

`lease.Intent` is a **logical intent to request a sandbox after authorization**, not a claimed SandboxLease or a provider resource. It has a stable `tenant_id / lease_intent_id / Run / RuntimeAttempt / request_digest` and deliberately has **no sandbox UID or executor attempt**.

The Sandbox-owned PostgreSQL database accepts only two versioned states: `WAITING_FOR_PERMIT` at generation 1 and `CANCELLED_BEFORE_PROVISION` at generation 2. The first create and the one winning generation-CAS cancel each write exactly one Outbox event in their own local transaction. Same identity replays its latest state, including cancellation; different request digests or attempt bindings fail closed. Cancellation is **not resource deletion** and may not be interpreted as provider UID absence. No attempt may be dispatched by this module.

The new `migrations/0002_lease_intents.sql` runs **only in the independent Sandbox Service database**, after 0001. `lease` integration tests use PostgreSQL 16 to check concurrent CAS (one winner), stale-generation refusal, cross-tenant reads, new-pool restart, and injected Outbox failure rollback with a safe reattempt. No external SandboxProvider, Guard Permit, PEP, AgentD or long-running command is exercised; this candidate does not complete ACP #70.

## Read-only operator CLI (candidate): `sandboxctl inspect`

This is a **local developer tool for a separate Sandbox database**, not a public endpoint or authentication system. It does not request Permit, execute commands, allocate a Sandbox, or update journal/lease state. Create a SELECT-only PostgreSQL role before using it outside the isolated test database. The CLI additionally sets PostgreSQL `default_transaction_read_only=on`; a caller-supplied tenant identifier **is not authentication**.

```bash
cd services/sandbox-journal
export SANDBOX_JOURNAL_READ_DSN='postgres://sandbox_reader:REDACTED@127.0.0.1:5432/sandbox_journal_ci?sslmode=disable'
go run ./cmd/sandboxctl inspect --tenant tenant-a --lease-intent sandbox-intent-1 --format text
go run ./cmd/sandboxctl inspect --tenant tenant-a --sandbox-uid sandbox-uid-1 --command-id command-1 --format json
```

To view *both* records, supply `--lease-intent`, `--sandbox-uid` and `--command-id`. Their tenant, canonical Run and Runtime Attempt must match. If any source is missing/unreadable/mismatched, the CLI exits nonzero and never claims a positive conclusion. `WAITING_FOR_PERMIT` and `PERMIT_UNAVAILABLE` mean `HOLD`; `CANCELLED_BEFORE_PROVISION` means `STOP_NO_PROVIDER_ACTION`, **not** confirmed RELEASED. All output has `can_dispatch=false`, `can_retry=false`, `can_declare_success=false`, `can_declare_released=false`, and `source=UNATTESTED_DB_SNAPSHOT`. Credentials and request digests are not printed.

The [isolated CI workflow](../../.github/workflows/sandbox-journal.yml) seeds a synthetic pre-Permit record and denied command into PostgreSQL 16, executes the real CLI in read-only mode and checks JSON/text safety fields. It does not inspect a live SandboxProvider or claim a production command worked. `SANDBOX_JOURNAL_READ_DSN` is read from the environment, **not** from command arguments, to avoid placing secrets into process argument lists.
