# Sandbox-owned Command Journal — pre-Permit, non-dispatch candidate

Status: **draft, non-production**. Tracked by [ACP #70](https://github.com/avaargsh/agent-control-panel/issues/70). This is an independent Go module + independent PostgreSQL database, located within this repository for review. It is NOT compiled into the ACP API module. Sandbox Service is sole writer for this database; do not run its migration against ACP's RunIntent DB.

The only callable mutation is `RecordPermitUnavailable` for a fully bound tenant/Run/RuntimeAttempt/SandboxUID/CommandID/request-digest identity. It writes one durable `PERMIT_UNAVAILABLE` row and one immutable Outbox fact **atomically**. Same identity+digest replays the record without a second event. Different digest, Run or Runtime Attempt conflicts. No executor attempt ID is created until an authorized dispatch actually exists. PostgreSQL unique constraints fence concurrent writers and deny immutable command rebinding. Reopening a fresh DB pool recovers the same record. The module deliberately has **no** command start, PREPARED/DISPATCHING/UNKNOWN transition, Permit claim, AgentD client, provider calls, credential access, or Sandbox Lease writer.

The separate database is not a production permit ledger; the module doesn't authenticate user-facing API calls. It is not wired to ACP, Runtime, Guard or an external sandbox process. Its opaque identifiers confer no authorization.

## Quickstart: disposable local demo

**One command from the repository root** (requires Docker Compose v2 and Go 1.27.4):

```bash
bash services/sandbox-journal/scripts/demo.sh
```

The script starts a disposable PostgreSQL 16 container bound **only to 127.0.0.1:55439**, applies Sandbox-only SQL migrations, creates a separate **SELECT-only demo reader**, inserts synthetic pre-Permit fixtures and runs the real `sandboxctl inspect` against that database. It confirms the demo reader cannot UPDATE a lease row, asserts that dispatch, retry, business success and resource release are all denied or unverified, and also confirms a missing lease fails closed. It prints JSON + text and **automatically stops the container and deletes its database** even on error. To avoid a local port conflict, set `SANDBOX_DEMO_PORT=55539`.

This demo uses a fixed public test password. Never use it with production data or expose the port outside loopback. The demo is deliberately **read-only at the CLI layer**; it does not provision a Sandbox, execute AgentD, issue Guard Permit or prove provider recovery. See PR #84 for scope and CI evidence.

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

The candidate `migrations/0002_lease_intents.sql` and additive `0003_lease_outbox_immutable.sql` run **only in the independent Sandbox Service database**, in numeric order after 0001. Migration 0003 locks the lease state/event tables while verifying all existing one-or-two-event histories against original Run, RuntimeAttempt and RequestDigest; inconsistent histories abort the migration, not silently seal them. PostgreSQL rejects ordinary UPDATE/DELETE (including a no-op update) and TRUNCATE of the lease event table, in addition to the existing unique Generation constraint. The real PostgreSQL suite tests committed waiting/cancelled rows, migration replays and deliberately injected pre-existing corruption under a disposable database-owner-only fixture transaction. A production role must never have schema ownership or permission to disable those triggers; PostgreSQL superusers and table owners can still bypass this barrier. Database append-only policy is **not** cryptographic authenticity, provider state, or Guard authorization. `lease` integration tests use PostgreSQL 16 to check concurrent CAS (one winner), stale-generation refusal, cross-tenant reads, new-pool restart, and injected Outbox failure rollback with a safe reattempt. No external SandboxProvider, Guard Permit, PEP, AgentD or long-running command is exercised; this candidate does not complete ACP #70.

## Pre-Permit CommandJournal immutable source receipts (candidate migration 0004)

The original `PERMIT_UNAVAILABLE` **command row and its atomic Outbox event are append-only facts**. `migrations/0005_command_journal_outbox_immutable.sql` is applied **only in the independent Sandbox Service DB**, after 0004; it is never applied to the ACP RunIntent database.

Before installing UPDATE/DELETE/TRUNCATE barriers, the migration takes a PostgreSQL lock and checks every original command's bound Outbox event, generation and **exact three-field JSONB** (`run_id`, `runtime_attempt_id`, `request_digest`). Any orphan, substituted digest or unexpected payload field causes the migration to fail without sealing corrupted data. Once installed, ordinary UPDATE/DELETE and TRUNCATE (including CASCADE) cannot rewrite the command or its Outbox. Idempotent INSERT/replay and fresh-process PostgreSQL readback remain supported.

Real PostgreSQL negative tests first demonstrate that ordinary SQL could mutate these facts before migration. Post-migration tests assert that no-op UPDATE, DELETE and TRUNCATE are rejected, that valid history survives an idempotent migration rerun, and that a historical corruption injection causes the migration preflight to fail. Only isolated database-owner test transactions temporarily disable the mutation triggers to model past compromise; this is **not** an application repair method.

**Security boundary:** an actual table owner/superuser can disable or replace database triggers. Production requires a separate least-privilege Sandbox writer role without DDL/table-owner privileges, source-minted signing keys and an independent audit stream. This migration proves only local DB DML immutability, **not** real Guard Permit, AgentD dispatch, UNKNOWN Inspect, physical release or independent evidence provenance.

## Database runtime roles (candidate 0004, independent Sandbox DB only)

After `0001`–`0003`, a **DBA or migration owner**, never a Sandbox runtime credential, runs `migrations/0004_lease_runtime_roles.sql`. It creates or validates two **NOLOGIN, non-owner** group roles:

- `acp_sandbox_lease_writer`: schema USAGE; `SELECT, INSERT` on lease-intent and lease-event tables; `UPDATE` only on the intent's `state`, `generation`, `updated_at` columns
- `acp_sandbox_lease_reader`: `SELECT` on those two lease tables only

The script withdraws any broader table grants from these group roles before applying the explicit allowlist. It rejects existing login/superuser/CREATEROLE/owner/member-role escalation and a database where `PUBLIC` can CREATE in the shared `public` schema. **An operator provisions an independent LOGIN and securely grants only the intended group role**; the database role script intentionally includes no LOGIN, passwords, connection string or live credential.

The hosted PostgreSQL 16 regression opens **separate authenticated LOGIN connections** and proves the writer can create/replay/cancel and the reader can inspect, while attempting direct event UPDATE/DELETE/TRUNCATE, identity rewrite, cross-module journal inspection, table creation, trigger disable and role escalation. A reader's write attempts must fail. This is **not** an authentication or authorization boundary for tenant identifiers: the Sandbox API must independently authenticate the caller, bind tenant/Run to trusted identity, and prevent cross-tenant SQL access. A compromised authorized writer still has narrowly scoped INSERT/UPDATE rights; these grants and append-only triggers alone do **not** make source facts cryptographically immutable or prove Permit/PEP authority.

Operational constraints: never run migrations with a runtime LOGIN; never share a table-owner or superuser credential with the app. Review existing role memberships and `PUBLIC`/default privileges separately before deploying. This is a candidate privilege contract in a disposable CI database, not evidence of a production service principal or real AgentD commands.


## Lease transaction commit barrier (candidate migration 0006)

`migrations/0006_lease_commit_integrity.sql` follows **0005** in the independent Sandbox DB migration order. It locks lease tables while auditing existing state/event history; a missing original event, premature cancellation event, forged Run/digest, or extra event fields abort the migration. It installs two **DEFERRABLE INITIALLY DEFERRED constraint triggers**, covering state INSERT/UPDATE and Outbox INSERT. At COMMIT, the database requires exactly one bound event for `WAITING_FOR_PERMIT / generation=1` or exactly the two original creation/cancellation events for `CANCELLED_BEFORE_PROVISION / generation=2`. This preserves the repository's atomic `Create` and generation-fenced `CancelBeforeProvision` transactions while rejecting direct SQL that writes only one side of the aggregate.

The independent PostgreSQL CI includes negative commit tests for orphaned state, cancellation without an Outbox, future event, wrong Run and unexpected sensitive payload fields, plus positive complete-history replay, CAS and SIGKILL-after-commit non-dispatch checks. This is **database integrity of pre-Permit lease intents only**. It does not authenticate callers or prove cross-tenant RLS: the shared Sandbox Writer credential must not be exposed to tenants or untrusted clients. Owner/DBA accounts can still alter triggers or history. No real sandbox provisioning, protected dispatch, AgentD provider receipt, Guard Permit, external UNKNOWN reconciliation or physical cleanup is enabled. A production roll-out requires independent owner review, controlled migration credentials, complete role grants and source-authenticated tenant binding.

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

## Sandbox inspector PostgreSQL role gate (2026-11-22)

`sandboxctl inspect` refuses database credentials with elevated server-side authority **before** consulting lease or command rows. Its least-privilege preflight requires the authenticated PostgreSQL session identity to be the effective user, with SELECT on the four verified read surfaces (lease, command and their original Outbox records), and denies administrator / role-management flags, broad predefined data roles, database/schema CREATE, table- or column-level mutation grants on the Sandbox journal/lease and outbox tables, or membership that could recover any of those privileges. A connection-level `default_transaction_read_only=on` remains a defense in depth, **not** a substitute for the dedicated PostgreSQL role.

The hosted Sandbox PostgreSQL 16 CI uses three disposable roles to exercise the boundary: an ordinary SELECT-only reader (allowed), a writer with SELECT+UPDATE (denied), and a reader with a delegated writer role (denied); the migration owner/superuser must also be denied. The one-command disposable demo retains its own SELECT-only role and explicit denied UPDATE assertion. Failure is reported without exposing database credentials.

**Scope limitation:** this is a local operator CLI check for accidentally overprivileged credentials, **not** an authenticated multi-tenant API. The `--tenant` flag is still a caller-supplied query scope, not a proof of Tenant identity. Nor does any of this authorize AgentD commands, Guard Permits, SandboxProvider provisioning, or release verification. A production inspection endpoint needs separately authenticated tenant/Run identity and server-enforced authorization before deployment.
