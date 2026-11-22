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
