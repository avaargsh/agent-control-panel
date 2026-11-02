# PostgreSQL Persistence Contract — P0

Status: **RunIntent repository and transactional Outbox foundation implemented; delivery workers and Runtime integration remain pending**.

This persistence layer owns only Control Plane RunIntent and messaging delivery state. It deliberately does not create a runs table: Agent Runtime owns Run/Task/RunAttempt lifecycle and identifiers.

## Implemented

- Migration: migrations/0001_run_intents_outbox_inbox.sql, embedded and applied by internal/runintent/postgres.Migrate.
- PostgreSQL is authoritative for RunIntent and the local Outbox/Inbox.
- Repository.Create atomically claims the idempotency key, inserts the RunIntent and appends agent.run-intent.created in one transaction.
- A matching idempotency replay returns the original record without a second Outbox event. Reuse of the same key with a different canonical digest returns ErrIdempotencyConflict.
- Repository.CompareAndSwap locks and reads the current row, verifies the expected version, immutable identity, allowed state transition and non-decreasing fencing token, then updates the row and appends its event in one transaction.
- A duplicate/conflicting Outbox insert rolls back the state transition.
- Reads revalidate persisted domain invariants before returning a record.
- Migration startup is serialized with a PostgreSQL advisory lock. The initial migration is transactional and safely retryable.
- PostgreSQL integration tests cover idempotent replay, conflicting digest, concurrent claims, CAS, and transaction rollback.

## Contract details

- Idempotency uniqueness: (tenant_id, principal_id, operation, idempotency_key).
- State transitions use optimistic version checks and a row lock; the update increments version exactly once.
- Lease claim, expiry and reclaim must monotonically advance fence_token. Stale owners are rejected by both version and fencing checks.
- Runtime Run/Workflow identifiers are written only from a verified Runtime receipt matching tenant, RunIntent ID and request digest.
- Outbox delivery is at-least-once. Never mark an event PUBLISHED before the broker acknowledges it.

## Remaining P0

- Outbox publisher: bounded FOR UPDATE SKIP LOCKED claims, durable leases, retry and acknowledgement.
- Inbox consumer: event deduplication, aggregate-version claims, ordered projection, gap deferral and quarantine.
- Authenticated Runtime StartRun / InspectRunIntent adapter and reconciliation worker.
- Service connection lifecycle, readiness integration, deployment configuration and operational metrics.
- Restart, lost-ACK, duplicate-start and Runtime idempotency integration tests.
- Migration history table and explicit forward/rollback policy for subsequent schema versions.

Do not expose mutating HTTP endpoints until Runtime authentication, durable dispatch/reconciliation, Outbox/Inbox workers and their failure-recovery tests are complete.
