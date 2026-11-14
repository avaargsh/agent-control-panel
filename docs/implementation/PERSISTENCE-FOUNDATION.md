# PostgreSQL Persistence Contract — P0

Status: **transactional RunIntent/Outbox repository and generic Outbox dispatcher implemented; broker adapter, Inbox worker and Runtime integration remain pending**.

This migration persists only Control Plane-owned RunIntent and messaging delivery state. It deliberately does not create a \`runs\` table: Agent Runtime owns Run/Task/RunAttempt lifecycle and identifiers.

## Migration

- \`migrations/0001_run_intents_outbox_inbox.sql\`
- PostgreSQL is the authoritative store for RunIntent and the local Outbox/Inbox.
- RunIntent creation must insert the row and its \`agent.run-intent.created\` Outbox event in one transaction.
- Idempotency claim is protected by the unique key \`(tenant_id, principal_id, operation, idempotency_key)\`; compare the stored canonical request digest before replaying.
- A reused key with a different digest is a 409 conflict.
- State transitions must use compare-and-swap: \`UPDATE ... WHERE id = $id AND version = $expected_version\`; increment version in the same statement and require exactly one affected row.
- Every lease claim/expiry/reclaim must monotonically advance \`fence_token\`. A stale owner must fail both the row-version CAS and fencing check.
- Runtime Run/Workflow identifiers are written only from a verified Runtime receipt matching tenant, RunIntent ID and request digest.

## Outbox publisher

Claim a bounded batch using \`FOR UPDATE SKIP LOCKED\`, transition rows to \`PUBLISHING\`, and assign owner/expiry in a transaction. Publish outside the database transaction. Acknowledge only with the same lease owner and event identity; publish is at-least-once.

Expired publish leases return to retryable state. Never mark an event PUBLISHED before the broker acknowledges it. The broker ACK still does not prove consumer application.

## Inbox and ordering

- Insert the event into \`inbox_events\` before projection work.
- Deduplicate by \`(consumer_name, event_id)\`.
- Claim each aggregate version in \`inbox_aggregate_claims\`; a conflicting event for an already claimed version is quarantined.
- Apply only \`last_applied_version + 1\`; update projection, cursor and Inbox state to APPLIED atomically.
- A gap remains RECEIVED/deferred. Do not advance the cursor.
- Unknown breaking schema versions are quarantined.

## Repository implementation foundation

### Implemented behavior (PR #5 — still Draft)

The Go repository foundation now provides:
- `Repository.Create`: tenant/principal-scoped idempotency claim, RunIntent insert and `agent.run-intent.created` Outbox append in one transaction.
- Exact replay checks the stored digest **and** immutable project/agent/release/session ownership metadata; a same-key/same-digest request that changes any separately stored owner field returns a conflict. A newly generated candidate ID is ignored on replay; the original committed ID is returned.
- `Repository.Get` reads tenant-scoped state and revalidates persisted domain invariants.
- `Repository.CompareAndSwap` locks the row, validates allowed transitions, immutable identity, optimistic version and fencing progression, then writes the transition and Outbox event atomically.
- Outbox insert failure rolls back the state transition. PostgreSQL integration tests cover concurrent idempotency, digest and owner-metadata conflicts, CAS, transaction rollback and migration re-entry.
- `Migrate` uses a PostgreSQL advisory lock and one transaction for schema DDL plus a version/name/SHA-256 migration ledger. It rejects changed checksums, incomplete schemas and unversioned pre-existing relations rather than silently adopting them.
- CI runs the repository tests against PostgreSQL via `PGTEST_DSN`, in addition to parent-branch migration and tenant-isolation smoke checks.

## PostgreSQL-clock RunIntent CAS gate (stacked Draft PR #13)

`Repository.CompareAndSwap` validates lease lifetime using PostgreSQL's
`clock_timestamp()` under the locked RunIntent row, then repeats the guard in
the conditional `UPDATE` immediately before the Outbox append. A caller's
clock or a stale in-memory `Intent` cannot authorize a commit after the stored
lease has expired.

- New PENDING→DISPATCHING and UNKNOWN→RECONCILING leases must expire strictly
  after the database clock and advance the fencing token exactly once.
- Valid Runtime receipt/reconciliation transitions must complete while the
  current lease is active and **must not increment** its fencing token.
- An ambiguous receipt may move active DISPATCHING/RECONCILING→UNKNOWN with the
  existing token; an expired lease may move to UNKNOWN only with `fence+1`.
  Premature expiry and post-expiry ACK/reconciliation are rejected without
  changing the RunIntent row or appending an Outbox event.
- This is a repository persistence guarantee, **not** a cryptographic Runtime
  receipt, mTLS authenticator, trusted principal snapshot, or an implementation
  of the cross-repository `StartRun/InspectRunIntent` protocol. Those remain
  blocked by ACP #10 / Runtime #20 owner-ratified contracts and recovery tests.
- CI verifies these cases using PostgreSQL 16 and synthetic typed outcomes;
  it does not establish staging recovery or database role/IAM hardening.

## Explicit remaining implementation gaps

- Inbox ingestion/consumer workers, including deduplication, tenant-scoped aggregate ordering, cursor advancement, gap recovery and quarantine.
- Production `EventPublisher` adapter with transport authentication, TLS, schema compatibility, metrics and deployment configuration.
- Authenticated Runtime `StartRun` / `InspectRunIntent` adapter and durable reconciliation worker.
- Service connection lifecycle, dependency-aware readiness, deployment configuration and operational metrics.
- Restart, lost-ACK, duplicate-start and cross-process recovery tests around the real Runtime adapter.
- Migration forward/rollback and backup/restore operational policy beyond the checksummed initial migration.

Do not expose mutating HTTP endpoints until Runtime authentication, durable dispatch/reconciliation, Outbox/Inbox workers and their failure-recovery tests are complete.

## Tenant-isolated messaging invariants (migration smoke)

The schema and PostgreSQL 16 CI now assert that the same aggregate ID and
version may exist in **different tenants**. The Outbox aggregate-version unique
key includes `tenant_id`; Inbox aggregate claims and cursor primary keys
also include `tenant_id`. The claim foreign key binds
`(consumer_name,event_id,tenant_id)` to the original Inbox event, preventing
an event from one tenant from being attributed to another.

The `migrations/tests/0001_tenant_isolation.sql` smoke test checks two-tenant
same-ID acceptance, same-tenant duplicate version refusal and cross-tenant
event attribution refusal. This verifies **schema constraints only**, not a
trusted broker consumer, authenticated principal, PostgreSQL Repository
transactions, or a production migration runner. Until these exist, do not
expose mutating Control Plane APIs.
