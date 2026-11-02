# PostgreSQL Persistence Contract — P0

Status: **schema foundation; repository and runtime integration pending**.

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

## Explicit implementation gaps

The SQL migration establishes constraints and indexes only. It does not yet provide:
- a Go PostgreSQL repository or connection lifecycle;
- transaction methods for idempotency + RunIntent + Outbox;
- lease claim/reclaim SQL with fencing;
- publisher and consumer workers;
- migrations runner and rollback policy;
- integration tests against a real PostgreSQL instance.

Do not expose mutating HTTP endpoints until those operations are implemented and tested with concurrent transactions, duplicate delivery, crash/restart and lost-ACK scenarios.
