# PostgreSQL Inbox Consumer — P0

Status: **durable Inbox intake and ordered projection worker implemented in a stacked Draft PR; transport adapter and operator replay remain pending**.

## Receive contract

The transport adapter must call `Repository.ReceiveInboxEvent` and commit the event to PostgreSQL **before** acknowledging the broker delivery.

- Delivery identity is scoped by `(consumer_name,event_id)`.
- Exact redelivery is idempotent.
- Reuse of an event ID with different persisted envelope fields or payload is surfaced as an identity conflict. A not-yet-applied stored event is quarantined. Every changed delivery is also committed to the append-only `inbox_event_conflicts` v2 archive (full persisted envelope fields, payload and deterministic SHA-256 conflict identity), including when the original is already `APPLIED` and cannot be retroactively quarantined. Exact replay of the same conflicting envelope does not create duplicate archive rows.
- Aggregate-version claims are scoped by consumer, tenant, aggregate type, aggregate ID and version.
- A competing event for an already-claimed aggregate version is retained as `QUARANTINED`; it never replaces the first claim.
- Cursor rows are initialized in the same transaction as the first accepted event.

The Inbox schema persists producer, event type, schema version, tenant, aggregate identity/version and JSON payload. Transport metadata not represented by the schema is not reconstructed by the applier.

The conflict archive is separate from the projection queue and its records cannot be UPDATEd, DELETEd or TRUNCATEd by ordinary database roles. The v2 SQL migration is additive, checksum-tracked and applied transactionally to existing v1 databases; changing v1 migration bytes is prohibited. An operator/runbook must still define alerting, authorized inspection, reconciliation and broker ACK/DLQ policy: persistent evidence alone does not imply that a conflicting event should be considered successfully applied, nor does it provide WORM retention against privileged DB users.

## Versioned CHECK guard verification (2026-11-05)

`Migrate` verifies five critical v1 `CHECK` predicates against the original, checksum-pinned `0001_run_intents_outbox_inbox.sql` rather than trusting a relation/name/type match. It compiles each expected predicate on an empty PostgreSQL temporary `LIKE` table and compares the server-normalized `pg_get_expr` definitions in the same transaction; temporary verification tables are removed on commit. This avoids pinning the comparison to a hard-coded output string from one PostgreSQL release and leaves the recorded v1/v2 migration SQL unchanged. The **migration role requires PostgreSQL TEMP privilege**; denial must fail startup rather than silently skip verification.

Regression evidence: five same-name/same-table `CHECK (TRUE)` replacements fail on [test-only RED 41941452246](https://github.com/avaargsh/agent-control-panel/actions/runs/41941452246) and are rejected on [GREEN 41941919219](https://github.com/avaargsh/agent-control-panel/actions/runs/41941919219). The latter passes PostgreSQL 16 integration (including fresh-install, recorded-v1 upgrade and re-entry), Go formatting, module verification, `go vet` and race-enabled tests. These tests do not establish PostgreSQL 17+ interoperability or resistance to database-owner/superuser tampering; schema permissions, connection search_path and external WORM retention remain separate deployment controls.

## Apply contract

`InboxWorker` applies only the next contiguous aggregate version.

- It locks the aggregate cursor and event row with `FOR UPDATE SKIP LOCKED`.
- Unsupported event/schema versions are quarantined with a stable error code.
- Later aggregate versions remain deferred while a version is missing or quarantined.
- The application projection, Inbox `APPLIED` state and aggregate cursor advance in one PostgreSQL transaction.
- A transient application error rolls back the full transaction. The event remains `RECEIVED` and can be retried.
- The applier receives the transaction and must not make external side effects. External side effects belong behind an idempotent outbox/provider adapter.

The worker drains bounded batches and reports the number of aggregates with deferred version gaps. It exits on persistent storage/applier errors so a process supervisor can restart or alert it.

## Delivery guarantees and limits

The intended boundary is at-least-once broker delivery plus idempotent durable Inbox intake. The broker adapter must ACK only after `ReceiveInboxEvent` commits. A crash after database commit but before broker ACK causes a duplicate delivery, which is safe for an exact event replay.

This slice does **not** select Kafka, NATS, Temporal or a cloud broker. It also does not implement quarantine replay tooling, cross-process broker fault injection, production metrics, worker lifecycle/readiness wiring or authenticated Runtime `StartRun` / `InspectRunIntent`.

Do not expose mutating public APIs or claim production readiness until those remaining P0 paths and the full Golden Path are verified.
