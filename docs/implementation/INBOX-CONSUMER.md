# PostgreSQL Inbox Consumer — P0

Status: **durable Inbox intake and ordered projection worker implemented in a stacked Draft PR; transport adapter and operator replay remain pending**.

## Receive contract

The transport adapter must call `Repository.ReceiveInboxEvent` and commit the event to PostgreSQL **before** acknowledging the broker delivery.

- Delivery identity is scoped by `(consumer_name,event_id)`.
- Exact redelivery is idempotent.
- Reuse of an event ID with different persisted envelope fields or payload is surfaced as an identity conflict. A not-yet-applied stored event is quarantined.
- Aggregate-version claims are scoped by consumer, tenant, aggregate type, aggregate ID and version.
- A competing event for an already-claimed aggregate version is retained as `QUARANTINED`; it never replaces the first claim.
- Cursor rows are initialized in the same transaction as the first accepted event.

The Inbox schema persists producer, event type, schema version, tenant, aggregate identity/version and JSON payload. Transport metadata not represented by the schema is not reconstructed by the applier.

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
