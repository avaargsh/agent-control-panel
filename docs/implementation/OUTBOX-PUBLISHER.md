# PostgreSQL Outbox Publisher — P0

Status: **generic Outbox dispatcher implemented; broker adapter and Inbox consumer remain pending**.

## Contract

The PostgreSQL Outbox is the durable boundary between Control Plane writes and
external delivery. RunIntent creation and its event are committed in the same
transaction. The dispatcher then claims a bounded batch, commits its leases,
publishes outside the transaction, and acknowledges only after the transport
reports success.

The dispatcher intentionally depends on the small `EventPublisher`
interface. The first implementation does not choose Kafka, NATS, Temporal, or
a cloud queue for the deployment. A transport adapter must preserve the event
ID and report success only after the transport acknowledges the message.

## Delivery guarantees

- **At least once.** A crash after broker acceptance but before database ACK can
  cause a duplicate publish. Consumers must deduplicate by `event_id`.
- **Bounded claims.** Each claim uses `FOR UPDATE SKIP LOCKED`, a batch limit,
  an owner and a lease expiry.
- **Per-aggregate ordering.** A version is claimable only after every earlier event for the same producer, tenant, aggregate type and aggregate ID is `PUBLISHED`. A leased, retrying or quarantined predecessor blocks later versions; quarantine requires explicit operator resolution before the aggregate stream can advance. Independent aggregates remain concurrent.
- **Fenced ACK/retry.** Every claim increments the persisted attempt counter.
  ACK and retry require event ID, lease owner and exact attempt; a stale claim
  cannot complete a newer claim even when a worker reuses its owner name.
- **Expired lease recovery.** Expired claims are eligible for reclamation.
  If the final permitted attempt expires, the event is quarantined because the
  transport may have accepted it before the worker crashed.
- **Retry safety.** Failed publishes are rescheduled with capped exponential
  backoff. Only stable error codes are persisted; raw publisher errors are
  never copied into the database.
- **No false success.** An event becomes `PUBLISHED` only after a publisher
  success and a matching database lease acknowledgement.

## Worker configuration

Every worker uses an owner unique to its process instance where possible.
The attempt fence remains authoritative if an owner value is accidentally
reused.

Configure:

- `BatchSize`: 1–1000 events per pass.
- `LeaseTTL`: must exceed `(BatchSize + 1) × PublishTimeout`; sequential batch
  publication needs a full per-event timeout budget plus one extra timeout-sized
  margin for database ACK and loop overhead.
- `PublishTimeout`: per-event transport timeout and strictly shorter than
  the lease TTL.
- `MaxAttempts`: maximum number of claim/publish attempts.
- `BaseBackoff` / `MaxBackoff`: capped exponential retry delay.
- `PollInterval`: idle polling cadence.

The worker's `DispatchOnce` method is appropriate for an external supervisor;
`Run` polls until context cancellation and exits on persistent storage or
lease errors so the process supervisor can restart or alert it.

## Explicit remaining work

- Implement and configure a production `EventPublisher` adapter with transport
  authentication, TLS, schema compatibility and broker observability.
- Implement Inbox persistence/consumer worker: deduplication, tenant-scoped
  aggregate-version claims, cursor sequencing, gap recovery and quarantine.
- Wire worker lifecycle, readiness and shutdown into service deployment.
- Add cross-process broker/PostgreSQL fault-injection tests for the
  publish-success/ACK-loss window and broker duplicate delivery.
- Define quarantine inspection, replay authorization and operator runbooks.

Until the production publisher adapter, authenticated Runtime dispatch adapter
and Inbox recovery path are integrated, do not expose mutating public APIs.
