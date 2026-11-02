# Cross-Service Contracts — v0.2

Status: **PROPOSED / BLOCKED**. Service-owned protocol sources and cross-repository signoff are required before service-to-service implementation.

## Contract ownership

- This repository may define cross-service envelope and compatibility guidance, but each service owns its public OpenAPI document, event payload schema and database schema.
- ACP stores immutable source references and consumer-side compatibility evidence; it does not publish a second copy of another service's normative protocol.
- A service may keep internal fields, but cannot redefine a foreign identifier or write another service's domain facts.
- Cross-service protocol ownership and compatibility remain proposed until the relevant service owners ratify them under [ACP issue #3](https://github.com/avaargsh/agent-control-panel/issues/3).

## Decision protocols (BLOCKED — ACP-local copies are not normative)

The platform has two distinct candidate interfaces owned by `agent-decision`:

- The Go Decision Core owns the DecisionRecord API and durable decision ledger. Its service-owned OpenAPI candidate is pinned at [agent-decision commit bbdf45e](https://github.com/avaargsh/agent-decision/blob/bbdf45e415b310b421932977ca415419772dcaaa/api/openapi.yaml).
- Python/TypeScript framework adapters are a separate, bounded reasoning interface. They must not create a second DecisionRecord ledger or be treated as wire-compatible with the Go Core.

The candidate protocols are currently incompatible. The ACP-local files under `contracts/agent-decision/v0.1/` are historical compatibility snapshots only. They must not be treated as the canonical Decision API, copied as a service-owned protocol, or used to freeze an endpoint, payload union, limits or error envelope. The legacy plugin source is explicitly blocked in the governance registry.

**Implementation gate:** [agent-decision#9](https://github.com/avaargsh/agent-decision/issues/9) and [ACP#3](https://github.com/avaargsh/agent-control-panel/issues/3). Until the Decision and Runtime owners ratify one versioned Core contract and a separately versioned adapter contract, clients must not assume the ACP-local schemas represent either interface.

Decision invocation semantics remain a candidate ownership rule: Runtime creates one stable `invocation_id` for a logical turn; Decision owns the durable invocation ledger and exact result; retries reuse the same ID and canonical request digest. This does not freeze the HTTP request or response schema.

## Event envelope

Every event is a versioned fact, not a command with implicit exactly-once semantics.

```json
{
  "event_id": "uuid",
  "event_type": "agent.run-intent.created",
  "schema_version": 1,
  "producer": "agent-control-panel",
  "tenant_id": "uuid",
  "aggregate_type": "run_intent",
  "aggregate_id": "uuid",
  "aggregate_version": 1,
  "occurred_at": "RFC3339 timestamp",
  "correlation_id": "uuid",
  "causation_id": "uuid",
  "traceparent": "00-...",
  "data": {}
}
```

Required fields are validated at the consumer boundary. `causation_id` may be omitted only for an originating event. Trace context is propagated but is never an authorization input. Events contain references and bounded metadata, never secret bytes, Permit tokens or raw credentials.

## Delivery, ordering and recovery

1. Producer commits the domain mutation and Outbox row in one local database transaction; the aggregate version increments in that transaction.
2. Enforce at most one event for each producer + aggregate type + aggregate ID + aggregate version.
3. Publisher is at-least-once. A publish acknowledgement is not proof that a consumer committed.
4. Consumer durably inserts `event_id` into Inbox before applying the projection. Recommended Inbox states: `RECEIVED`, `APPLIED`, `QUARANTINED`.
5. Apply only the next contiguous `aggregate_version`. Projection update, consumer cursor advance and `APPLIED` transition commit atomically.
6. An event at or below the applied cursor is stale/duplicate and must not reapply. A different event claiming an already-used aggregate version is quarantined.
7. A version gap is durably retained as `RECEIVED`/deferred; do not advance the cursor or mark it APPLIED. Recover missing versions from producer replay or an authoritative snapshot, then apply in order.
8. Unknown breaking schema versions are quarantined and alerted. Additive optional fields may be ignored only where the schema permits it.
9. No distributed transaction and no exactly-once delivery or external-effect claim.

## Candidate identifier ownership (cross-service ratification pending)

See [Identifier Lifecycle](IDENTIFIER-LIFECYCLE.md) for the canonical creator, owner and retry rules.

- Control Plane: `run_intent_id`.
- Runtime: `run_id`, `workflow_id`, `run_attempt_id`; Runtime proposes to generate `invocation_id` and `guard_submission_key` before calling their owning services; EngageGuard owns the Action Operation and proposed `operation_id` (creation semantics remain blocked by G03).
- Decision: DecisionRecord, invocation ledger/result and `proposal_id`.
- EngageGuard: Action Operation record (wire field `operation_id`), `action_hash`, `permit_id`, `executor_attempt_id`.
- Compute Control Plane: `workload_id`, `allocation_id`, `compute_operation_id`.
- Temporal: native Workflow/Activity attempt metadata; do not serialize it as Runtime `run_attempt_id`.
- Provider: provider-native resource IDs/UIDs.
- Evidence producer: `evidence_digest` for its own immutable payload.

Do not reuse Guard `operation_id` for a Compute provider mutation. Do not use one generic `attempt_id` for Runtime, Temporal and executor attempts.

## Protected action identity and ActionHash (BLOCKED — G03)

The intended ownership boundary is:

- Runtime persists one stable `guard_submission_key` and reuses it as the HTTP `Idempotency-Key` for retries.
- EngageGuard owns the protected-action record, ActionHash, approval, Permit, Operation Journal and verified Receipt.
- The current EngageGuard ActionRequest draft and the ACP proposal disagree on whether `operation_id` is caller-supplied or generated by EngageGuard. The intended server-owned identity must not be implemented as an accepted wire contract until EngageGuard and Runtime ratify it.

The ActionHash preimage/domain separator is also unresolved. The ACP-local vector file and architecture drafts currently contain divergent domain-separator spellings. The local `contracts/engageguard/action-hash/v0.1/workspace-write-vectors.json` is therefore a comparison fixture only, not a normative source. Do not use its value, plain `json.Marshal`, or another local guess to authorize or verify protected actions.

**Implementation gate:** [EngageGuard#3](https://github.com/avaargsh/EngageGuard/issues/3) and [ACP#3](https://github.com/avaargsh/agent-control-panel/issues/3). The owning services must publish one versioned ActionRequest contract, trusted normalization rules, RFC 8785 JCS preimage and shared Go/Python/TypeScript vectors before clients or trusted executors rely on them.

## Compute and Sandbox boundary

An Agent-originated protected compute request is authorized at the EngageGuard action boundary. Compute Control Plane validates the delegated authorization at its API enforcement point, then creates and owns its own `compute_operation_id`, Workload, Allocation and provider journal. Guard operation_id and Compute compute_operation_id are linked by references/correlation only.

Internal Compute reconciler/provider operations use Compute service identity and its domain authorization policy. EngageGuard does not become a second writer for Kubernetes, Kueue or provider observations. SandboxProvider owns sandbox lifecycle and isolation; it may request capacity through Compute but must not create a duplicate Workload/Allocation for the same resource.

## Idempotency and API conventions

- Every mutating API accepts an idempotency key scoped to tenant + authenticated principal + operation.
- Persist the canonical request digest with the idempotency key in the same transaction as the resource and Outbox row; claim atomically under a unique constraint.
- Same key + same digest returns the original resource/result or current operation status. Same key + different digest returns HTTP 409 (`IDEMPOTENCY_KEY_REUSED`).
- In-flight duplicates return the same operation/status (202 + stable status reference where asynchronous); they never pass through to a second side effect.
- Retention exceeds the longest retry, workflow replay, event redelivery and manual recovery window.
- Versioned JSON APIs under `/api/v1`; OpenAPI is the public HTTP source of truth.
- Propagate request context, deadline, trace context and authenticated principal.
- Stable error envelope:

```json
{
  "code": "IDEMPOTENCY_KEY_REUSED",
  "message": "Idempotency key was reused with a different payload",
  "retryable": false,
  "correlation_id": "uuid",
  "details": {}
}
```

- HTTP: 400 malformed, 401 unauthenticated, 403 unauthorized, 404 absent, 409 idempotency/version conflict, 422 semantically invalid, 429 quota/rate limit, 503 unavailable, 500 internal.
- Error details are bounded and safe; never expose credentials, policy secrets, stack traces or unbounded provider payloads.

## Compatibility policy

- Unknown protocol versions and response discriminators fail closed.
- Additive optional fields require schema-compatible changes and shared cross-language fixtures.
- Removing/renaming fields, changing identifier ownership or changing state semantics requires a new major contract version and migration plan.
- Contract changes are reviewed here first, then propagated to consumers with matching conformance tests.
