# Cross-Service Contracts — v0.2

Status: Proposed; freeze before service-to-service implementation.

## Contract ownership

- This repository owns the platform-wide event envelope, identifier namespaces, idempotency/error semantics and compatibility rules.
- Each service owns its OpenAPI document, event payload schemas and database schema.
- The Decision plugin wire payload is defined only by the canonical v0.1 JSON Schemas in this repository. Runtime and Python/TypeScript plugins must validate against the same files and shared vectors; do not maintain private protocol forks.
- A service may keep internal fields, but cannot redefine a foreign identifier or write another service's domain facts.

## Agent Decision Plugin Protocol v0.1

Canonical schemas:

- `contracts/agent-decision/v0.1/decision-turn.schema.json`
- `contracts/agent-decision/v0.1/decision-result.schema.json`

Transport: HTTP JSON `POST /api/v1/decision-turns`. gRPC/streaming is deferred until measured throughput or streaming requirements justify another transport.

### Request

The required fields are defined by the request schema: `protocol_version`, stable `invocation_id`, tenant/Agent/Bundle/Release/Session/Run/Turn identity, resolved `user_input`, bounded `context_projection`, exact `allowed_capabilities` ID/version pairs, absolute `deadline` and W3C `trace_context`.

Runtime resolves authorization and context before invoking the plugin. Projected content is supplied inline. Source references are opaque provenance identifiers only; plugins must not dereference them or use them as network URLs. `tenant_id` in the body is context, not proof of identity; the plugin must bind it to the authenticated Runtime workload identity.

### Response

The v0.1 union has exactly two variants, discriminated by `kind`:

- `final_response`: text, optional structured output and evidence references.
- `action_proposals`: one or more typed proposals with capability ID/version, arguments, target reference and rationale reference.

A proposal is untrusted input. It does not assert authorization, approval, Permit issuance or successful execution. The plugin must never return ActionHash, Permit material, bearer credentials, provider secrets or claims that a protected effect has already occurred.

Clarification requests are expressed as a FinalResponse for v0.1; a separate NeedsInput variant requires a versioned protocol extension. Transport/service errors use the platform error envelope and are not a third Decision result variant.

### Invocation identity, idempotency and retry

- Runtime generates `invocation_id` once for a logical Decision Turn and reuses it for every Temporal Activity retry.
- Decision owns the invocation ledger and persists canonical request digest plus the exact result.
- Same `invocation_id` + same digest replays the exact stored result.
- Same `invocation_id` + different digest returns HTTP 409; never recompute silently.
- Result retention must outlive the maximum workflow retry, replay and event redelivery window.
- The current Go/Python smoke implementation is a deliberately smaller test profile, not full v0.1 conformance until it consumes these schemas and shared fixtures.

### Transport and limits

- Maximum request body: 1 MiB; maximum response body: 256 KiB.
- Context projection: at most 128 items; capabilities: at most 64; proposals: at most 16.
- Enforce absolute deadline and cancellation. A Temporal Activity timeout does not replace the request deadline.
- Production traffic requires authenticated workload identity and an authenticated encrypted channel (mTLS or equivalent). Plain HTTP is loopback-only for local development.
- Plugins have no provider credentials, Permit tokens, privileged network egress or direct privileged tool execution.
- HTTP 200 carries a schema-valid Decision result. HTTP 400/413/415/422 indicate invalid request; 409 indicates invocation idempotency conflict; 429/5xx indicate service/transport failure. Error bodies use the platform error envelope.
- Runtime validates content type, response size, schema, protocol version and matching `invocation_id`; unknown variants fail closed.

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

## Identifier ownership

See [Identifier Lifecycle](IDENTIFIER-LIFECYCLE.md) for the canonical creator, owner and retry rules.

- Control Plane: `run_intent_id`.
- Runtime: `run_id`, `workflow_id`, `run_attempt_id`; Runtime generates `invocation_id` and `action_operation_id` before calling their owning services.
- Decision: DecisionRecord, invocation ledger/result and `proposal_id`.
- EngageGuard: Action Operation record (wire field `operation_id`), `action_hash`, `permit_id`, `executor_attempt_id`.
- Compute Control Plane: `workload_id`, `allocation_id`, `compute_operation_id`.
- Temporal: native Workflow/Activity attempt metadata; do not serialize it as Runtime `run_attempt_id`.
- Provider: provider-native resource IDs/UIDs.
- Evidence producer: `evidence_digest` for its own immutable payload.

Do not reuse Action `operation_id` for a Compute provider mutation. Do not use one generic `attempt_id` for Runtime, Temporal and executor attempts.

## Action authorization and execution

```text
Decision ActionProposal
  -> Runtime persists accepted proposal
  -> Runtime assigns stable action_operation_id (wire: operation_id)
  -> EngageGuard authenticates caller and resolves trusted binding
  -> EngageGuard validates and canonicalizes action
  -> EngageGuard computes action_hash
  -> policy decision / approval bound to action_hash
  -> one-time audience- and operation-bound Permit
  -> trusted enforcement point verifies Permit + action_hash
  -> external effect
  -> EngageGuard Operation Journal reconciliation + verified Receipt
  -> Runtime records Receipt against Run
```

- Runtime reuses the same operation ID and semantically identical request on every retry.
- EngageGuard computes ActionHash only after trusted normalization; plugin-supplied hashes are rejected/ignored.
- Canonicalization is RFC 8785 JCS. Exact preimage: UTF-8 bytes `engageguard/action-hash/v1\\0` followed by JCS canonical JSON bytes. SHA-256 digest is 64 lowercase hexadecimal characters. Plain Go `json.Marshal` is not the cross-language contract.
- Shared vectors: `contracts/engageguard/action-hash/v0.1/workspace-write-vectors.json`.
- Same Action `operation_id` with a different canonical action/hash returns 409 and fails closed.
- Approval, Permit, executor claim and Receipt bind the same operation and hash. Receipt uses `executor_attempt_id`, not a generic `attempt_id`.

## Compute and Sandbox boundary

An Agent-originated protected compute request is authorized at the EngageGuard action boundary. Compute Control Plane validates the delegated authorization at its API enforcement point, then creates and owns its own `compute_operation_id`, Workload, Allocation and provider journal. Action and Compute operations are linked by references/correlation only.

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
