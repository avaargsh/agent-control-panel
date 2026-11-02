# Cross-Service Contracts — v0.1

Status: Proposed implementation contract. The JSON Schemas under `contracts/agent-decision/v0.1/` are normative for the Decision plugin wire payload.

## Contract ownership

- This repository owns the platform-wide envelope, identifier naming rules, compatibility policy and cross-service invariants.
- Each service owns its public OpenAPI document, database schema and service-specific event payloads.
- The Decision request/response schemas in this repository are the single canonical v0.1 wire contract. Runtime, Decision and future TypeScript workers must consume the same schemas/test vectors; do not maintain a second hand-authored protocol definition.
- A service may add private internal fields, but must not change a public payload or reinterpret an identifier without a versioned contract change.

## Agent Decision Plugin Protocol v0.1

Canonical schemas:

- `contracts/agent-decision/v0.1/decision-turn.schema.json`
- `contracts/agent-decision/v0.1/decision-result.schema.json`

Transport is HTTP JSON at `POST /api/v1/decision-turns` for v0.1. gRPC or streaming is deferred until measured requirements justify another transport.

### Request

The required request fields are defined by the request schema:

- `protocol_version`, stable `invocation_id`
- `tenant_id`, `agent_id`, `bundle_digest`, `release_id`
- `session_id`, `run_id`, `turn_id`
- resolved `user_input` and bounded `context_projection`
- `allowed_capabilities` as exact capability ID/version pairs
- absolute `deadline` and W3C `trace_context`

The Runtime resolves authorized input/context before invocation. The plugin receives the projected content inline; source references are opaque provenance identifiers only and must not be dereferenced by the plugin. This avoids granting plugins arbitrary storage access or requiring provider credentials.

The plugin may reason only over the supplied projection and capabilities. `allowed_capabilities` is a decision constraint, not an authorization grant or Permit.

### Response union

The response uses the explicit `kind` discriminator:

- `final_response`: answer text, optional structured output and evidence references.
- `action_proposals`: one or more typed proposals; arguments are untrusted.
- `needs_input`: prompt and missing fields; Runtime maps this to its waiting/input lifecycle.
- `decision_error`: stable code, retryability and safe message.

A proposal never asserts that an action is authorized, approved, executed or safe. The plugin must never return `action_hash`, Permit material, executable bearer credentials, provider secrets or claims of successful side effects.

### Invocation idempotency and retry

- Runtime creates `invocation_id` once for a logical Decision Turn and reuses it on every Temporal Activity retry.
- Decision persists the canonical request digest and exact response keyed by `invocation_id`.
- Same `invocation_id` + same request digest replays the exact stored response.
- Same `invocation_id` + different request digest returns HTTP 409 and is never silently recomputed.
- The result record must outlive the maximum Temporal retry/replay/redelivery window. Do not use a short TTL that can expire while a Run can still be replayed.
- A deterministic smoke-test adapter may omit model execution, but it is explicitly a protocol subset until it passes both canonical schemas and idempotency tests.

### Transport and limits

- Maximum request body: 1 MiB; maximum response body: 256 KiB.
- Context projection: at most 128 items; capability list: at most 64; response proposals: at most 16.
- Enforce the absolute deadline and cancellation. Runtime's Activity timeout is not a substitute for the request deadline.
- Production traffic requires authenticated workload identity and an authenticated encrypted channel (mTLS or equivalent). Plain HTTP is permitted only on loopback for local development.
- The plugin has no provider credentials, Permit tokens, privileged network egress or direct privileged tool execution.
- HTTP 200 carries a schema-valid Decision result union. HTTP 400/413/415/422 indicate invalid request; 409 indicates invocation idempotency conflict; 429/5xx are transport/service failures. Error bodies use the platform error envelope below.
- Runtime validates response size, content type, schema, protocol version and matching `invocation_id`; malformed or unknown variants fail closed.

## Event envelope

Every service event uses this envelope (service-specific `data` is separately schema-versioned):

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
  "data": {}
}
```

### Event write and consume rules

1. The authoritative producer commits its domain mutation and outbox row in one local database transaction. It increments `aggregate_version` in that same transaction.
2. At most one event is emitted for a given producer + aggregate type + aggregate ID + aggregate version. Enforce a local unique constraint.
3. Delivery is at-least-once and may be duplicated or reordered. There is no exactly-once delivery claim and no distributed transaction.
4. Consumer first durably inserts the event into its inbox under a unique `event_id`; inbox receipt and projection application are separate durable states.
5. Apply an event only when its `aggregate_version` is the next contiguous version for that aggregate. Apply the projection update, advance the consumer cursor and mark the inbox row APPLIED atomically.
6. An event with a version at or below the applied cursor is a duplicate/stale delivery and must not reapply the mutation. A different event claiming an already-used aggregate version is quarantined as a producer contract violation.
7. An event ahead of the next expected version is retained as RECEIVED/DEFERRED; do not advance the cursor or mark it APPLIED. Recover the gap from producer replay or an authoritative snapshot, then apply in order.
8. Unknown breaking schema versions are quarantined and alerted; additive optional fields may be ignored only where the event schema explicitly allows them.
9. Events contain references and bounded metadata, never secret bytes, Permit tokens or raw credentials.

Recommended inbox states: `RECEIVED`, `APPLIED`, `QUARANTINED`. A gap is a reason to defer application, not to discard the event.

## Required identifier semantics

See [Identifier Lifecycle](IDENTIFIER-LIFECYCLE.md) for the authoritative producer and retry rules.

- `run_intent_id`: agent-control-panel.
- `run_id`, `workflow_id`, `run_attempt_id`: agent-runtime (Temporal owns workflow history).
- `invocation_id`, `proposal_id`, DecisionRecord: agent-decision.
- `action_operation_id` (wire field `operation_id`), `action_hash`, `executor_attempt_id`: EngageGuard / trusted executor.
- `compute_operation_id`, `allocation_id`: compute-control-panel.
- `provider_resource_id`: provider-native reference.
- `evidence_digest`: calculated and owned by the service that produces the immutable evidence.

Do not use one generic `attempt_id` for Runtime, Temporal and executor attempts. Do not reuse the Action `operation_id` for a Compute provider operation.

## Action authorization and execution

The canonical flow is:

```text
Decision ActionProposal
  -> Runtime persists proposal
  -> Runtime assigns stable action_operation_id / operation_id
  -> EngageGuard authenticates caller and resolves trusted binding
  -> EngageGuard canonicalizes action and computes action_hash
  -> policy decision / approval bound to action_hash
  -> one-time audience- and operation-bound Permit
  -> trusted enforcement point validates Permit + action_hash
  -> external effect
  -> EngageGuard Operation Journal reconciliation + verified Receipt
  -> Runtime records Receipt against the Run
```

- Runtime reuses the same `operation_id` and semantically identical request on retry.
- EngageGuard computes `action_hash` only after trusted normalization; a plugin-supplied hash is ignored/rejected.
- Cross-language canonicalization uses RFC 8785 JSON Canonicalization Scheme (JCS), UTF-8 and a versioned domain separator before SHA-256. Plain Go `json.Marshal` is not the cross-language contract.
- Same `operation_id` with a different canonical action/hash is HTTP 409 and fail-closed.
- Approval, Permit, executor claim and Receipt bind the same operation and hash. Receipt includes `executor_attempt_id`, not a generic `attempt_id`.

## Compute operation boundary

An Agent-originated protected compute request is authorized by EngageGuard at the action boundary. Compute Control Plane validates the delegated authorization at its API enforcement point, then creates and owns a distinct `compute_operation_id`, Workload, Allocation and provider journal. The Action Operation and Compute Operation are linked by references/correlation only.

Internal Compute reconciler/provider operations use the Compute service identity and Compute's own authorization policy; they do not create a second EngageGuard Action Operation for every controller loop. EngageGuard never becomes the authority for Kubernetes, Kueue or provider observations.

## API conventions

- Versioned HTTP JSON APIs under `/api/v1`; OpenAPI is the source of truth for public HTTP APIs.
- Propagate request context, absolute deadline, W3C trace context and authenticated principal.
- Stable error envelope:

```json
{
  "code": "CONFLICT",
  "message": "Idempotency key was reused with a different payload",
  "retryable": false,
  "correlation_id": "uuid",
  "details": {}
}
```

- Error details are safe, bounded and never contain credentials, policy secrets or raw provider responses.
- State-changing APIs require an idempotency key scoped to tenant + authenticated principal + operation. Persist the canonical request digest and claim the key atomically under a unique constraint.
- Same key + same canonical payload returns the original resource/operation or its current status. Same key + different payload returns 409.
- In-flight duplicates return the existing operation/status (202 + stable status reference where asynchronous); they never pass through to a second side effect.
- Retention must exceed the longest retry, workflow replay, event redelivery and manual recovery window.
- Use explicit pagination, request/body limits, optimistic aggregate versions and structured 409 version conflicts.

## Compatibility policy

- The v0.1 schema is strict: unknown protocol versions and unknown response discriminators fail closed.
- Additive optional fields require a schema-compatible change and cross-language fixtures before adoption.
- Removing/renaming fields, changing field meaning, changing identifier ownership or changing state semantics requires a new protocol major version and an explicit migration plan.
- Contract changes are reviewed in this repository first, then propagated to each consumer repository with matching contract tests.
