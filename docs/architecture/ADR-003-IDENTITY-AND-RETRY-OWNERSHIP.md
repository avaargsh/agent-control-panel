# ADR-003: Canonical Identity, Idempotency and Retry Ownership

Status: Proposed v0.2

## Context

The first implementation draft conflated RunIntent with Run identity, assigned a Workflow ID before Runtime created a Run, used a boolean to authorize UNKNOWN recovery, and did not express lease/fencing ownership. Similar ambiguity exists when multiple layers retry the same external effect.

## Decision

### Identity

- Agent Control Plane creates immutable `run_intent_id` and stores tenant/principal-scoped idempotency key plus canonical request digest.
- Agent Runtime is the sole creator/owner of `run_id`, `workflow_id` and `attempt_id`.
- Runtime derives a stable Temporal Workflow ID from canonical `run_id`; a StartRun retry with the same RunIntent ID/digest returns the same Run.
- Control Plane stores Runtime identifiers only after a matching receipt and exposes them as a read-only projection.
- Cancellation is a separate Runtime command, not a RunIntent terminal state.

### Dispatch and recovery

RunIntent dispatch is a control-plane handshake, not Run execution state:

```text
PENDING → DISPATCHING → ACCEPTED | REJECTED | UNKNOWN
UNKNOWN → RECONCILING → ACCEPTED | REJECTED | PENDING | MANUAL_REVIEW
```

- Dispatcher claim is persisted with lease owner, lease expiry, version and monotonically increasing fencing token.
- Expired dispatch/reconciliation leases become UNKNOWN; a stale worker cannot commit a receipt.
- ACCEPTED requires Runtime's matching `run_intent_id`, request digest, `run_id` and `workflow_id`.
- REJECTED is allowed only for a definitive pre-creation rejection with a stable reason code.
- UNKNOWN is never blindly retried. Runtime is queried by RunIntent ID and digest.
- Only an authoritative final not-found from Runtime's idempotency registry returns the intent to PENDING; retry reuses the exact same key and digest.
- Conflicting IDs/digests or contradictory provider evidence enter MANUAL_REVIEW.

### Retry ownership

- Temporal owns durable workflow orchestration and activity retry for operations that are safe/idempotent.
- Runtime owns Run/Task/Attempt lifecycle and Temporal integration.
- agent-decision owns bounded framework invocation; it returns FinalResponse or ActionProposal only.
- EngageGuard owns ActionHash, approval, Permit, protected-action Operation Journal and effect reconciliation.
- Compute Control Plane owns compute provider operation journal and provider reconciliation.
- A caller may retry an API request only with the same idempotency key and canonical digest. No two services independently retry the same side effect.

## Consequences

- RunIntent cannot be mistaken for a Run, and a workflow ID cannot be invented by the Control Plane.
- Leases and fencing prevent a stale dispatcher from overwriting a newer reconciliation result.
- Exactly-once external effects are not promised; stable idempotency plus inspect/reconciliation is required.
- Runtime must expose an authoritative lookup by RunIntent ID and request digest before the Control Plane can safely resolve UNKNOWN.
