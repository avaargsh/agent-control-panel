# P0 Golden Path — Acceptance Contract

Status: proposed acceptance gate; G02/G03 service-owned protocol details remain blocked.

## Outcome

A clean deployment accepts an immutable AgentBundle, creates an AgentRelease and stable Agent/Session/RunIntent identities, dispatches the RunIntent idempotently to Agent Runtime, and records the Runtime-created Run reference. Runtime/Temporal executes the Run. Protected effects are authorized and journaled by EngageGuard. Compute is requested through Compute Control Plane. Duplicate delivery and process restart do not create duplicate logical Runs or blind external side effects.

## Canonical flow

1. Submit AgentBundle; validate schema and compute immutable content digest.
2. Create AgentRelease referencing exact bundle digest and release intent.
3. Resolve AgentIdentity, tenant/project scope and authorization from verified principal.
4. Create Session and RunIntent. Persist client idempotency key and canonical request digest.
5. In one transaction, persist RunIntent and its Outbox event.
6. Dispatcher claims RunIntent using a lease and fencing token; call Runtime `StartRun` with the same `run_intent_id` and digest on every retry.
7. Runtime's unique idempotency record is authoritative. Runtime creates `run_id` and `workflow_id = "agent-run/v1/" + run_id`; Control Plane never generates either.
8. A matching Runtime receipt moves RunIntent to ACCEPTED. A lost/ambiguous ACK moves it to UNKNOWN; query Runtime by RunIntent ID and digest. An authoritative final not-found may retry the exact same request/key. A mismatch goes to MANUAL_REVIEW.
9. Temporal owns durable workflow history, retries, waits, signals, cancellation and replay. Runtime owns Run/Task/RunAttempt state and maps workflow outcomes to Run lifecycle.
10. Runtime invokes the service-owned Decision Core API. A separately versioned framework adapter may provide bounded reasoning; the Go Core and adapter contracts must be ratified independently under agent-decision #9. ACP-local v0.1 schemas are historical compatibility snapshots only. No specific response union is frozen here.
11. Runtime persists each accepted proposal and one stable `guard_submission_key`; EngageGuard owns the Action Operation and proposed `operation_id`. EngageGuard canonicalizes and authorizes the action, computes ActionHash, binds Approval/Permit/Receipt, and delegates the effect to a trusted enforcement point. Operation ID creation and ActionHash preimage remain blocked under EngageGuard #3.
12. When compute is required, Runtime requests a Workload using originating Run ID and immutable requirements. Compute Control Plane owns provider selection, Workload, Allocation and `compute_operation_id`. Kueue admits; Kubernetes schedules.
13. Runtime records workflow outcome; Control Plane updates only its read-only Run projection. Evidence links exact release, intent, Runtime Run, Action/Compute operations and provider observations.

## State ownership

- RunIntent state: Agent Control Plane.
- Run / Task / RunAttempt lifecycle: Agent Runtime.
- Temporal workflow history and native Activity attempts: Temporal.
- Decision invocation ledger/result: agent-decision.
- Action / ActionHash / Permit / Action Operation: EngageGuard; operation_id creation semantics and ActionHash preimage remain blocked under G03.
- Workload / Allocation / Compute operation: Compute Control Plane.
- Actual admission, Pod placement and provider resources: Kueue / Kubernetes / provider.
- Sandbox lifecycle and isolation: selected Sandbox Provider.

## RunIntent dispatch state machine

```text
PENDING → DISPATCHING → ACCEPTED | REJECTED | UNKNOWN
UNKNOWN → RECONCILING → ACCEPTED | REJECTED | PENDING | MANUAL_REVIEW
```

PENDING after reconciliation means Runtime's authoritative idempotency registry confirmed no Run was created; retry the same RunIntent ID and request digest. It does not mean mint a new intent. Cancellation is a Runtime command, not a terminal RunIntent state.

## Required tests

- Same tenant/principal/key/digest returns one intent; same key with different digest returns 409.
- Outbox atomicity and publisher duplicate delivery.
- Inbox dedupe, aggregate-version duplicate and version-gap handling.
- RunIntent state transition, lease expiry, stale fencing token and concurrent dispatch.
- Runtime duplicate StartRun with same key/digest returns the same Run ID and Workflow ID.
- Lost ACK → UNKNOWN → RECONCILING → found / authoritative not-found / mismatch.
- Runtime rejects same idempotency key with a different digest.
- Temporal start uses stable Runtime-generated Workflow ID and duplicate-start policy.
- Decision Core and framework-adapter requests/results pass their separately versioned service-owned contract fixtures after G02 ratification; same invocation ID/digest replays the exact Decision result.
- Protected action retry is owned by EngageGuard, not Runtime/Temporal.
- After G03 ratification, ActionHash golden vectors match across Go/Python/TypeScript using the service-owned RFC 8785 preimage.
- Tenant/project boundary and secret-hygiene tests.
- Fresh-process restart at each critical window; inspect persisted state and evidence.
- Read projection cannot write Runtime-owned Run lifecycle.

## Exit gate

P0 passes only when persistence, authorization, outbox/inbox, dispatch recovery and failure-mode tests run in a clean checkout. A health endpoint or pure state-machine unit test is not a Golden Path.
