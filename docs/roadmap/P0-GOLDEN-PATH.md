# P0 Golden Path — Acceptance Contract

Status: implementation gate

## Outcome

A clean deployment accepts an immutable AgentBundle, creates an AgentRelease and stable Agent/Session/RunIntent identities, dispatches the RunIntent idempotently to Agent Runtime, and records the Runtime-created Run reference. Runtime/Temporal executes the Run. Protected effects are authorized and journaled by EngageGuard. Compute is requested through Compute Control Plane. Duplicate delivery and process restart do not create duplicate logical Runs or blind external side effects.

## Canonical flow

1. Submit AgentBundle; validate schema and compute immutable content digest.
2. Create AgentRelease referencing exact bundle digest and release intent.
3. Resolve AgentIdentity, tenant/project scope and authorization from verified principal.
4. Create Session and RunIntent. Persist client idempotency key and canonical request digest.
5. In one transaction, persist RunIntent and its Outbox event.
6. Dispatcher claims RunIntent using a lease and fencing token; call Runtime `StartRun` with the same `run_intent_id` and digest on every retry.
7. Runtime's unique idempotency record is authoritative. Runtime creates `run_id` and deterministic `workflow_id`; Control Plane never generates either.
8. A matching Runtime receipt moves RunIntent to ACCEPTED. A lost/ambiguous ACK moves it to UNKNOWN; query Runtime by RunIntent ID and digest. An authoritative final not-found may retry the exact same request/key. A mismatch goes to MANUAL_REVIEW.
9. Temporal owns durable workflow history, retries, waits, signals, cancellation and replay. Runtime owns Run/Task/Attempt state and maps workflow outcomes to Run lifecycle.
10. Decision plugin receives one bounded invocation and returns FinalResponse or typed ActionProposal. It has no direct privileged credentials or execution authority.
11. ActionProposal is canonicalized and authorized by EngageGuard. ActionHash, Permit and Operation Journal belong to EngageGuard; trusted executor performs the side effect.
12. When compute is required, Runtime requests a Workload using originating Run ID and immutable requirements. Compute Control Plane owns provider selection, Workload, Allocation and provider operation journal. Kueue admits; Kubernetes schedules.
13. Runtime records workflow outcome; Control Plane updates only its read-only Run projection. Evidence links exact release, intent, runtime Run, action/compute operations and provider observations.

## State ownership

- RunIntent state: Agent Control Plane.
- Run / Task / Attempt lifecycle: Agent Runtime.
- Temporal workflow history: Temporal.
- Decision invocation: agent-decision.
- Action / Permit / operation ambiguity: EngageGuard.
- Workload / Allocation / compute provider operation: Compute Control Plane.
- Actual admission, Pod placement and provider resources: Kueue / Kubernetes / provider.

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
- Runtime duplicate StartRun with same key/digest returns the same Run ID.
- Lost ACK → UNKNOWN → RECONCILING → found / authoritative not-found / mismatch.
- Runtime rejects same idempotency key with a different digest.
- Temporal start uses stable Runtime-generated workflow ID and duplicate-start policy.
- Protected action retry is owned by EngageGuard, not Runtime/Temporal.
- Tenant/project boundary and secret-hygiene tests.
- Fresh-process restart at each critical window; inspect persisted state and evidence.
- Read projection cannot write Runtime-owned Run lifecycle.

## Exit gate

P0 passes only when persistence, authorization, outbox/inbox, dispatch recovery and failure-mode tests run in a clean checkout. A health endpoint or pure state-machine unit test is not a Golden Path.
