# ADR-002: Temporal Orchestrates; Agent Framework Decides

## Status

Proposed v0.2. Normative for the Runtime / Decision boundary once the shared v0.1 plugin schemas are frozen.

## Decision

Use Temporal for durable workflow orchestration and a managed Python/TypeScript Agent Framework plugin for bounded reasoning turns. Runtime is the sole owner of platform Run lifecycle. A framework invocation returns exactly one v0.1 result: `final_response` or `action_proposals`. It does not execute privileged tools.

Protected effects are executed separately through EngageGuard and a trusted enforcement point.

## Responsibilities

- **Temporal Workflow:** deterministic lifecycle control flow, timers, waits, signals/updates, cancellation and orchestration decisions. No direct I/O, network calls, database calls, LLM calls, random values or wall-clock reads outside Temporal deterministic APIs.
- **Temporal Activity:** database, HTTP, model-plugin, EngageGuard and provider I/O. Activity inputs carry stable identifiers and explicit deadlines.
- **Agent Framework plugin:** model reasoning and structured proposal generation over Runtime-supplied bounded input/context within token, time, byte and proposal limits.
- **Agent Runtime:** canonical Run/Task/RunAttempt lifecycle, Workflow ID mapping, invocation/operation correlation and result projection.
- **EngageGuard:** action authentication, trusted canonicalization, ActionHash, policy decision, approval, Permit, trusted execution and Action Operation Journal.
- **Compute Control Plane:** Workload/Allocation and provider operation lifecycle; Kubernetes/Kueue/provider remain authoritative for actual admission and execution.

## Invocation contract

The canonical wire schemas are:

- `contracts/agent-decision/v0.1/decision-turn.schema.json`
- `contracts/agent-decision/v0.1/decision-result.schema.json`

Runtime creates one `invocation_id` per logical Decision Turn. Temporal Activity retries reuse the same ID and identical canonical request. Decision stores the request digest and exact response; same ID/same digest replays, same ID/different digest conflicts. The plugin cannot fetch opaque source references or use them as arbitrary network URLs; Runtime supplies the already-authorized projection inline.

The plugin's `allowed_capabilities` constrain proposal generation only. They do not grant execution permission. Every ActionProposal is untrusted and is revalidated by EngageGuard at execution time. Clarification is represented as a FinalResponse in v0.1; new response variants require a versioned schema change. Transport errors use the platform error envelope.

## Retry ownership

1. Temporal owns Workflow and Activity retry scheduling.
2. Decision owns invocation idempotency and exact result replay.
3. EngageGuard owns Action Operation idempotency, Permit claim and UNKNOWN reconciliation.
4. Compute Control Plane owns Compute Operation idempotency and provider reconciliation.
5. Runtime never generates a new invocation/operation ID merely because an Activity was retried.
6. An Activity may repeat a request with the same stable ID. It must not create a new logical side effect while the owning service reports UNKNOWN.
7. Retryable transport failures may be retried within the bounded Temporal policy. Protocol/schema/security failures are non-retryable and fail closed.
8. A protected action timeout is not a normal retry signal. Runtime queries EngageGuard using the same Action operation ID; only EngageGuard's reconciled state can authorize continuation.

## Prohibited overlap

- Framework does not own platform Run/Task state, durable retry policy, approval state or sandbox allocation.
- Temporal Workflow does not perform direct I/O or model calls.
- Runtime and EngageGuard do not independently retry the same external side effect.
- Framework plugin does not directly execute privileged tools, receive Permit tokens or hold long-lived credentials.
- Compute Control Plane does not become a second Action Operation authority; EngageGuard does not become a second provider-operation authority.

## Consequences

Workflow histories remain replayable. Frameworks can be replaced without migrating platform Run state. Decision execution can be retried without changing invocation identity. Action and compute ambiguity remain owned by the service that owns the corresponding operation journal.
