# ADR-002: Temporal Orchestrates; Agent Framework Decides

## Status

Proposed v0.2. The service-owned Decision Core and framework-adapter boundaries are candidates; exact wire protocols remain blocked pending agent-decision #9.

## Decision

Use Temporal for durable workflow orchestration. Runtime is the sole owner of platform Run lifecycle and invokes the Go Decision Core API owned by agent-decision; that Core may use a separately versioned Python/TypeScript framework adapter for bounded reasoning. The Core and adapter are different interfaces and must not share an assumed v0.1 wire contract. Framework adapters do not execute privileged tools.

Protected effects are executed separately through EngageGuard and a trusted enforcement point.

## Responsibilities

- **Temporal Workflow:** deterministic lifecycle control flow, timers, waits, signals/updates, cancellation and orchestration decisions. No direct I/O, network calls, database calls, LLM calls, random values or wall-clock reads outside Temporal deterministic APIs.
- **Temporal Activity:** database, HTTP, model-plugin, EngageGuard and provider I/O. Activity inputs carry stable identifiers and explicit deadlines.
- **Agent Framework plugin:** model reasoning and structured proposal generation over Runtime-supplied bounded input/context within token, time, byte and proposal limits.
- **Agent Runtime:** canonical Run/Task/RunAttempt lifecycle, Workflow ID mapping, invocation/operation correlation and result projection.
- **EngageGuard:** action authentication, trusted canonicalization, ActionHash, policy decision, approval, Permit, trusted execution and Action Operation Journal.
- **Compute Control Plane:** Workload/Allocation and provider operation lifecycle; Kubernetes/Kueue/provider remain authoritative for actual admission and execution.

## Invocation contract

The canonical protocol source belongs to agent-decision. Its Go Core OpenAPI candidate is pinned in the governance registry; the framework-adapter protocol is a separate interface and is not assumed to match the Core API.

ACP-local files under `contracts/agent-decision/v0.1/` are historical compatibility snapshots only, not canonical schemas. Do not infer a frozen endpoint, payload union, field set, limit or error envelope from them. The Go Core and adapter contracts must be independently versioned and ratified by agent-decision and Runtime (G02).

Runtime creates one `invocation_id` per logical Decision Turn. Temporal Activity retries reuse the same ID and canonical request digest. Decision owns the durable invocation ledger and exact result; same ID/same digest replays, same ID/different digest conflicts. Runtime supplies context that has already passed its authorization and projection policy. A framework adapter is a bounded reasoning component, not a second Decision ledger.

Any ActionProposal is untrusted input and is revalidated by EngageGuard before a protected effect. Proposal discriminators and clarification variants are part of the unratified adapter protocol; this ADR does not freeze them.

## Retry ownership

1. Temporal owns Workflow and Activity retry scheduling.
2. Decision owns invocation idempotency and exact result replay.
3. EngageGuard owns Action Operation idempotency, Permit claim and UNKNOWN reconciliation.
4. Compute Control Plane owns Compute Operation idempotency and provider reconciliation.
5. Runtime never generates a new invocation_id or guard_submission_key merely because an Activity was retried; EngageGuard owns operation_id.
6. An Activity may repeat a request with the same stable ID. It must not create a new logical side effect while the owning service reports UNKNOWN.
7. Retryable transport failures may be retried within the bounded Temporal policy. Protocol/schema/security failures are non-retryable and fail closed.
8. A protected action timeout is not a normal retry signal. Runtime reuses the same guard_submission_key and consults EngageGuard's authoritative operation lookup using the ratified contract; only EngageGuard's reconciled state can authorize continuation.

## Prohibited overlap

- Framework does not own platform Run/Task state, durable retry policy, approval state or sandbox allocation.
- Temporal Workflow does not perform direct I/O or model calls.
- Runtime and EngageGuard do not independently retry the same external side effect.
- Framework plugin does not directly execute privileged tools, receive Permit tokens or hold long-lived credentials.
- Compute Control Plane does not become a second Action Operation authority; EngageGuard does not become a second provider-operation authority.

## Consequences

Workflow histories remain replayable. Frameworks can be replaced without migrating platform Run state. Decision execution can be retried without changing invocation identity. Action and compute ambiguity remain owned by the service that owns the corresponding operation journal.
