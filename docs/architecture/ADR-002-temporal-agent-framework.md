# ADR-002: Temporal Orchestrates; Agent Framework Decides

## Status
Proposed

## Decision
Use Temporal for durable workflow orchestration and a managed Python/TypeScript Agent Framework plugin for bounded reasoning turns. Runtime is the sole owner of platform Run lifecycle. A framework invocation returns a final response or typed ActionProposal. Protected tool effects are executed separately through EngageGuard.

## Workflow responsibilities
- Temporal Workflow: deterministic control flow, timers, waits, signals/updates, cancellation and orchestration decisions.
- Temporal Activity: network/database/provider I/O and calls to Runtime, Decision, EngageGuard, Compute.
- Agent Framework plugin: model reasoning and structured proposal generation within a bounded invocation.
- EngageGuard: canonical action, policy decision, approval, Permit, trusted execution and Operation Journal.

## Prohibited overlap
- Framework does not own platform Run/Task state or durable retry.
- Temporal Workflow does not perform direct I/O or model calls.
- Runtime and EngageGuard do not both retry the same side effect.
- Framework plugin does not directly execute privileged tools or hold long-lived credentials.

## Consequences
Workflow histories remain replayable. Frameworks can be replaced without migrating platform Run state. Each tool proposal is authorized against current policy immediately before execution.
