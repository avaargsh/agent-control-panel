# Agent Control Panel

Agent Infrastructure Control Plane for self-hosted, Kubernetes-first Agent workloads.

## Product boundary

This repository contains the Go Agent Control Plane API and reconciliation services. A Web Console may be a client of these APIs, but does not own business state.

The Control Plane owns Tenant/Project scope (initially), Agent identity, AgentBundle, AgentRelease, canonical Session identity, RunIntent, desired configuration, release governance and federation bindings.

Agent Runtime owns Run/Task/RunAttempt execution lifecycle. Temporal owns durable workflow history and native retry/replay metadata. EngageGuard owns Action authorization, ActionHash, Approval, Permit and the Action Operation Journal. Compute Control Plane owns Workload, Allocation and Compute Operation. Kubernetes/Kueue and the selected providers own actual scheduling and execution state.

## Golden Path

`AgentBundle → AgentRelease → Session → RunIntent → Runtime / Temporal → Decision Plugin → EngageGuard → Trusted Enforcement Point → Receipt / Evidence`

Compute allocation is a separately owned service flow linked by Workload/Allocation references; it is not a second Run or Action state machine.

## Core resources

| Resource | Authority |
|---|---|
| Tenant / Project | This Control Plane (initial scope) |
| Agent / AgentBundle / AgentRelease | This Control Plane |
| AgentIdentity / SessionIdentity | This Control Plane |
| RunIntent | This Control Plane |
| Run / Task / RunAttempt | Agent Runtime |
| Workflow history and native Activity attempts | Temporal |
| DecisionRecord / invocation result | agent-decision |
| Action / ActionHash / Approval / Permit / Action Operation | EngageGuard |
| ComputeProvider / Pool / Workload / Allocation / Compute Operation | compute-control-panel |
| Actual Pod / Job / Kueue admission | Kubernetes / Kueue |
| Actual Sandbox lifecycle | selected Sandbox Provider |

## Architecture principles

1. One authoritative writer per business fact; no shared writable database across services.
2. API-first and Kubernetes-first, but not Kubernetes-only.
3. PostgreSQL per service, transactional outbox/inbox, versioned APIs and events.
4. Desired state and observed state are distinct; reconcile idempotently.
5. Unknown external outcomes remain UNKNOWN until the owning service reconciles the exact operation.
6. Temporal owns durable orchestration; Agent Framework owns bounded model reasoning only.
7. Agent-originated protected side effects pass through EngageGuard and a trusted enforcement point.
8. Internal provider reconciliation remains owned by Compute/Sandbox services under service identity and domain policy.
9. Secrets never enter AgentBundle, plugin payloads, logs, traces, events or evidence.

## Normative architecture documents

- [Platform baseline](docs/architecture/PLATFORM-BASELINE.md)
- [Domain ownership](docs/architecture/DOMAIN-OWNERSHIP.md)
- [Cross-service contracts](docs/architecture/CROSS-SERVICE-CONTRACTS.md)
- [Identifier lifecycle](docs/architecture/IDENTIFIER-LIFECYCLE.md)
- [ADR-001: Domain authority](docs/architecture/ADR-001-domain-authority.md)
- [ADR-002: Temporal and Agent Framework boundary](docs/architecture/ADR-002-temporal-agent-framework.md)
- [Implementation roadmap](docs/roadmap/IMPLEMENTATION-ROADMAP.md)
- [P0 Golden Path](docs/roadmap/P0-GOLDEN-PATH.md)
- [Decision Turn request schema](contracts/agent-decision/v0.1/decision-turn.schema.json)
- [Decision result schema](contracts/agent-decision/v0.1/decision-result.schema.json)

## Historical documents

[Original Architecture Baseline](docs/architecture/BASELINE.md) is retained as a superseded historical snapshot only. It is not an implementation contract.

## Status

This is a greenfield implementation. Legacy source code is not a compatibility constraint. Preserve validated domain invariants and failure lessons, not old implementation structure. Architecture documents are proposals until independently reviewed; no production-readiness claim follows from documentation or a smoke test alone.
