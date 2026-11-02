# Agent Control Panel

Agent Infrastructure Control Plane for self-hosted, Kubernetes-first Agent workloads.

## Product boundary

This repository contains the Go Agent Control Plane API and reconciliation services. A Web Console may be a client of these APIs, but does not own business state.

The Control Plane owns Tenant/Project scope (initially), Agent identity, AgentBundle, AgentRelease, canonical Session identity, RunIntent, desired configuration, release governance and federation bindings.

Agent Runtime owns Run/Task/Attempt execution lifecycle. Temporal owns durable workflow history and orchestration. EngageGuard owns per-action authorization and operation journal. Compute Control Plane owns compute resources and allocations. Kubernetes and the selected Sandbox Provider own actual execution resources.

## Golden Path

`AgentBundle → AgentRelease → Session → RunIntent → Agent Runtime / Temporal → Decision Plugin → EngageGuard → Trusted Executor → Evidence`

## Core resources

| Resource | Authority |
|---|---|
| Tenant / Project | Initial platform scope and ownership |
| Agent / AgentBundle / AgentRelease | This Control Plane |
| AgentIdentity / SessionIdentity | This Control Plane |
| RunIntent | This Control Plane |
| Run / Task / Attempt / workflow history | Agent Runtime / Temporal |
| DecisionRecord | agent-decision |
| Action / Approval / Permit / OperationJournal | EngageGuard |
| ComputeProvider / Pool / Workload / Allocation | compute-control-panel |
| Actual Pod / Job / Sandbox state | Kubernetes / selected provider |

## Architecture principles

1. One authoritative writer per business fact; no shared writable database across services.
2. API-first and Kubernetes-first, but not Kubernetes-only.
3. PostgreSQL per service, transactional outbox/inbox, versioned APIs and events.
4. Desired state and observed state are distinct; reconcile idempotently.
5. Unknown external outcomes remain UNKNOWN until inspected and reconciled.
6. Temporal owns durable orchestration; Agent Framework owns bounded model reasoning only.
7. Every protected side effect passes through EngageGuard and a trusted enforcement point.
8. Secrets never enter AgentBundle, plugin payloads, logs, traces or evidence.

## Non-goals

Do not build a proprietary Agent framework, workflow engine, sandbox runtime, MCP/A2A gateway, IAM, policy language or GPU scheduler. Do not duplicate Temporal workflow history or retry state in this repository.

## Status

This is a greenfield implementation. Legacy source code is not a compatibility constraint. Preserve validated domain invariants and failure lessons, not old implementation structure.

## Architecture documents

- [Platform baseline](docs/architecture/PLATFORM-BASELINE.md)
- [Domain ownership](docs/architecture/DOMAIN-OWNERSHIP.md)
- [Cross-service contracts](docs/architecture/CROSS-SERVICE-CONTRACTS.md)
- [ADR-001: Domain authority](docs/architecture/ADR-001-domain-authority.md)
- [ADR-002: Temporal and Agent Framework boundary](docs/architecture/ADR-002-temporal-agent-framework.md)
- [Implementation roadmap](docs/roadmap/IMPLEMENTATION-ROADMAP.md)
- [Original Agent Control Plane baseline](docs/architecture/BASELINE.md)
- [P0 Golden Path](docs/roadmap/P0-GOLDEN-PATH.md)
