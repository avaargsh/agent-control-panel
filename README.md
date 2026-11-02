# Agent Control Plane

Go-based Agent Infrastructure Control Plane and management API for self-hosted, Kubernetes-first Agent workloads.

> The repository name is `agent-control-panel`; the service is the **Agent Control Plane**. It is not the web console, Agent Runtime, or an Agent Framework.

## Product boundary

This repository owns Tenant/Project scope (initially), Agent identity, immutable AgentBundle and AgentRelease, canonical Session identity, RunIntent, desired configuration, release governance, federation bindings, and a read-only execution projection. It dispatches RunIntent to Agent Runtime and reconciles the dispatch receipt.

It does **not** own executed Run/Task/Attempt/Checkpoint lifecycle, Temporal history, Agent reasoning, protected actions, provider operation journals, compute allocations, or actual Kubernetes/Sandbox resources.

## Authority map

| Domain fact | Authority |
|---|---|
| Tenant / Project, Agent / Bundle / Release | Agent Control Plane |
| SessionIdentity, RunIntent | Agent Control Plane |
| Run / Task / RunAttempt / execution lifecycle | Agent Runtime |
| Durable workflow history / native Activity attempts | Temporal |
| DecisionRecord / invocation ledger and result | agent-decision |
| Action / ActionHash / Approval / Permit / Action Operation | EngageGuard |
| ComputeProvider / Pool / Workload / Allocation / Compute Operation | compute-control-panel |
| Kueue admission / queue state | Kueue |
| Pod placement and actual Pod / Job state | Kubernetes and provider |
| Actual sandbox isolation and lifecycle | selected Sandbox Provider |

A Run shown by this API is a **read-only projection** from Agent Runtime. The canonical `run_id` is generated and owned by Runtime. The Control Plane's `run_intent_id` is not a Run ID.

## Golden Path

`AgentBundle → AgentRelease → Session → RunIntent → Agent Runtime → Temporal → Decision Core → optional framework adapter`

Protected effects use a separate path:

`ActionProposal → EngageGuard → Trusted Executor → Operation Receipt → Evidence`

Compute is requested through Compute Control Plane; a Decision plugin never creates compute resources.

## Architecture invariants

1. One authoritative writer per business fact; no cross-service database writes.
2. Each service owns its PostgreSQL database and migrations.
3. Domain mutation and Outbox row commit in one local transaction; consumers commit Inbox dedupe and projection atomically.
4. APIs and events are versioned; same idempotency key + same canonical request digest returns the same record; a different digest returns 409.
5. Desired state and observed state are distinct; stale aggregate versions are not applied.
6. Ambiguous remote outcomes remain UNKNOWN and are reconciled before retry.
7. Temporal owns durable orchestration; Agent Framework owns only a bounded reasoning turn.
8. EngageGuard owns protected-action authorization and Action Operation Journal; Compute owns provider operation journal.
9. Secrets never enter AgentBundle, plugin payloads, logs, traces or evidence.

## Architecture and contract references (proposed)

- [Platform baseline](docs/architecture/PLATFORM-BASELINE.md)
- [Domain ownership](docs/architecture/DOMAIN-OWNERSHIP.md)
- [Cross-service contracts](docs/architecture/CROSS-SERVICE-CONTRACTS.md)
- [Identifier lifecycle](docs/architecture/IDENTIFIER-LIFECYCLE.md)
- [ADR-001: Domain authority](docs/architecture/ADR-001-domain-authority.md)
- [ADR-002: Temporal and Agent Framework boundary](docs/architecture/ADR-002-temporal-agent-framework.md)
- [ADR-003: Identity, idempotency and retry ownership](docs/architecture/ADR-003-IDENTITY-AND-RETRY-OWNERSHIP.md)
- [ADR-004: Compute and Sandbox boundary](docs/architecture/ADR-004-COMPUTE-AND-SANDBOX-BOUNDARY.md)
- [P0 Golden Path](docs/roadmap/P0-GOLDEN-PATH.md)
- [Architecture review disposition](docs/architecture/REVIEW-DISPOSITION-2026-11-02.md)
- [Implementation roadmap](docs/roadmap/IMPLEMENTATION-ROADMAP.md)
- [Agent Decision Go Core API candidate](https://github.com/avaargsh/agent-decision/blob/bbdf45e415b310b421932977ca415419772dcaaa/api/openapi.yaml) — service-owned source, blocked pending [agent-decision#9](https://github.com/avaargsh/agent-decision/issues/9).
- [Cross-repository protocol authority proposal](https://github.com/avaargsh/agent-control-panel/blob/governance/platform-v0.3/docs/governance/ADR-0001-PROTOCOL-AUTHORITY.md) — proposed only; not ratified.
  
The ACP-local `contracts/agent-decision/v0.1/` schemas and `contracts/engageguard/action-hash/v0.1/` vectors are retained as historical compatibility snapshots. They are not normative service contracts and must not be used to freeze a wire format or ActionHash preimage before the owning services approve the source contract.

## Status

This is a greenfield implementation. Architecture documents are proposals until independently reviewed. A smoke test or green unit-test workflow alone does not establish production readiness.
