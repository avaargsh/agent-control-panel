# Open Agent Infrastructure — Platform Baseline

Status: Proposed implementation baseline
Date: 2026-11-02
Scope: agent-control-panel, agent-runtime, agent-decision, EngageGuard, compute-control-panel

## Product outcome

A self-hosted, Kubernetes-first platform that lets operators publish versioned Agents, execute durable Runs through managed framework plugins, govern every privileged action, and allocate heterogeneous compute without building another Agent framework, workflow engine, sandbox runtime, IAM or scheduler.

## Capability map and build order

| Module | Repository | Authority | Depends on |
|---|---|---|---|
| agent-control | agent-control-panel | Tenant/project scope (initial), Agent, Bundle, Release, Session identity, RunIntent, deployment intent | — |
| runtime | agent-runtime | Run, Task, Attempt, execution lifecycle projection; Temporal owns durable workflow history | agent-control |
| decision | agent-decision | Framework invocation, model decisions, plan/tool proposals, evaluation | runtime contract, gateway |
| governance | EngageGuard | Action, decision, risk, approval, Permit, Operation Journal, audit | identity context, trusted executor |
| compute | compute-control-panel | Provider, Pool, Workload, Allocation, compute operations and observations | Kubernetes/Kueue |
| sandbox | external provider adapter | Actual sandbox lifecycle and isolation | runtime, compute where needed |

Build order: shared contracts → agent-control foundation → runtime + Temporal → EngageGuard golden path → managed decision plugin → compute integration → UI/federation.

## Architecture invariants

1. One authoritative writer per business fact.
2. Control Plane owns desired state and logical Agent/Session identity; Runtime owns Run execution semantics.
3. Temporal owns workflow history, timers, retries and replay. No second workflow engine or duplicated retry state machine.
4. Agent Framework invocation is a bounded decision turn. It emits a final result or typed ActionProposal; it does not own platform Run state or privileged execution.
5. Every protected side effect passes through EngageGuard and a trusted enforcement point.
6. Compute Control Plane owns compute allocation intent and reconciliation; Kubernetes/Kueue/provider own actual scheduling and execution.
7. Persist intent before dispatch. Use transactional outbox/inbox for service events.
8. A missing acknowledgement is UNKNOWN, not FAILED. Reconcile before retry.
9. IDs and contracts are versioned; cross-service references do not create shared database ownership.
10. PostgreSQL per service is authoritative. No shared writable schema. Introduce Kafka only when measured fan-out/throughput requires it.

## Temporal / Agent Framework boundary

Temporal Workflow coordinates durable Run lifecycle, waits, approval signals, cancellation, timeout and recovery. Activities perform I/O and call external services. A managed Agent Framework plugin executes one bounded reasoning turn and returns a typed proposal. Tool execution is a separate Runtime → EngageGuard → Trusted Executor path. The plugin never receives provider credentials or direct privileged network access.

A framework may internally use a graph/agent loop for a bounded turn, but it must not independently own the platform Run lifecycle, durable retry policy, approval state or sandbox allocation.

## Deployment shape

Start with coarse deployables per repository: API and reconciler/worker processes. Split further only for independent scaling or security isolation. Temporal is an external durable execution service. Each service owns its own PostgreSQL database/schema and migrations.

## Deferred

Multi-region federation, Agent Fabric, autonomous multi-agent delegation, custom policy language, custom workflow engine, custom sandbox controller, custom GPU scheduler, Kafka, and generalized marketplace.

## Acceptance

A clean environment completes:
- AgentBundle → Release → Session → RunIntent.
- Runtime starts a Temporal Workflow and invokes a managed decision plugin.
- A proposed protected tool action is authorized and executed only through EngageGuard.
- Runtime records completion from durable workflow outcome.
- Compute workload is admitted through Kueue and reconciled through Kubernetes.
- Crash/restart and lost-ack tests prove no duplicate logical Run and no blind replay of ambiguous side effects.
