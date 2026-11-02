# Open Agent Infrastructure — Platform Baseline

Status: Proposed implementation baseline  
Date: 2026-11-02  
Scope: agent-control-panel, agent-runtime, agent-decision, EngageGuard, compute-control-panel

## Product outcome

A self-hosted, Kubernetes-first platform that lets operators publish versioned Agents, execute durable Runs through managed framework plugins, govern protected actions and allocate heterogeneous compute. The platform integrates mature workflow, Agent Framework, policy, sandbox and scheduler components instead of building replacements.

## Capability map and authority

| Module | Repository | Authoritative facts | Depends on |
|---|---|---|---|
| Agent Control Plane | agent-control-panel | Tenant/Project scope (initial), Agent, Bundle, Release, AgentIdentity, SessionIdentity, RunIntent, desired deployment/release intent, Context Projection policy | — |
| Runtime | agent-runtime | Run, Task, RunAttempt, execution lifecycle projection, stable Workflow ID mapping | agent-control |
| Workflow engine | Temporal | Workflow history, timers, signals, native Workflow/Activity retry and replay | Runtime |
| Decision | agent-decision | DecisionRecord, invocation request digest/result replay, proposals and evaluation | Runtime protocol |
| Governance | EngageGuard | Canonical Action, ActionHash, AuthorizationDecision, Risk, Approval, Permit, Action Operation Journal and Receipt | authenticated identity, trusted enforcement point |
| Compute | compute-control-panel | ComputeProvider, Pool, Workload, Allocation, Compute Operation Journal and provider observations | Kubernetes/Kueue/provider |
| Sandbox | external provider adapter | Actual sandbox lifecycle and isolation | Runtime; Compute where required |
| Identity | external OIDC/workload identity provider | Credential issuance, signing keys and identity lifecycle | all services |

## Build order

1. Freeze shared schemas, identifier lifecycle, event delivery and ownership contracts.
2. Build Control Plane and Compute Go foundations independently against those contracts.
3. Build Runtime persistence and Temporal Run vertical slice.
4. Build Decision reference plugin and cross-language conformance tests.
5. Build EngageGuard ActionHash/approval/Permit/trusted-executor golden path.
6. Integrate Runtime → Decision → EngageGuard and then Compute.
7. Add sandbox providers, UI, federation and advanced GPU integrations only after the vertical slices pass.

## Architecture invariants

1. One authoritative writer per business fact; independent PostgreSQL databases and migrations per service.
2. Control Plane owns desired Agent state, logical Agent/Session identity and RunIntent. Runtime owns Run/Task/Attempt execution semantics.
3. Runtime creates `run_id` once per accepted `run_intent_id`; Runtime defines the stable Workflow ID mapping. Temporal owns workflow history, timers, replay and native retry metadata.
4. Agent Framework executes one bounded Decision Turn and returns the v0.1 discriminated response union: FinalResponse, ActionProposals, NeedsInput or DecisionError. It never owns platform Run state or privileged execution.
5. Every Agent-originated protected side effect is authorized through EngageGuard and enforced by a trusted execution boundary. Internal service reconciliation uses its own workload identity and domain policy.
6. EngageGuard owns ActionHash, approval, Permit and Action Operation Journal. Compute owns Compute Operation Journal, Allocation and provider reconciliation.
7. Compute Control Plane owns compute allocation intent and reconciliation; Kubernetes/Kueue/provider own actual scheduling and execution.
8. Persist intent before dispatch. Use transactional outbox/inbox; delivery is at-least-once, may reorder, and consumers apply only contiguous aggregate versions.
9. Missing acknowledgement is UNKNOWN, not FAILED. Reconcile the exact operation identity before any new side effect attempt.
10. Identifiers are opaque across service boundaries and have one creator/owner. Do not conflate Run, Temporal, executor or provider attempts.
11. OpenAPI and the canonical Decision JSON Schemas are executable contracts. Cross-language consumers share conformance fixtures.
12. Introduce Kafka, a second controller framework or custom schedulers only when measured requirements justify them.

## Temporal / Agent Framework boundary

- Temporal Workflow contains deterministic orchestration only: lifecycle transitions, timers, signals/updates, approval waits, cancellation and recovery.
- Temporal Activities perform database, HTTP, model-plugin, EngageGuard and provider I/O.
- Runtime owns Run metadata and maps RunIntent to one stable Workflow ID.
- Agent Framework plugin performs bounded model reasoning over Runtime-supplied user input and context projection. It returns a typed result; it cannot dereference arbitrary source references, hold provider credentials or invoke privileged tools.
- Runtime supplies stable `invocation_id`; Decision persists and replays the exact result for the same request digest.
- Temporal retries a Decision Activity with the same invocation identity. It may retry an EngageGuard API request only with the same `operation_id`; EngageGuard decides whether the action is complete, pending or UNKNOWN.
- EngageGuard owns ambiguity/reconciliation for protected actions. Runtime owns business Run ambiguity. Compute owns provider operation ambiguity. No two services independently retry the same external effect.

## ActionHash and operation identity

Runtime persists an accepted ActionProposal and assigns one stable `action_operation_id` before first submission. EngageGuard authenticates the caller, resolves trusted bindings, canonicalizes the action using RFC 8785 JCS, and computes the SHA-256 ActionHash. Approval, Permit, executor claim and Receipt bind the same operation and hash. A reused operation ID with a different canonical action is rejected.

For compute actions, EngageGuard authorization is linked to a distinct Compute Workload/Operation. Compute Control Plane generates its own `compute_operation_id` and remains authoritative for provider state.

## Event and API contracts

See:

- [Cross-Service Contracts](CROSS-SERVICE-CONTRACTS.md)
- [Domain Ownership](DOMAIN-OWNERSHIP.md)
- [Identifier Lifecycle](IDENTIFIER-LIFECYCLE.md)
- [Decision request schema](../../contracts/agent-decision/v0.1/decision-turn.schema.json)
- [Decision result schema](../../contracts/agent-decision/v0.1/decision-result.schema.json)

## Deployment shape

Start with coarse deployables per repository: API and reconciler/worker processes. Split only for independent scaling or security isolation. Temporal is an external durable execution service. Each service owns its PostgreSQL database/schema and migrations.

## Deferred

Multi-region federation, Agent Fabric, autonomous multi-agent delegation, custom policy language, custom workflow engine, custom sandbox controller, custom GPU scheduler, Kafka, generalized marketplace and nonessential UI expansion.

## Acceptance

A clean deployment must complete:

- AgentBundle → AgentRelease → Session → RunIntent.
- Runtime creates one canonical Run and starts one stable Temporal Workflow.
- Runtime invokes a schema-conformant managed Decision plugin and validates the matching invocation result.
- A protected ActionProposal is canonicalized, authorized and executed only through EngageGuard's trusted enforcement point.
- A lost ACK produces UNKNOWN and exact-operation reconciliation; no blind replay occurs.
- Compute Workload is admitted through Kueue and reconciled through Kubernetes; deletion is not final until provider absence is observed.
- Crash/restart, duplicate delivery, version-gap and cross-tenant tests pass with durable evidence.

A happy-path demo or unit tests alone do not establish production readiness.
