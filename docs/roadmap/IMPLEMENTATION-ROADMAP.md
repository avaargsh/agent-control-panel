# Implementation Roadmap

## Phase 0 — Freeze architecture contracts

- [ ] Freeze domain ownership and canonical identifier ownership.
- [ ] Freeze RunIntent → Runtime StartRun / InspectRunIntent handshake and stable Workflow ID mapping.
- [ ] Freeze canonical Agent Decision v0.1 request/result JSON Schemas and shared Go/Python/TypeScript fixtures.
- [ ] Freeze ActionProposal → Runtime operation_id → EngageGuard ActionHash → Approval/Permit → Receipt chain.
- [ ] Freeze Compute Workload / Allocation / compute_operation_id relationship.
- [ ] Freeze event envelope, aggregate-version gap recovery, Inbox states and idempotency/error semantics.
- [ ] Freeze Temporal, Decision, EngageGuard and Compute retry ownership.
- [ ] Mark conflicting legacy architecture documents superseded.

**Exit gate:** all consumers reference the same schema and identifier versions. A smoke-test subset must be labeled as such and cannot claim full v0.1 conformance.

## Phase 1 — Go foundations (parallel)

### agent-control-panel

- [ ] Go API/reconciler bootstrap, config, health/readiness, telemetry and graceful shutdown.
- [ ] Tenant/project authorization and Agent/Bundle/Release/Session identity models.
- [ ] PostgreSQL migrations, atomic idempotency claim, optimistic versions and transactional outbox.
- [ ] RunIntent API and fenced dispatcher; no Run/Task/Attempt state machine.
- [ ] Persist Runtime-assigned run_id/workflow_id only after matching receipt.

### agent-runtime

- [ ] Go Runtime bootstrap and PostgreSQL Run metadata/idempotency schema.
- [ ] Unique mapping from run_intent_id + request digest to one Runtime-owned run_id.
- [ ] Stable Workflow ID mapping: `agent-run/v1/{run_id}`.
- [ ] Transactional StartRun intent/outbox; duplicate StartRun returns same Run.
- [ ] Deterministic Temporal Workflow and Activity boundaries.

### agent-decision

- [ ] Python reference plugin validates canonical v0.1 schemas.
- [ ] Strict request/response validation and bounded HTTP server.
- [ ] Durable invocation idempotency: same ID/digest replays exact result; changed digest conflicts.
- [ ] Mock/deterministic adapter first; framework adapter is replaceable.
- [ ] Shared Go/Python/TypeScript conformance vectors.

### EngageGuard

- [ ] Canonical ActionEnvelope and RFC 8785 JCS ActionHash golden vectors.
- [ ] Authenticated PEP and trusted ToolBinding resolution.
- [ ] Authorization and action-bound Approval.
- [ ] One-time audience/operation-bound Permit claim.
- [ ] Trusted Workspace Executor and root/symlink/TOCTOU confinement.
- [ ] Action Operation Journal, Receipt and UNKNOWN reconciliation.

### compute-control-panel

- [ ] Go service bootstrap and PostgreSQL schema/migrations.
- [ ] Workload/Allocation API and stable compute_operation_id.
- [ ] Durable operation leases, generation/version fencing and outbox/inbox.
- [ ] FakeProvider create/inspect/delete contract suite.
- [ ] Kubernetes Job + Kueue adapter POC; no custom scheduler.

## Phase 2 — Agent RunIntent vertical slice

- [ ] AgentBundle → AgentRelease → Session → RunIntent.
- [ ] Runtime accepts RunIntent, atomically creates one Run and stable Workflow ID.
- [ ] Temporal starts/inspects the same Workflow ID under duplicate requests.
- [ ] Runtime invokes one bounded Decision Turn using canonical schemas and stable invocation_id.
- [ ] FinalResponse and ActionProposals are validated; plugin cannot execute privileged effects.
- [ ] Restart, duplicate delivery, lost start ACK, replay and cancellation tests.

## Phase 3 — Secure action vertical slice

- [ ] Runtime persists accepted ActionProposal and assigns one stable Action operation_id.
- [ ] EngageGuard canonicalizes and hashes trusted action.
- [ ] Approval and Permit bind exact ActionHash, operation ID, target, audience and expiry.
- [ ] Trusted enforcement point claims Permit once and executes.
- [ ] Receipt binds ActionHash and executor_attempt_id.
- [ ] Lost ACK becomes UNKNOWN; Runtime queries same operation and does not blindly replay.
- [ ] Adversarial tests: changed arguments, target, binding, policy, path traversal, symlink race and concurrent claim.

## Phase 4 — Compute Workload vertical slice

- [ ] Agent-originated compute request passes EngageGuard authorization.
- [ ] Compute API creates distinct Workload and compute_operation_id.
- [ ] FakeProvider proves create/inspect/delete and UNKNOWN recovery.
- [ ] Kubernetes Job adapter and Kueue admission integration.
- [ ] Delete finality requires provider-observed absence for exact generation/resource UID.
- [ ] Crash, stale generation, quota exhaustion and real-cluster POC evidence.

## Phase 5 — Platform expansion

- [ ] Managed Python and TypeScript plugin workers.
- [ ] Framework adapter (LangGraph first; a second adapter proves protocol neutrality).
- [ ] Sandbox provider POC and secure workspace executor.
- [ ] Console, gateway, observability, quotas and federation.
- [ ] DRA/HAMi/MetaX and multi-cluster integration only behind capability gates.

## Quality gates

No phase passes on a happy-path demo alone. Every phase requires build, unit/integration tests, API/schema compatibility, security checks and failure-mode evidence. Exactly-once external effects are never claimed; use stable IDs, atomic idempotency, durable journals and reconciliation.
