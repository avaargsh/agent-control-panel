# Implementation Roadmap

## Phase 0 — Contract freeze (blocking gate)

- [ ] Freeze domain ownership and canonical identifier lifecycle.
- [ ] Adopt the canonical Decision Turn and Result JSON Schemas; generate/validate Go, Python and TypeScript fixtures from the same files.
- [ ] Freeze RunIntent → Run → Workflow ID mapping and Attempt namespaces.
- [ ] Freeze ActionProposal → action_operation_id → ActionHash → Approval/Permit → Receipt chain.
- [ ] Freeze Compute Workload / Allocation / compute_operation_id relationship.
- [ ] Freeze event envelope, aggregate-version gap recovery, inbox states and error/idempotency semantics.
- [ ] Mark conflicting legacy architecture/P0 documents superseded.
- [ ] Record any deferred decision explicitly; no consumer may invent a private variant.

**Exit gate:** all five repositories reference the same contract version and pass schema/identifier conformance tests. No implementation may claim full v0.1 conformance while using a private subset.

## Phase 1 — Independent Go service foundations (parallel)

### agent-control-panel

- [ ] Go service bootstrap, configuration validation, health/readiness, telemetry and graceful shutdown.
- [ ] Tenant/project authorization boundary and Agent/Bundle/Release/Session identity models.
- [ ] PostgreSQL migrations, atomic idempotency claim, optimistic versions and transactional outbox.
- [ ] RunIntent API and reconciler dispatch contract; no Run/Task/Attempt state machine.
- [ ] Persist Runtime-assigned `run_id` / `workflow_id` as references after Runtime acceptance.

### agent-runtime

- [ ] Go service bootstrap and PostgreSQL Run metadata/idempotency schema.
- [ ] Unique mapping from `run_intent_id` to one Runtime-owned `run_id`.
- [ ] Stable Workflow ID mapping: `agent-run/v1/{run_id}`.
- [ ] Transactional Run start intent and outbox; duplicate StartRun returns the same Run.
- [ ] Deterministic Temporal Workflow and Activity boundaries.

### agent-decision

- [ ] Python reference plugin validates the canonical v0.1 schemas.
- [ ] Strict request/response validation and bounded HTTP server.
- [ ] Durable invocation idempotency: same ID/digest replays exact result; changed digest conflicts.
- [ ] Mock/deterministic adapter first; framework adapter is a later replaceable implementation.
- [ ] Shared Go/Python/TypeScript conformance vectors.

### EngageGuard

- [ ] Canonical ActionEnvelope and RFC 8785 JCS ActionHash test vectors.
- [ ] Authenticated PEP and trusted ToolBinding resolution.
- [ ] Authorization and action-bound Approval.
- [ ] One-time audience/operation-bound Permit claim.
- [ ] Trusted Workspace Executor and root/symlink/TOCTOU confinement.
- [ ] Action Operation Journal, Receipt and UNKNOWN reconciliation.

### compute-control-panel

- [ ] Go service bootstrap and PostgreSQL schema/migrations.
- [ ] Workload/Allocation API and stable `compute_operation_id`.
- [ ] Durable operation leases, generation/version fencing and outbox/inbox.
- [ ] FakeProvider create/inspect/delete contract suite.
- [ ] Kubernetes Job + Kueue adapter POC; no custom scheduler.

## Phase 2 — Durable Run vertical slice

- [ ] AgentBundle → AgentRelease → Session → RunIntent.
- [ ] Runtime accepts RunIntent, atomically creates one Run and stable Workflow ID.
- [ ] Temporal starts/inspects the same Workflow ID under duplicate requests.
- [ ] Runtime invokes one bounded Decision Turn using canonical schemas and stable invocation_id.
- [ ] FinalResponse and NeedsInput map to explicit Runtime outcomes.
- [ ] Restart, duplicate delivery, lost start ACK, replay and cancellation tests.

## Phase 3 — Secure action vertical slice

- [ ] Decision returns ActionProposal; Runtime persists it and assigns one stable action_operation_id.
- [ ] EngageGuard canonicalizes and hashes the trusted action.
- [ ] Approval and Permit bind exact action_hash, operation ID, target, audience and expiry.
- [ ] Trusted enforcement point claims Permit once and executes.
- [ ] Receipt binds action hash and executor_attempt_id.
- [ ] Lost ACK becomes UNKNOWN; Runtime queries the same operation and does not blindly replay.
- [ ] Adversarial tests: changed arguments, target, binding, policy, path traversal, symlink race and concurrent claim.

## Phase 4 — Compute vertical slice

- [ ] Agent-originated compute request passes EngageGuard authorization.
- [ ] Compute API creates a distinct Workload and compute_operation_id.
- [ ] FakeProvider proves create/inspect/delete and UNKNOWN recovery.
- [ ] Kubernetes Job adapter and Kueue admission integration.
- [ ] Delete finality requires provider-observed absence for the exact generation.
- [ ] Crash, stale generation, quota exhaustion and real-cluster POC evidence.

## Phase 5 — Platform expansion

- [ ] Managed Python and TypeScript plugin workers.
- [ ] Framework adapter (LangGraph first; a second adapter proves protocol neutrality).
- [ ] Sandbox provider POC and secure workspace executor.
- [ ] Console, gateway, observability, quotas and federation.
- [ ] DRA/HAMi/MetaX and multi-cluster integration only behind capability gates.

## Quality gates

No phase passes on a happy-path demo alone. Each phase requires build, tests, API/schema compatibility, security checks and failure-mode evidence. Do not claim exactly-once external effects; use stable identifiers, atomic idempotency, durable journals and reconciliation.
