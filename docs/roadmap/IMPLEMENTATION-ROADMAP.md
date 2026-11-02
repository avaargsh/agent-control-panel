# Implementation Roadmap

## Phase 0 — Contracts and architecture
- [ ] Freeze capability map, domain ownership and service boundaries.
- [ ] Publish event envelope, identifier rules, idempotency and error contracts.
- [ ] Define Temporal Workflow and Agent Decision plugin contract.
- [ ] Define EngageGuard ActionEnvelope / ActionHash / Permit / Receipt contract.
- [ ] Define Compute Provider and Workload operation contract.

## Phase 1 — Go foundations
- [ ] Go service bootstrap, config validation, health/readiness, telemetry and graceful shutdown.
- [ ] PostgreSQL migrations, transaction boundaries, outbox/inbox.
- [ ] OpenAPI generation and compatibility tests.
- [ ] CI: gofmt, go vet, tests, race, workflowcheck, dependency/security scanning.

## Phase 2 — Durable Run vertical slice
- [ ] AgentBundle, AgentRelease, Session and RunIntent API.
- [ ] Runtime Run metadata and Temporal Workflow start with deterministic Workflow ID.
- [ ] Temporal Workflow invokes one bounded Agent Decision plugin turn.
- [ ] Final answer and run result projection.
- [ ] Restart/replay/duplicate-start/cancel tests.

## Phase 3 — Secure action vertical slice
- [ ] Canonical ActionEnvelope and stable ActionHash.
- [ ] Authorization and approval bound to action hash.
- [ ] One-time Permit claim and trusted Workspace Executor.
- [ ] Operation Journal, UNKNOWN reconciliation and receipt verification.
- [ ] Path traversal, symlink, concurrent claim and lost-ack tests.

## Phase 4 — Compute vertical slice
- [ ] Provider / Pool / Workload / Allocation model.
- [ ] Kubernetes Job provider adapter.
- [ ] Kueue admission integration.
- [ ] Provider operation journal and deletion finality.
- [ ] Fake provider contract tests and real-cluster POC.

## Phase 5 — Platform expansion
- [ ] Managed Python and TypeScript plugin workers.
- [ ] Framework adapter (LangGraph first; second adapter proves neutrality).
- [ ] Sandbox provider POC and secure workspace executor.
- [ ] Console, gateway, observability and quotas.
- [ ] DRA/HAMi/MetaX and multi-cluster integration.

## Quality gates
No phase passes on a happy-path demo alone. Each phase requires tests, build, API contract checks and failure-mode evidence. Do not claim exactly-once external effects; use idempotency plus reconciliation.
