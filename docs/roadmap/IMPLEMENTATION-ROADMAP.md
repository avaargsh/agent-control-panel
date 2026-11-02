# Implementation Roadmap

## Phase 0 — Freeze architecture contracts

- [ ] Freeze domain ownership and canonical identifier ownership.
- [ ] Freeze RunIntent → Runtime StartRun / InspectRunIntent handshake.
- [ ] Freeze Workload v1 API, provider operation journal and observation contract.
- [ ] Freeze event envelope, aggregate version/gap handling and idempotency digest rules.
- [ ] Freeze Temporal / Agent Framework / EngageGuard retry ownership.
- [ ] Freeze Compute / Kueue / Kubernetes / SandboxProvider boundaries.
- [ ] Remove or mark superseded architecture documents.

## Phase 1 — Go foundations

- [ ] Config validation, API/reconciler process modes, health/readiness and graceful shutdown.
- [ ] PostgreSQL migrations, transaction boundaries and per-service database ownership.
- [ ] Idempotency records and canonical request digest.
- [ ] Transactional Outbox and Inbox with aggregate-version enforcement.
- [ ] OpenAPI as source of truth; compatibility tests and stable error envelope.
- [ ] CI: gofmt check (no mutation), go vet, tests, race, dependency/security scanning.

## Phase 2 — Agent RunIntent vertical slice

- [ ] AgentBundle, AgentRelease, Session and RunIntent API.
- [ ] Runtime StartRun idempotency keyed by RunIntent ID + digest.
- [ ] Runtime creates canonical Run ID and deterministic Workflow ID.
- [ ] Lease/fencing protected dispatcher and UNKNOWN → RECONCILING.
- [ ] Runtime final-not-found / found / conflict outcomes.
- [ ] Restart, lost-ACK, duplicate-start, event-gap and tenant-isolation tests.

## Phase 3 — Compute Workload vertical slice

- [ ] Provider / Pool / Profile / Workload / Allocation / Observation schemas.
- [ ] Durable ComputeOperation journal, stable operation ID and request digest.
- [ ] Lease owner, expiry and fencing token.
- [ ] UNKNOWN → RECONCILING → succeeded / retry-same-operation / failed / manual-review.
- [ ] FakeProvider create/inspect/delete contract tests.
- [ ] Delete finality by exact provider resource ID/UID.
- [ ] Stale-generation compensation and restart/fault-injection tests.

## Phase 4 — External adapters

- [ ] Temporal Workflow/Activity adapter in Runtime (not this Control Plane).
- [ ] Kubernetes Job adapter and Kueue admission integration in Compute.
- [ ] Capability-gated device plugins/DRA/provider adapters.
- [ ] SandboxProvider adapter with no duplicate compute resource ownership.

## Phase 5 — Platform expansion

- [ ] Managed Python and TypeScript Decision plugin workers.
- [ ] Framework adapter (LangGraph first; second adapter proves neutrality).
- [ ] EngageGuard trusted executor and action-bound credential integration.
- [ ] Console, gateway, observability, quotas and federation.

## Quality gates

No phase passes on a happy-path demo alone. Every phase requires build, unit/integration tests, contract tests and failure-mode evidence. Exactly-once external effects are never claimed; use idempotency plus reconciliation.
