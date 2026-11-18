# Architecture Review Disposition — 2026-11-02

Status: reviewed corrections incorporated into proposed v0.2 architecture; protocol ownership and G02/G03 wire details remain blocked, not a formal GitHub approval.

| Review finding | Required correction | Disposition |
|---|---|---|
| RunIntent and Run identity were conflated | Agent Control Plane owns RunIntent; Runtime creates canonical Run/Workflow/Attempt IDs | Fixed in DOMAIN-OWNERSHIP, ADR-003, P0 Golden Path |
| Control Plane assigned Workflow ID before Runtime accepted a Run | Runtime derives workflow_id from its canonical run_id; Control Plane stores a read-only reference | Fixed in ADR-003 and RunIntent contract |
| UNKNOWN recovery used a boolean and could be called by an arbitrary caller | Typed Runtime receipt/lookup result; lease owner, expiry, version and fencing token; authoritative not-found only | Fixed in RunIntent Go model; PostgreSQL CAS and Runtime adapter remain P0 |
| RunIntent state could resemble Run lifecycle (RUNNING/SUCCEEDED) | RunIntent states describe dispatch only; Run execution state belongs to Runtime | Fixed in domain model and tests |
| action_hash / operation_id / attempt_id ownership was ambiguous | EngageGuard owns Action Operation and ActionHash; Runtime persists guard_submission_key; Compute owns compute operation; Runtime owns run_attempt_id. operation_id creation and ActionHash preimage remain G03 blockers | Ownership direction clarified; wire semantics remain blocked pending EngageGuard/Runtime signoff |
| Temporal and Agent Framework could duplicate state/retry ownership | Temporal orchestrates; Runtime owns Run lifecycle; Decision Core owns DecisionRecord; framework adapters are separately versioned bounded reasoning interfaces | Candidate boundary documented in ADR-002; Decision Core/adapter protocols remain blocked pending agent-decision #9 |
| Event delivery could duplicate or reorder state | Transactional Outbox/Inbox; event_id dedupe; aggregate_version duplicate/gap handling | Fixed in CROSS-SERVICE-CONTRACTS |
| Idempotency lacked canonical payload conflict semantics | Tenant + authenticated principal + operation key + canonical digest; same/different digest behavior defined | Fixed in CROSS-SERVICE-CONTRACTS and ADR-003 |
| Old baseline documents contradicted the new authority map | Supersede old baseline and link the v0.2 platform baseline | Fixed; historical BASELINE.md explicitly marked superseded |
| Repository name panel implied UI ownership | Explicitly define this repository as Go Agent Control Plane API; Console is a client | Fixed in README |

## Remaining acceptance gaps

- PostgreSQL schema, conditional version updates and unique idempotency constraints.
- Transactional Outbox/Inbox implementation and event gap parking/retry.
- AuthN/AuthZ middleware and tenant/project isolation integration tests.
- Runtime StartRun / InspectRunIntent adapter and durable idempotency registry.
- Fresh-process restart and lost-ACK integration tests.
- Evidence persistence and verification.
- Ratification of the service-owned Decision Core and framework-adapter protocols (G02); ACP-local JSON schemas are historical compatibility snapshots only.
- Ratification of EngageGuard operation_id creation semantics and the exact RFC 8785 ActionHash preimage/vectors (G03).

The architecture is not production-approved until these gaps have executable evidence. The companion Go PR is an incremental domain prototype, not a completed P0 Golden Path.
