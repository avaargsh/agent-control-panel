# Architecture Review Disposition — 2026-11-02

Status: reviewed corrections incorporated into proposed v0.2 contracts; not a formal GitHub approval.

| Review finding | Required correction | Disposition |
|---|---|---|
| RunIntent and Run identity were conflated | Agent Control Plane owns RunIntent; Runtime creates canonical Run/Workflow/Attempt IDs | Fixed in DOMAIN-OWNERSHIP, ADR-003, P0 Golden Path |
| Control Plane assigned Workflow ID before Runtime accepted a Run | Runtime derives workflow_id from its canonical run_id; Control Plane stores a read-only reference | Fixed in ADR-003 and RunIntent contract |
| UNKNOWN recovery used a boolean and could be called by an arbitrary caller | Typed Runtime receipt/lookup result; lease owner, expiry, version and fencing token; authoritative not-found only | Fixed in RunIntent Go model; PostgreSQL CAS and Runtime adapter remain P0 |
| RunIntent state could resemble Run lifecycle (RUNNING/SUCCEEDED) | RunIntent states describe dispatch only; Run execution state belongs to Runtime | Fixed in domain model and tests |
| action_hash / operation_id / attempt_id ownership was ambiguous | EngageGuard owns action_hash/action operation; Compute owns compute operation; Runtime owns attempt_id | Fixed in DOMAIN-OWNERSHIP and CROSS-SERVICE-CONTRACTS |
| Temporal and Agent Framework could duplicate state/retry ownership | Temporal orchestrates; Runtime owns Run lifecycle; plugin is bounded and returns FinalResponse/ActionProposal | ADR-002 retained and referenced by ADR-003 |
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

The architecture is not production-approved until these gaps have executable evidence. The companion Go PR is an incremental domain prototype, not a completed P0 Golden Path.
