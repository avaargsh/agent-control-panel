# Open Agent Infrastructure — governance v0.3 candidate

Status: **PROPOSED / NOT RATIFIED** (2026-11-02).
Tracking: https://github.com/avaargsh/agent-control-panel/issues/3.

## Intended product boundary

A Kubernetes-first, self-hosted agent infrastructure to publish immutable AgentBundles, accept versioned RunIntent, execute durable Runs, verify evidence-backed decisions, authorize protected effects, and provision compute/sandboxes through mature controllers. Do not build another scheduler, workflow engine, IAM system, policy language, or generic agent framework.

## Proposed authoritative domains

| Domain | Sole authoritative writer | Other systems |
|---|---|---|
| Tenant, Project, Agent, Bundle, Release, Session, RunIntent | agent-control-panel (Go) | Control Plane projects Runtime run states but cannot own them |
| Run, Task, RunAttempt, RunIntent→Run mapping | agent-runtime (Go) | Temporal owns workflow history; Runtime owns workflow ID mapping |
| DecisionRecord, immutable decision/evidence ledger | agent-decision (Go Core) | Python/TS reasoning adapters cannot own another DecisionRecord ledger |
| Protected Action, action_hash, approval, Permit, action operation/receipt | EngageGuard (Go) | Runtime only proposes/submits and projects outcomes |
| Workload, Allocation, ComputeOperation, provider mutation journal | compute-control-panel (Go) | Kubernetes/Kueue/providers own actual external facts |
| Workflow replay, Activity scheduling, timers | Temporal | Go Runtime code must be deterministic inside Workflows |
| Sandbox identity, lifecycle, isolation | selected SandboxProvider | Only the SandboxProvider requests Compute capacity for a sandbox claim |

RunIntent ID is made by ACP; Runtime creates run_id and workflow_id from the accepted intent. The proposed Workflow ID mapping is agent-run/v1/{run_id}. The Control Plane MUST NOT create the business Run ID or infer Run success from RunIntent acceptance.

## Architectural choice: split Go Core from framework adapter

**Preferred option (candidate):** agent-decision Go service owns verifiable DecisionRequest, DecisionRecord, evidence/strategy verification, and ledger APIs. Python/TypeScript are independently versioned bounded inference adapters with no platform Run identity, no protected execution, no Permit, no Action Operation and no second authoritative ledger. The Go Core may invoke the adapter for an explicitly versioned strategy; a deterministic SRE read-only strategy need not use it.

Rejected option A: treating both Go Core and Python plugin as different implementations of the same unversioned Decision v0.1 service. Their response shapes, context trust, identity and error envelopes conflict.

Rejected option B: migrating Temporal Workflow ownership into the Decision service. It would split durable Run state across two owners and duplicate retries.

Open compatibility gate: ACP draft includes an inline-context two-variant DecisionTurn while the Decision Plugin draft uses immutable context refs and a three-variant response. Their JSON Schemas MUST NOT share a version identifier. The live protocol is owned by the service publishing that endpoint. The registry below references immutable commit revisions and must never fork the schema.

## Protected action and Operation identity proposal

Runtime persists one stable Guard submission idempotency key before network I/O. Guard creates and owns operation_id and the Action Operation. Same authenticated tenant + key + canonical request digest must resolve the same operation. Same key with changed digest fails closed. This is **not yet ratified**, because the current implementation is not yet a trusted, durable Guard admission service. EngageGuard PR #5 proposes caller `ActionSubmission` without `operation_id` and Guard-internal `ActionRequest` after identity resolution, but the PostgreSQL key/operation claim, Permit and UNKNOWN journal remain unimplemented.

Hash is computed by Guard only after trusted normalization. A single versioned domain separator plus full RFC 8785 JCS and cross-language vectors are required. Go json.Marshal alone is not equivalent to RFC 8785 for arbitrary values. No Permit or ActionHash is supplied by an untrusted model/plugin.

UNKNOWN, RECONCILING and MANUAL_REVIEW must not lead to a second external effect. Guard owns protected-action reconciliation; Compute owns provider mutation reconciliation. A successful provider HTTP acknowledgement does not prove exact-resource deletion, receipt verification, or exactly-once execution.



## Identifier creation is not record authority

The Runtime **creates** invocation_id for a logical Decision Turn and guard_submission_key before protected-action HTTP submission. However, Decision **owns** the durable invocation ledger and exact result, while EngageGuard **owns** the idempotency index and server-generated operation_id. These are caller-issued request identities, not Runtime-owned foreign database records. See the manifest's issued_request_ids section. Retried requests MUST use the original ID and canonical request digest; a changed digest conflicts.

## Compute and sandbox

Direct Run capacity: Runtime → Compute CP. Sandbox capacity: Runtime → SandboxProvider Claim → Compute CP (no duplicate Workload). Compute CP controls provider/pool choice and Workload/Allocation; Kueue controls admission/quota and Kubernetes controls Pod placement. Provider/native UID remains external authority for resource existence and delete finality.

## Governance process

1. Service API owner publishes OpenAPI/JSON Schema, versioned fixtures and source commit. Platform governance stores immutable pointers only.
2. One business fact has one authoritative writer; no cross-service writes, no shared writable databases.
3. Changes to ID ownership, discriminated unions, trust semantics, canonical hash, or UNKNOWN recovery require a new contract version and an ADR with consumer impact.
4. The governance manifest is a **tracking tool**, not evidence that the proposed contracts are accepted. Its CI verifies internal consistency; it cannot prove a Go/Python/TS integration works.
5. Before a Draft implementation is declared ready: owner and consumer sign off, shared fixtures pass, transaction/replay/fault tests pass, and the PR's branch ancestry is checked against main.
6. Do not merge inconsistent parallel branches independently. Rebase/cherry-pick only after a written compatibility plan; never force-push or close active user work as part of this proposal.
7. Block automatic privileged execution until Guard Permit and journal end-to-end evidence exists.

## Exit evidence

- One RunIntent+digest maps to exactly one Run after lost ACK and restarts.
- Decision Core replay returns identical DecisionRecord, with verified fresh evidence and subject binding.
- Optional adapter output is validated and becomes non-authoritative evidence, not a permit.
- Guard idempotency key + request replay and 409 conflict are proven against a live Guard adapter.
- Correct JCS/ActionHash vectors pass Go, Python and TypeScript; tampering invalidates authorization.
- Compute FakeProvider proves UNKNOWN/reconciliation, stale fencing and exact UID deletion finality.
- Cross-tenant, expired identity, revoked binding, duplicate event, gap and restart tests are documented with CI links.

See [PR integration plan](./PR-STACK-AND-GATES.md), [ADR-0001](./ADR-0001-PROTOCOL-AUTHORITY.md) and machine-readable [contract registry](../../governance/contract-registry.v0.3.json).

For behavior reuse from the former `agent-control-plane` and the disposable `temp-runner` acceptance harness, see [legacy reuse and two-stage Golden Path](./LEGACY-REUSE-AND-GOLDEN-PATH.md). This is a migration/acceptance proposal only; it does not claim the legacy lock is accessible, or that G01–G05 is passing.


## Guard wire/internal contract split (P0 G03)

A caller submits a bounded untrusted `action-submission.v1` JSON payload plus a stable HTTP `Idempotency-Key`. This external payload does **not** carry operation_id, tenant/subject assertions, policy, ToolBinding or executor audience. Guard must resolve identity and all privileged bindings after authenticated admission; only Guard's internal `ActionRequest` may bind its newly created operation_id.

Governance pins both independently: `guard-action-submission` for caller ingress, `guard-internal-action-request` for trusted internal normalization. Both remain blocked until Guard's PostgreSQL unique claim + exact replay/conflict, domain-separated RFC 8785 JCS, Permit and live lost-ACK/UNKNOWN tests are verified. Branches #4 and #5 are competing sibling proposals, **not** a tested end-to-end implementation.
