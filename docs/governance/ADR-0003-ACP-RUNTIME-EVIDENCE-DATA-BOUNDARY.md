# ADR-0003: ACP governs RunIntent and evidence references; Runtime and data engines execute

Status: **PROPOSED / NOT RATIFIED**. Date: 2026-11-05.
Owners for ratification: ACP, Agent Runtime, Agent Decision, EngageGuard, and data-execution adapter owner.
Tracking: [ACP governance #3](https://github.com/avaargsh/agent-control-panel/issues/3), [ACP Runtime adapter #10](https://github.com/avaargsh/agent-control-panel/issues/10), and [Runtime principal binding #20](https://github.com/avaargsh/agent-runtime/issues/20).

This is an architecture and acceptance proposal only. It does **not** publish a new normative wire API, approve a PR, implement a SQL engine, or close G01–G05.

## Context and decision

The product is an **Agent Control Plane**, not a second workflow engine, authoritative Run store, authorization engine, SQL planner, or SQL executor. Reuse mature execution and data ecosystems; make authority, security, durable handoff, and verifiable evidence the differentiating platform features.

| Fact / operation | Authoritative owner | ACP responsibility |
|---|---|---|
| Tenant, Project, Agent, Release, SessionIdentity, RunIntent | ACP | Validate principal and policy context; accept, version, persist, and dispatch intent |
| Run, Task, Attempt, workflow history, checkpoint, execution retries | Agent Runtime / Temporal (respective boundaries) | Persist an immutable Runtime receipt/ref and project observed status; **never** mint or reconstruct Run identity |
| DecisionRecord and decision/evidence ledger | Agent Decision Go Core | Hold version-pinned references, not a second mutable DecisionRecord |
| Protected action, Approval, Permit, Operation Journal, action reconciliation | EngageGuard | Present/request approval and project Guard status; **never** mint a Permit or infer permission from an approval screen |
| Compute Workload, Allocation, provider reconciliation | Compute Control Plane | Maintain desired resource policy and external references only |
| Semantic metrics, catalog, SQL planning, query execution, query result storage | Selected semantic/data platform and external query engine | Version-pin connector policy/configuration and reference external query evidence; **no SQL runtime in ACP** |

All service-owned request/response schemas, schema migrations, and event formats remain authoritative in the service publishing them. ACP governance pins contract revisions and consumer fixtures; it does not fork or silently normalize incompatible wire schemas.

## Durable RunIntent and execution identity

1. ACP accepts a RunIntent only from an authenticated initiating principal. Record immutable tenant, project, Agent/Release/Session bindings, initiating subject/effective actor, policy decision/revision reference, request digest, idempotency key and configuration stamp. The calling workload identity is distinct from the initiating principal.
2. ACP commits the accepted intent and dispatch Outbox record in one PostgreSQL transaction. Enforce uniqueness on the appropriate scoped idempotency key and conflict on any changed digest or immutable binding. Do not treat an ACK as a successful Run.
3. Runtime is the sole source of canonical `run_id`, `workflow_id`, and Run/Attempt state. ACP may store only verified Runtime-owned IDs and history/checkpoint references.
4. If a dispatch ACK is lost, persist **UNKNOWN**, enter **RECONCILING**, inspect Runtime's authoritative idempotency registry, and retry **only** after a definitive NOT_FOUND_FINAL with the **same** key/digest. A mismatch or indeterminate result never triggers a second logical Run.
5. Every lease takeover advances a fence. Stale workers may not commit receipts; terminal state and protected side effects must be reconciled by their respective owning services.
6. Temporal and Runtime own execution orchestration and retry. ACP may retry *delivery of intent* according to the reconciliation protocol, but must not run Temporal workflows or duplicate Runtime's execution state machine.

See ACP PRs #2/#5/#6/#7 for proposed Go, PostgreSQL, Outbox and Inbox slices. Their local CI is not evidence of authenticated StartRun/InspectRunIntent, crash/restart, or live Temporal acceptance.

## Authorization, approval, and audit

- **Admission vs execution:** ACP verifies actor/session, tenant/project, Agent/Release and policy revision at intent acceptance; Runtime and the data connector independently enforce execution-time scope. Persisted context is audit evidence, **not** a reusable bearer token or an evergreen authorization grant.
- **Workload identity:** authenticate ACP→Runtime and Runtime→connector/Guard with workload credentials (e.g. verified mTLS/SPIFFE) and an allowlisted audience. Never forward an end-user bearer token or trust arbitrary `X-Tenant`, `X-Actor`, model, or plugin claims as identity.
- **Protected actions:** Decision output is an untrusted proposal. Runtime submits it to EngageGuard. Guard resolves trusted identity/bindings and owns policy enforcement, approval, ActionHash, Permit, one-time claim, Operation Journal and UNKNOWN recovery. An ACP approval UI merely displays authoritative Guard status.
- **Audit ownership:** ACP appends auditable intent, configuration, permission-policy, approval-request and evidence-reference *linkage* events transactionally with its changes. Runtime, Decision and Guard retain their own authoritative execution/decision/action events. Do not copy their event streams into competing writable ACP ledgers.
- **Access to evidence:** every reference lookup, download or review must reauthorize the requesting principal for tenant/project and current policy, independently of the context recorded when the evidence was produced. Missing/revoked scope, unknown source revision or unverifiable provenance fails closed.

## Evidence: reference-only control plane

An ACP EvidenceIndex is a projection/locator for records owned elsewhere; it is **not** an authority for the underlying facts or a substitute for immutable object storage, a verified receipt or a retention service.

Proposed minimum *metadata* for one immutable reference (illustrative, not wire-stable):

- Scope and binding: `tenant_id`, `project_id`, `run_intent_id`; optional **Runtime-issued** `run_id` only after a matched receipt.
- Origin: owning service identifier, origin type (Runtime history/checkpoint, DecisionRecord, Guard receipt, Compute evidence, external query result), source record ID, source schema/contract version and immutable source revision.
- Integrity/correlation: source content digest and algorithm, correlation/trace IDs, source timestamp, ingestion timestamp and relevant policy/snapshot version.
- Governance: sensitivity/classification, retention policy reference, verification result, and an optional access-controlled external object locator. Credentials and query results themselves must not be embedded in ACP references.

Only the source owner can assert the source record's business fact. ACP validates scope, format, owner identity, digest binding and source revision, keeps a write-once record of the linkage, and returns **no evidence content** without a fresh authorization decision. Stale, mismatched, missing or unverified references are not promoted into decision/approval evidence. Content digest alone does not establish trust, retention or provenance.

For external query evidence, keep query execution ID, semantic/metric definition revision, source snapshot/watermark, query/result digest, row-count/redaction metadata and engine-owned result location; keep raw result data outside ACP.

## Data execution port: integrate; never rebuild SQL execution

- ACP may register an **allowlisted, versioned data-connector capability** and its authorized tenant/project scope, semantic catalog revision, budgets and result-evidence policy. Neither ACP nor an LLM plugin should hold arbitrary DB credentials.
- A Runtime/Decision-managed adapter invokes an existing query service or data platform over a **selected standardized/versioned interface** (for example a compatible Flight SQL, JDBC/ODBC bridge, or a well-defined engine API). Select one per connector with documented protocol/version/fixture tests; this ADR **does not** declare these alternatives mutually wire-compatible or choose an engine.
- Inputs bind the initiating principal/policy snapshot reference, tenant/project, semantic or approved query-plan reference, exact connector/contract revision, parameters, deadline and maximum resource/data budget. Do not accept an unbounded model-generated SQL string as a privileged execution instruction.
- The adapter enforces catalog/metric authority, row/column security, parameter binding, resource limits, result redaction and query cancellation with the external engine. A textual `SELECT` check is **not** a sufficient read-only or authorization guarantee (e.g. functions/export/UDFs can have effects).
- Read-only queries require actual data-source authorization. Mutating SQL, external exports and other protected effects additionally require EngageGuard's permitted action protocol. Neither ACP nor Decision self-approves.
- Query execution submissions require a stable invocation/idempotency identity. On an ambiguous timeout or lost ACK, inspect the query engine's authoritative operation status; never blindly resubmit a potentially costly or effectful query. Treat missing authoritative inspection as **UNKNOWN/manual review**.
- Return only typed status plus source-owned query execution, provenance, result and audit references. The query executor owns query/run state and result bytes. ACP merely relates these to its RunIntent and visibility policy.

### Not in scope

Building a SQL parser/optimizer/executor, semantic metric authority, database replication, a second agent framework, new Temporal replacement, ACP-owned action Permit, mutable copies of Runtime/Decision/Guard ledgers, or treating an EvidenceIndex as an audit/WORM compliance guarantee.

## Acceptance and negative tests (proposed, not completed)

| Gate | Minimum independently reproducible test | Evidence required |
|---|---|---|
| G01 ACP↔Runtime | Lost StartRun ACK and ACP/Runtime restart yield one canonical Run. Reuse key+digest; changed policy/actor/digest conflicts. Stale fence cannot persist a receipt. | Exact source SHAs, authenticated real-service PG/Temporal logs and correlated IDs |
| G02 Decision | Runtime-issued Run ID and immutable initiating context survive a Decision adapter call; an untrusted model output cannot mutate identity or authorize an action. | Cross-language versioned consumer fixtures |
| G03 Guard | Untrusted proposal cannot execute without one-time Permit; approval UI/cached policy does not grant access; duplicate/conflicting submissions and action UNKNOWN reconcile without a second effect. | Guard-owned receipt and real protected-execution test |
| Evidence | Same opaque source ID across tenants never crosses scope; revoked access denies retrieval; changed digest/source revision is rejected; missing provenance remains unverified. | Source-owner records + ACP reference-level tests + access-denial audit |
| Data port | One real engine adapter proves bounded authorized read, row/column security, budget cancellation, result digest/source snapshot, lost-ACK inspect, and DENY of raw unapproved or mutating SQL. | Connector version, semantic revision, engine execution ID, fixture and masked result evidence |
| G05 Golden Path | Restart and crash injection through ACP→Runtime/Temporal→Decision→Guard (where protected)→approved data connector, with no duplicate protected effect and an auditable evidence chain. | Separate unit, PG integration, cross-service and staging acceptance evidence |

**Evidence grading:** `DESIGNED` ≠ `IMPLEMENTED` ≠ `TESTED_AT_EXACT_HEAD` ≠ `LIVE_ACCEPTED`. A successful local manifest check does not certify live principal propagation, current source snapshots, protected execution or data-engine compliance. Revalidate after any head/base SHA, wire contract or policy change.

## Rollout order

1. Ratify identity and service-owned `StartRun/InspectRunIntent` protocol under ACP #10 and Runtime #20. Keep mutating ACP HTTP routes closed until authenticated durability/recovery exists.
2. Finish ACP Outbox/Inbox broker lifecycle, authenticated Runtime adapter, reconciliation worker, and operator quarantine/replay controls.
3. Introduce a **small, internal-only** immutable EvidenceRef model and repository once its source-owner, policy and retention decisions are agreed; do not expose a general evidence write API beforehand.
4. Add one read-only data execution adapter against an existing engine and semantic authority, with authorization and provenance tests; require Guard Permit before expanding to protected mutations.
5. Run G01–G05 exact-head and staging acceptance. Keep current stacked PRs Draft until their own gates are satisfied.

Decision is pending explicit review from affected owners. No production capability or cross-repository contract change is asserted by this ADR.
