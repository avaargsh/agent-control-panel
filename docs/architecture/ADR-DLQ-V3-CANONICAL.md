# ADR — Canonical ACP DLQ disposition v3

Status: Proposed / repository-tested; not independently accepted.
Owner: agent-control-panel Inbox / RunIntent.
Governance: https://github.com/avaargsh/agent-control-panel/issues/21
Baseline: https://github.com/avaargsh/agent-control-panel/pull/18
Hardening: https://github.com/avaargsh/agent-control-panel/pull/22
Competing alternative: https://github.com/avaargsh/agent-control-panel/pull/19

## Decision

Use exactly one version-3 migration: **0003_inbox_dlq_dispositions.sql** and **inbox_dlq_dispositions**.
Preserve composite delivery key (source_stream, source_consumer, source_sequence), immutable event_id UUID NOT NULL, and separate frozen tenant_id and ACP consumer_name.
Tenant_id or consumer_name in an Inbox row is evidence metadata, never an authentication oracle.
Do not merge #18 and #19 sequentially: they allocate conflicting v3 migration names, checksum histories and table/event schemas.
Port compatible safety controls from #19 into the #18 lineage, not duplicate v3 migrations.

## Mandatory invariants

- Immutable source, event, tenant, reason, SHA256, target and exact evidence.
- Monotonic publish_started and published, no silent recovery of UNKNOWN.
- Startup attestation: PK, critical CHECK expressions, event_id UUID NOT NULL, full nonconditional row and statement triggers, immutable trigger function source and security attributes.
- Verify journal relkind is an ordinary table and relpersistence is permanent; reject UNLOGGED/temporary/shadowed relations.
- Explicitly revoke PUBLIC table/function grants and reject any later privilege drift.
- Production writer must use an independent non-owner LOGIN role with authenticated broker-to-tenant binding, tenant-scoped reads and minimal writes.

## Versioned rollout and acceptance

The Draft v3 SQL includes new explicit revocations, changing its SHA256. Do not silently alter a recorded v3 history in any deployed database. If any prior v3 checksum has been applied, stop and plan a separately reviewed additive v4 forward migration plus restore and role-grant procedure.
The JetStream POC still writes a separate disposable poc_dlq_dispositions relation and is not upgraded by this change. No production adapter, authorization, Permit, side-effect exactly-once guarantee or automatic UNKNOWN reconciliation is implied.
Require exact integrated-head PostgreSQL16, Go race/vet/gofmt, broker failure injection, independent migration/runtime DB LOGIN roles, restore, broker mTLS/ACL/HA and cross-service G01/G05 staging before promotion.
Track remaining broker evidence in issue #16 and IAM/restore in issue #20.
Keep PR #18 and #22 Draft. Close #19 unmerged only after the compatible security properties are transferred and reviewed.

## Tenant-scoped LOGIN/RLS gate — 2026-11-10

The canonical v3 journal is an immutable evidence store, **not** an authenticated tenant boundary. Its restricted PostgreSQL role can hold table-wide `SELECT` and publication-state `UPDATE` grants. Independent `LOGIN` credentials alone cannot prevent tenant-A users from reading, modifying, or inserting tenant-B journal records.

[Executed RED #42726358578](https://github.com/avaargsh/agent-control-panel/actions/runs/42726358578) on the existing #17 branch proved all three cross-tenant accesses with a real non-owner, non-BYPASSRLS PostgreSQL login. [Test-scoped GREEN #42726701025](https://github.com/avaargsh/agent-control-panel/actions/runs/42726701025) proved that an **owner-provisioned** role-specific `CREATE POLICY ... TO <login>` with exact tenant `USING` and `WITH CHECK`, `ENABLE ROW LEVEL SECURITY`, and `FORCE ROW LEVEL SECURITY` denies cross-tenant SELECT/UPDATE/INSERT. This policy exists **only inside the disposable integration-test schema**. Neither the canonical v3 SQL checksum nor production IAM changed.

Before any production rollout, require an independently reviewed additive forward migration, **not an edit to v3**:

- Specify the trusted broker origin → tenant → independently authenticated PostgreSQL `LOGIN` binding and its provisioning, rotation, revocation, and role-membership rules. Do not use client-settable `app.tenant_id` or another untrusted session GUC as authorization authority.
- Install tenant-scoped read/write RLS for the journal with both `USING` and `WITH CHECK`, `ENABLE` plus `FORCE`, non-owner `NOBYPASSRLS` runtime roles, and only reviewed table/column grants. Make an absent or unknown role-to-tenant binding deny all access.
- Prove tenant A and B access denials with **separate authenticated sessions**, including SELECT invisibility, UPDATE row-count zero, INSERT `42501`, prohibited tenant reassignment, DDL/trigger tampering, inherited grants/role switches, and correct authorized writes.
- Test production-shaped RLS policy/catalog attestation at startup, invalid/missing role bindings, real PostgreSQL dump/restore with policies/grants retained, and authentication through the service/broker boundary. Do not use superuser-only test sessions as tenant isolation proof.
- Record the migration version, restore/rollback plan, affected installed v3 checksums, owner/security review and staging G01/G05 evidence before upgrading release readiness.

Current decision: **test feasibility established; production tenant authority and versioned policy migration not accepted.** Keep ACP #17 Draft and ACP Issue #20 open.
