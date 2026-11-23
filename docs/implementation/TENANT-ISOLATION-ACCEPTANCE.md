# P0 tenant isolation and execution-governance acceptance matrix

Status: **proposed acceptance contract; not a production security attestation**  
Baseline: `main` at 2026-11-22; all historical evidence and PRs must be rechecked at their exact source HEAD.  
Scope: ACP admission/authority plus independently owned Runtime, Guard, Sandbox/AgentD, credential broker and evidence consumers.

## Goal and authority boundaries

A tenant is not isolated merely because a row has `tenant_id`. A tenant-A principal must be unable to read, modify, resume, execute, attach to, receive credentials for, or export tenant-B state, including after a crash, replay, role change or temporary dependency outage.

ACP owns the authenticated Tenant/Project/Principal binding, catalog authorization, RunIntent and access-controlled references. Runtime owns Run/Checkpoint and Temporal histories. EngageGuard owns protected-operation authorization, approval/Permit/Operation and revocation. Sandbox Service/AgentD own sandbox and command lifecycle. A broker owns credential issuance and egress PEP. Evidence is not authority. Neither a model proposal nor a previously allowed RunIntent is a new protected-action Permit.

**Critical threat-model constraint:** a service role with broad raw SQL `SELECT` is not database tenant-isolated merely because the HTTP handler binds a tenant. `set_config('app.tenant_id', ...)` is useful trusted application context when guarded by authenticated server identity; it is **not**, by itself, an independent authentication oracle for arbitrary sessions. Temporal Namespace or Task Queue naming is also not a complete security boundary. Require server-side authenticated and authorized identities plus appropriately scoped DB/runtime access.

## Acceptance gates

| Gate / authority | Minimum positive control | Required cross-tenant / revocation negative control | Evidence / current status |
| --- | --- | --- | --- |
| G-T01 identity + admission (ACP) | Two real tenant catalogs; distinct authenticated OAuth clients and subjects; correct tenant/project/release/session admitted with exact input digest | Tenant B bearer cannot choose A's tenant or replay A's idempotency key; same logical resource names in A/B do not collide; revoked original client/membership cannot continue | ACP CatalogPolicy and real OAuth/PG test exist in non-production; #93 adds two-tenant tests but is **Draft**. Admission is not Guard Permit. |
| G-T02 data / DB (ACP and independently owned stores) | Independent non-owner PostgreSQL LOGINs with reviewed schema/table/column grants; tenant-owned queries and RLS USING/WITH CHECK verified where claimed | A login cannot SELECT/UPDATE/INSERT B's journal/metadata; cannot SET ROLE, change GUC, exploit PUBLIC grants, owner/BYPASSRLS, SECURITY DEFINER or cross-tenant JOIN; missing tenant binding denies all | Workspace tables have scoped FORCE RLS tests; `migrations/tests/0001_tenant_isolation.sql` tests aggregate key separation, **not** independent tenant LOGIN denial. DLQ v3 production journal tenant-RLS/role and restore gate remain open in Issue #20. #93 reader privilege guard is Draft and explicitly not DB-per-tenant raw SQL isolation. |
| G-T03 Run/Checkpoint/Temporal (Runtime) | One authenticated ACP RunIntent -> canonical Runtime Run and durable checkpoint; post-crash same binding and state | Foreign tenant cannot inspect, signal, resume, attach to Workflow, change namespace or steal worker/queue identity; worker restart after grant revocation does not grant protected execution | Historical same-Run Temporal probe and Decision continuation do not prove cross-tenant production execution or protected effects. Capture owning-service evidence, not ACP mock receipts. |
| G-T04 policy / approvals / Permit (Guard) | Model emits only an untrusted Proposal; policy/approval binds tenant, principal, Run, tool, version, exact action digest, resource and expiry; executor rechecks fresh Permit at irreversible boundary | Tool Binding escalation, changed arguments, stale epoch, revoked role/Permit, forged approval, replay after Worker restart, TOCTOU between approval and commit must deny; UNKNOWN must reconcile, never blind retry | Draft #91 defines an eight-observation post-fault gate and intentionally blocks when independent producers are absent. BreakerEpoch is **not** Guard authorization Epoch. No production Guard effect is proven. |
| G-T05 sandbox / command / credentials (Sandbox, AgentD, broker) | Separate authenticated lease/command scope, minimally privileged filesystem/network execution, lease generation and unique SandboxUID; broker supplies scoped short-lived credentials via references | Tenant B cannot attach A's process, read its workspace/artifacts/credential mounts, exploit reused UID or stale generation, use host-inherited credentials, metadata service, redirect/DNS/proxy bypass; revoked Permit denies new effects | Sandbox/AgentD and credential egress remain Issue #70/#71 release blockers. Same inode/readback and UNKNOWN must be observed by the actual service, not local fixtures. |
| G-T06 logs / evidence / exports (evidence consumers) | Signed/bound source observation; audit and retrieval APIs verify tenant/project/principal on the server; redaction and export access audited | A cannot retrieve B's trace, logs, transcript, context snapshot, EvidenceRef, S3 object or signed export by guessing IDs; no bearer/API key in evidence; missing origin or unverifiable signature denies release | No independently accepted full end-to-end cross-tenant evidence-export security test; do not use frontend filtering as proof. |

## Test data and execution protocol

Use disposable, independently authenticated tenant-A and tenant-B identities. Deliberately reuse the **same** visible project/agent/session/resource labels and idempotency string, but preserve globally unique opaque Run/operation identifiers. Record real server-selected tenant rather than accepting a client header. Start with A's legitimate admission, recover a crashed Worker, revoke an original membership/Permit, and exercise each denied B read, mutation, resume, credential request and evidence export. Include A/B positive controls to prove the test did not pass merely because all access was broken.

For each gate, save:

- Exact repository and Git commit of the **actual source under test**, branch/PR ancestry, CI workflow run, dependency/container digest, PostgreSQL/Temporal/IdP/Guard versions, and real service identity.
- Precondition and authorized positive control; forged/foreign/stale request; HTTP or gRPC status, PostgreSQL SQLSTATE and row count where applicable; immutable Run/Operation/lease IDs and server-side audit correlation.
- Verifiable artifact/trace hashes with secrets redacted, actual failure-injection timestamp, post-recovery identity/epoch binding, and independent verifier verdict.
- Distinguish `DESIGNED`, `CODE REVIEWED`, `LOCAL TESTED`, `REAL SERVICE TESTED`, `STAGING VERIFIED`, `PRODUCTION ACCEPTED`. **No inherited CI evidence from a parent SHA; no SKIP, synthetic fixture, or mock-only PASS counts as a real-service gate.**

## Risk-ordered delivery and release decision

1. **P0 / ACP:** independently review Draft #93's PostgreSQL authority reader privilege guard and genuine two-tenant admission/authority test. Keep its per-tenant raw SQL limitation explicit. Do not change existing checksum-pinned migrations in place.
2. **P0 / DLQ:** pursue Issue #20 using an additive reviewed migration/role provisioning and independent authenticated A/B LOGIN denial plus PostgreSQL dump/restore; do not treat test-only FORCE RLS as production installed.
3. **P0 / Runtime + Guard:** pin the same accepted Run and fault across independently trusted observations, enforce fresh authorization Epoch at commit after resume, separate the Runtime breaker epoch, reconcile UNKNOWN without duplicate effects. Draft #91 remains blocked until real service producers exist.
4. **P0 / Sandbox + broker:** complete Issue #70/#71, real isolated workspace and command journaling, least-privilege credentials and deny-by-default egress, then run the two-tenant negative matrix under actual service identities.
5. **P1 / evidence consumers:** add backend-enforced tenant query/export tests across trace, logs, Context, Evidence and object-store references. Use independent keying/access policy, redaction and expiry/rotation drills.

**Fail-closed release gate:** missing independent positive/negative proof for any protected effect or data export means `NOT VERIFIED`; no protected tool/credential/egress promotion, no production-isolation claim and no main merge solely on documentation. This document is a test contract, not a security sign-off. Cross-service owners must provide and independently review their own exact-head evidence.

## Interview-truth boundary

Safe statement: "I designed the identity-to-execution isolation layers and implemented/tested selected ACP admission, persistence, catalog and recovery mechanisms in a non-production prototype. I am explicitly tracking database raw-SQL privilege isolation, Runtime/Guard/Sandbox cross-tenant execution, credential broker and evidence export as remaining independent security release gates."

Unsafe statement: "Temporal namespaces provide tenant isolation", "all tables have tenant-isolated database roles", "the Guard/Sandbox end-to-end path is production-certified", or "an authenticated RunIntent authorizes subsequent protected tool calls".
