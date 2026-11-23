# AgentD mTLS Read-Only Evidence Export (candidate, Draft PR #113)

This is **not a production command execution API**. It is an optional same-Run, source-only read service layered on the independent Sandbox/AgentD journal implemented by Draft [#108](https://github.com/avaargsh/agent-control-panel/pull/108) and [#111](https://github.com/avaargsh/agent-control-panel/pull/111). The ACP G05 source-signature consumer is independently implemented in Draft [#112](https://github.com/avaargsh/agent-control-panel/pull/112). No `main` branch merge or production deployment is implied.

## Endpoint

`POST /v1/agentd/evidence:read` with exactly one canonical JSON `{"ref":{...}}` containing the complete immutable original attempt `Ref` (Tenant/Run/RuntimeAttempt/Sandbox/Command/Attempt/ProviderUID/request digest/PermitID/Epoch/original PID/boot ID/start ticks). JSON duplicate fields, unknown extras, forged headers, large bodies, method aliases and ambiguous path variants are rejected. No request may invent a new CommandID or trigger a dispatch.

**Transport and peer identity** are independently configured by the server operator: use a TLS listener with `RequireAndVerifyClientCert`, a tightly scoped client certificate CA and TLS 1.3 where available. The handler additionally requires `r.TLS.VerifiedChains` to contain a verified peer chain, **exactly one** URI SAN and an exact workload URI of:

```text
spiffe://<configured-trust-domain>/tenant/<TenantID>/run/<RunID>/role/evidence-reader
```

A CN, HTTP header, JSON `tenant_id`, generic organization certificate, or caller-selected trust domain **does not confer identity**. The exact cert scope is tied to the original immutable Run/tenant before any source read occurs. It is a candidate path convention, not proof that a real SPIFFE/SPIRE issuer or workload attestor has been deployed.

**Trusted Head**: the source export constructor requires `PinnedHeadLookup` injected by a trusted authority *outside the candidate source database and request*. A test static callback models a future ACP-accepted exact head, and is not a production distribution/revocation service. Missing, stale, truncated, untrusted or mismatched source event Head rejects export. The handler never falls back to the source Journal's own advertised Head. Each handler instance is backed by a per-tenant PostgreSQL LOGIN pool; the authenticated login-to-tenant map is owner-only, and RLS resolves tenant scope from immutable `session_user`. A caller-settable GUC cannot switch the tenant. The handler rejects a pool whose database LOGIN is mapped to a different tenant. Additive migration 0016 (without modifying 0015) pins each authorized LOGIN to its original PostgreSQL role OID and rejects revoked or stale role mappings; a failed or unapplied 0016 keeps evidence reads disabled.

**Source authenticity**: the handler queries the original immutable attempt and full `agentd.inspect` history in a read-only transaction, independently verifies AgentD's Ed25519 source signature, schema, SHA256, complete count/revision/hash chain, and pinned terminal Head. It returns the original signed payload bytes as Base64, without reserializing signed JSON. A terminal receipt is exported **only if** the latest signed Inspect event is `EXITED` or `FAILED_CONFIRMED` and an independently signed, durably committed OS Wait has matching status/digest. If the original OS Wait has already committed a terminal receipt but the most recent signed Inspect remains UNKNOWN, the HTTP Handler returns **409** and exports no signed evidence; after a fresh committed Inspect, terminal export may succeed. If the source itself remains consistently unresolved, only `UNKNOWN/HOLD` with no terminal or Retry is returned. The HTTP read creates zero new `agentd.inspect` events.

**Bounded:** request body is capped at 8 KiB, returned chain at 256 events. Without a cryptographically proven pagination/segment checkpoint protocol, too-long histories are **BLOCKED** instead of being truncated to an apparently complete proof. All successful and error responses set `Cache-Control: no-store`.

## Forward-only 0015 → 0016 authorization migration (fail-closed)

**Do not blindly migrate existing 0015 reader mappings.** Historical `0015` only stores `login_role` + `tenant_id`; an authenticated PostgreSQL LOGIN may have been dropped and recreated under the same name **before** 0016 runs. The current `pg_roles.oid` is not evidence of the original grant owner. Automatically filling `login_oid` by name would grant the replacement principal another tenant's access.

1. **Stop/quiesce AgentD evidence HTTP readers** and revoke old read-role access before making any authorization changes; do not keep the old `0015` name-based read endpoint active during migration. Preserve a secure out-of-band owner-approved binding inventory and PostgreSQL audit trail. Do not treat caller-submitted `app.tenant_id` as an identity.
2. As the trusted DB owner, **explicitly revoke each old name-only mapping** while still on the historical `0015` schema, using the approved inventory to confirm which LOGIN was previously allowed. No automatic deletion is performed by the migration itself. Operator must inspect and approve any exceptional legacy roles first.
3. Run `0016_agentd_reader_login_oid_fence.sql` in a transaction. It adds `login_oid` and **raises SQLSTATE 23514** if even one unverifiable `NULL` mapping remains. The whole migration rolls back, including the newly added column; failure is not a partial success. Never override the condition by guessing the OID.
4. After a clean upgrade, the owner individually verifies the replacement LOGIN/tenant and **enrolls an explicit `(login_role, login_oid, tenant_id)` tuple**. The role must be independently authenticated and have only the dedicated read-only group membership and the required source SELECT privileges. A renamed/recreated LOGIN must not regain an old mapping implicitly.
5. Re-enable reader traffic only after verifying exact role OID, TLS Tenant/Run URI scope, tenant-A/tenant-B RLS negative cases, revoked mapping, missing Head and real source signature chain. If any step fails, keep the endpoint unavailable and the overall G01–G05 gate **BLOCKED**.

In disposable PostgreSQL CI, `TestAgentDEvidenceReaderOIDUpgradeRequiresExplicitReenrollment` reproduces a real `0015` role-name replacement: migration must fail atomically, explicit owner removal of the old binding enables the upgrade, and only new deliberate enrollment can create another mapping. This is **not** a claim that production credentials or legacy deployments have been upgraded. In any environment that has **already recorded 0016** as applied, never edit that recorded migration in place; introduce a subsequent audited migration/repair instead. This PR's 0016 is still Draft and not merged into main.

## Real test boundary

The CI suite uses a disposable PostgreSQL 16 database owner (not a real production AgentD role), actual Linux OS child processes and `Wait` receipts, an ephemeral TLS CA issuing client-auth certificates with different run/tenant URI SANs, real `httptest` TLS mutual handshakes and source Ed25519 signatures. Tests cover live UNKNOWN/HOLD, committed real terminal, independent Head staleness, correct TLS source identity, wrong Run/tenant, no peer certificate, untrusted AgentD key and foreign AttemptID. Tests do not exercise a deployed mesh proxy or real production certificate issuer.

## Release and security blockers (fail-closed)

1. Missing actual authenticated Guard Permit issuer, runtime Tool Binding, epoch fencing and executor PEP prior to any command effect; this PR deliberately has **no dispatch endpoint**.
2. The source writer remains owner-controlled. Draft #113 adds a dedicated `NOLOGIN` read-only group role and a separate LOGIN per tenant. An owner-only login-to-tenant map plus a narrowly scoped `SECURITY DEFINER` resolver binds RLS to immutable `session_user`; caller-settable GUCs are deliberately ignored. The handler rejects owner/overprivileged identities and verifies that the pool LOGIN maps to the mTLS peer tenant. Production role provisioning, per-tenant credential custody and independent deployment remain operator obligations.
3. No real provisioned private signing keys, key rotation/revocation, trusted SPIFFE issuer, workload attestation or configured production mTLS listener (the handler tests use ephemeral identities).
4. No independent, write-protected accepted Run/Guard binding and exact signed Head distribution integrated into ACP's live G05; the injected callback remains a trusted contract, not a deployed service.
5. No source-owned signed sandbox workspace continuity, independent Runtime/Guard postfault reconcilers, authenticated original same-Run response assembler, physical Compute/Sandbox provider-absence or cost FINAL evidence.
6. An OS Wait terminal does not prove remote side effects are undone. A durable inspect event does not grant authority to retry a command. **UNKNOWN/HOLD must remain sticky on uncertainty.**

Do not replace `G01–G05 BLOCKED` with a synthetic green E2E. Do not merge to `main` without exact-HEAD CI, actual server-enforced branch protection and review restrictions, authentic same-Run source evidence, and policy/production checks. Independent human security review is recommended but not an extra synthetic hard approval count.
