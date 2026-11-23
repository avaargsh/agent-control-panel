# RunIntent admission boundary (development only)

Tracks [ACP #10](https://github.com/avaargsh/agent-control-panel/issues/10) and [Runtime #20](https://github.com/avaargsh/agent-runtime/issues/20).

## Current implementation

ACP owns tenant/project/release/session/RunIntent identity and admission
policy. Runtime alone issues canonical Run/Workflow/Attempt/Turn identities.
No admission result is a protected action Permit.

- The historical digest-only `Service.Admit` remains development
  compatibility, not a new-run production entrypoint.
- `AdmitWithInput` validates bounded JSON and computes the exact byte-bound
  digest before authorization. The authenticated Resolver may not supply a
  different target or digest. PrincipalSnapshot is server-derived.
- `Introspector` authenticates direct bearer credentials via HTTPS RFC 7662:
  exact issuer, audience, expiration, bearer type, verified client and scope.
  Unsupported delegated or proof-of-possession credentials fail closed.
- `CatalogPolicy` resolves the external issuer/subject and OAuth client
  against the current ACP-owned tenant, project, principal, RUNNER role,
  enabled AgentRelease and session ownership. No caller-supplied role or
  policy decision becomes authority. `CreateWithCatalog` repeats the lookup
  under PostgreSQL row locks and checks expiration after acquiring them.
- Input, snapshot, RunIntent and minimal Outbox event commit atomically.
  Every exact replay reauthenticates and reauthorizes; a revoked membership
  or changed binding cannot append another event.

The adapter sends no human bearer token to Runtime. No public mutating API,
production dispatch, Guard Permit or provider release is enabled here.

## Live identity-provider acceptance

[ACP #62](https://github.com/avaargsh/agent-control-panel/pull/62) provisions
a disposable, loopback-only HTTPS Keycloak **26.8.2** issuer for
`client_credentials` and RFC 7662 with separate test runner/resource-server
clients. A fresh CA and random client secrets are generated inside the job;
they are never production credentials or embedded in the source. The
successfully observed image digest is pinned in the script.

From a clean candidate checkout on a machine with Docker, OpenSSL, Python,
Go matching go.mod, curl and an **isolated** PostgreSQL database:

```sh
PGTEST_DSN='postgres://postgres:<test-password>@127.0.0.1:5432/acp_oidc?sslmode=disable' \
  bash scripts/test-real-oidc-admission.sh
```

The script creates and removes its own temporary issuer/CA, checks HTTPS
OIDC discovery, and runs the exact live test with integration explicitly
enabled. Do not run against a production database. The test mints real
service-account access tokens, validates issuer/audience/client/scope,
rejects invalid tokens, commits the exact input and one Outbox row, denies
missing scope and role revocation on replay, and waits for actual access
token expiration. No test skips on missing enabled environment
configuration.

Historical live evidence:
[`dd8b3a66df0a6bc11f772059b697b69c2dad7a02` / #44249476537](https://github.com/avaargsh/agent-control-panel/actions/runs/44249476537):
the actual test executed and passed in 32.09s. The separate Go format
job failed and was corrected; subsequent exact-head verification is
required, not inherited. See current PR checks before claiming acceptance.

This proves real disposable OAuth service-account authentication and
catalog admission only. Interactive end-user OIDC code/PKCE, live
production IdP, signing/rotation and dynamic revocation, immutable
Release provisioning, database role isolation, public HTTP admission,
dispatch-time reauthorization and owner-ratified cross-service contracts
remain release gates. No protected effects or independent verifier are
authorized by this test.

## v12 catalog origin and current continuation authority (ACP #64)

The preceding admission and real issuer sections describe the staged
Golden Path: immutable execution input, actual issuer introspection/catalog
admission, authenticated Runtime StartRun and UNKNOWN reconciliation.
See exact evidence in the P0 roadmap. v12 adds the following current
authority boundary without changing ownership:

- Commit the verified historical OAuth issuer, external subject and exact
  client ID in the same transaction as RunIntent, input and Outbox. Never
  store bearer/refresh tokens or client secret. A legacy NULL origin
  cannot acquire an origin by UPDATE or a new-style replay.
- Same tenant/principal/idempotency key, same target and digest but a
  different authenticated client conflicts. The actual original catalog
  membership is required on each fresh continuation read, even if another
  client for the same principal remains a RUNNER.
- A trusted internal reader resolves only ACCEPTED RunIntent matching
  tenant, RunIntent ID, request digest, canonical Runtime Run/Workflow ID,
  original issuer/subject/client membership, enabled owner/session/release/
  project/tenant, original policy/config and exact persisted input digest.
  The response is an ACP catalog observation, never a Runtime lifecycle
  fact or a Guard authorization.
- Historical OAuth authentication is not a live Token introspection. The
  token lifetime governs admission; durable continuation is scoped by the
  current catalog. Issuer-side token/session revocation propagation,
  long-lived run expiry policy, delegation/actor changes, distributed
  Permit revocation and the TOCTOU between read and dispatch remain open.

### Authenticated read-only service

Opt-in internal binary `cmd/acp-authority-api`:

```text
ACP_AUTHORITY_DATABASE_URL       # dedicated read-only role; never an Agent credential
ACP_AUTHORITY_TLS_CERT
ACP_AUTHORITY_TLS_KEY
ACP_AUTHORITY_CLIENT_CA          # dedicated workload trust-domain roots
ACP_AUTHORITY_PEER_SPIFFE_ID     # exact authenticated Decision/Runtime workload
ACP_AUTHORITY_TENANT             # one operator-configured tenant
ACP_AUTHORITY_LISTEN_ADDR        # default 127.0.0.1:8444
```

The separate migration job applies v12 using the existing checksummed
runner. The service never migrates; its DB connections default to
read-only. Grant only schema USAGE and SELECT on the needed
`run_intents` and admission catalog relations, never write, TRUNCATE,
DDL or schema ownership. A dedicated LOGIN and actual write denial are
tested in the isolated live CI; production grants/rotation/RLS remain
deployment gates.

PostgreSQL grants database-level `TEMPORARY` to `PUBLIC` on a new
database by default. The dedicated authority-reader database must have
`REVOKE TEMPORARY ON DATABASE <dedicated_db> FROM PUBLIC`, and the
reader LOGIN must not receive direct or inherited TEMP rights. Otherwise
the reader can create a temporary relation called `run_intents`, which
PostgreSQL searches before the configured application schema when
executing unqualified table names. The startup/per-request role guard
now refuses a LOGIN with effective database-level TEMP privilege, even
if its seven application relation SELECT grants are otherwise exact.
This is a **database provisioning requirement**: do not revoke PUBLIC
TEMP on an unrelated shared production database without an impact
assessment. The real PostgreSQL regression uses an isolated disposable
database for all privilege-changing cases.

The authority service now additionally **fails at startup** if its actual
PostgreSQL LOGIN is privileged (superuser, BYPASSRLS, role/database creator),
can create objects in any non-system schema, has database-level CREATE
privilege (which permits making new schemas), can invoke an owner-privileged
SECURITY DEFINER routine in a reachable non-system schema through effective
schema USAGE and routine EXECUTE (including default PUBLIC EXECUTE),
has effective SELECT/USAGE/UPDATE on a PostgreSQL sequence in any non-system
schema (including grants via PUBLIC), owns or inherits ownership of its
schema/tables, lacks any of its seven required SELECT grants, or has write
privileges or additional application-table reads in that schema. Both table-
level and effective column-level grants are checked, including `PUBLIC` grants:
a column-only `SELECT` on Outbox or a column-only `UPDATE` on RunIntent is
still an excessive authority and must fail startup. A dedicated LOGIN must
also have no database role memberships: a `NOINHERIT` membership with
`SET ROLE` can escalate after startup even when initial effective table
privileges appear limited. The separate
`TestAuthorityDatabaseRoleFailClosed` uses a real, independently authenticated
LOGIN in an isolated PostgreSQL test database, then adds and revokes excessive
grants to prove the gate changes its decision, including actual CREATE TABLE
in a foreign schema and CREATE SCHEMA using a database-level grant.
A further negative case creates a real SECURITY DEFINER SQL function that
reads an otherwise inaccessible foreign table: the independently authenticated
reader can call it through PostgreSQL's default PUBLIC EXECUTE, but the role
startup gate now must reject it; revoking PUBLIC/direct EXECUTE restores the
least-privilege state. This tests **effective callable routines**, not routine
presence alone. PostgreSQL sequence privileges are a separate ACL class:
a dedicated reader with foreign-sequence USAGE or UPDATE can actually
advance persisted sequence state via `nextval()`, while SELECT can read
`last_value`. The real PostgreSQL **RED** in
[Actions #44994581526](https://github.com/avaargsh/agent-control-panel/actions/runs/44994581526)
showed all three sequence grants were wrongly allowed by the previous
table/function-only startup guard (`allowed=true want=false`). The
negative suite now requires denial with a grant and successful restoration
plus PostgreSQL SQLSTATE 42501 after each REVOKE. These are executed CI
regression cases, not a claim that
startup validation continuously monitors future grants. It requires `PGTEST_DSN` and is
**not** a production deployment or a substitute for tenant-specific RLS.
A compromised authority service with this read-only role could still read
other tenants' rows in its granted tables via raw SQL: the mTLS service's
server-side configured tenant and exact predicates protect its public
response, not arbitrary SQL issued by a compromised process.

### Multi-tenant isolation: release-blocking acceptance matrix

| Boundary | Existing ACP authority | Required closure / negative proof |
| --- | --- | --- |
| Identity and resources | OAuth introspection, exact issuer/subject/client, tenant/project/agent/release/session catalog joins, transactional admission recheck | A and B have real memberships and duplicate logical selectors; A cannot submit, replay, inspect or mutate B; no caller/header/URL-derived tenant authority; dedicated migrations and DB role hardening |
| Run state | ACP holds RunIntent and verified Run references; Runtime owns Run, Temporal workflows, checkpoints and context | Runtime independently binds Tenant+Project+AgentRelease+Session+Run to persisted state; reject foreign workflow lookup, checkpoint restore, TaskQueue dispatch and session replay; test restarted Worker with both tenants present |
| Tool and protected actions | ACP publishes release-bound capability evidence; no ACP model-selected permit | Decision/EngageGuard validates exact action scope, resource, Run, policy revision and authorization epoch before every protected effect; revoked and foreign-tenant permits must fail after a paused/recovered Run; UNKNOWN remains unresolved until authoritative reconciliation |
| Execution substrate | ACP contracts only; Sandbox/AgentD and Compute own physical isolation and operations | Namespace/workload identity, secrets broker, egress deny-by-default, workspace/object-store key policies, quota, independent tenant credentials and post-SIGKILL cleanup; prove tenant A cannot read B files, secrets, network endpoints or GPU allocations using real enforcement |
| Evidence, logs and usage | Scoped RunIntent/Outbox identity and signed publication references; no unified tenant audit reader | Tenant-aware authorization at query/export paths (not frontend filtering), redaction, encryption, audit of denied reads, immutable correlation and isolation of billing aggregates; prove cross-tenant query, cursor, trace, object-store and export denial |

A database `tenant_id` predicate is not itself RLS. Existing scoped
Workspace/lock tables have targeted policies, but this repository does **not**
claim row-level isolation of every RunIntent, Outbox, catalog or telemetry table.
Do not roll out global `FORCE ROW LEVEL SECURITY` without first giving
admission/dispatcher/publisher distinct non-owner roles, transaction-scoped
trusted authorization context, and regression tests for async workers. An
application-settable `app.tenant_id` is not an authentication boundary.

The minimum **two-tenant Golden Path** is: provision independently authenticated
A/B identities and identical user-visible resource names; admit A; spoof B
in headers, payloads, Run and checkpoint IDs, tool arguments, approval epochs,
sandbox paths, observability queries and exported evidence. Every foreign
operation must return 403/404 or another documented fail-closed result with
zero foreign rows/bytes and no protected side effect, while legitimate same-
tenant work, replay and Worker recovery continue to succeed. Record the
exact ACP/Runtime/Guard/Sandbox commit SHAs, actual role identities, test
artifacts and denied-operation audits. No G01–G05 or production multi-tenant
security certification is implied by this single ACP-side role gate.

`GET /internal/v1/run-authority/{run_intent_id}?run_id=...&request_digest=...`
requires verified TLS 1.3 and the exact configured SPIFFE peer. Tenant is
never a request field. It returns version `acp.run-authority.v1` with
tenant/RunIntent/Run/request digest, project/agent/release/session,
principal/subject/actor, policy revision and config digest, no input,
OAuth origin or permit. On missing/revoked/foreign/mismatched authority
return 403, malformed selectors 400, unverified caller 401, unavailable
or corrupt authority 503. No stale cache. Clients must validate exact
server CA/hostname/SPIFFE, full binding and schema; must recheck at any
protected execution boundary. No production service is enabled.

### Reproducibility and remaining gates

Standalone original-client regression in
`admission_origin_replay_integration_test.go` runs on the exact pre-fix
source and candidate in `admission-origin-regression.yml`; require the
specific behavior RED marker and actual candidate PASS, not a compiler
failure or Skip. Full PostgreSQL test covers current revocation/config
changes and legacy/adoption/downgrade rejection. Same live issuer
acceptance CI uses actual Runtime recovery, then a separately compiled
ACP authority API with real mTLS and read-only LOGIN; it does not invoke
Decision Core or issue permits. Historical catalog-only evidence at
`a94e8b232ccfce51837c50bbef511f152a00cada`:
[real OAuth cross-service](https://github.com/avaargsh/agent-control-panel/actions/runs/44253509357)
and [Go/PG16](https://github.com/avaargsh/agent-control-panel/actions/runs/44253509424)
PASS. Inspect current exact-head CI for the subsequent network service.

Next: publish actual immutable release-bound Context and Capability
snapshots and independent evidence provenance, implement authentic
Decision Core principal/authority adapter and a durable checkpoint
continuation, with independent verification before Guard/Sandbox/tool
egress. Do not substitute the new ACP authority observation for those
missing facts or mark the entire enterprise Golden Path complete.
