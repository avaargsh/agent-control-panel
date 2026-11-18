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
