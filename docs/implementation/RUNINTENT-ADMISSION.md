# RunIntent admission boundary (development only)

Tracks [ACP #10](https://github.com/avaargsh/agent-control-panel/issues/10) and [Runtime #20](https://github.com/avaargsh/agent-runtime/issues/20).

## Implemented internal contract

`internal/admission.Service.Admit(ctx, request)` accepts only resource selectors (Tenant/Project/Agent/Release/Session), an idempotency key and a proposed request digest. It has no caller-controlled principal, policy, configuration snapshot or Runtime identity fields. The host must inject a trusted Resolver and PostgreSQL repository. No default resolver or HTTP endpoint is provided.

1. Validate request shape before consulting the resolver.
2. Resolve the authenticated principal, effective subject/actor, policy revision, canonical request digest and immutable configuration from trusted sources. Resolver errors deny admission. An assertion with a different target or digest is rejected.
3. Validate the nonzero principal snapshot and immutable identity. Generate only ACP-owned UUIDs (RunIntent and Outbox event), not Run/Workflow IDs.
4. Use the existing Repository.Create transaction to commit the PENDING RunIntent, snapshot and creation event together.
5. Re-resolve authorization on every replay. A denied replay writes nothing; a changed immutable snapshot with the same tenant/principal/idempotency key is an idempotency conflict. The repository returns the original identity on an exact replay.

The Outbox payload contains only the RunIntent ID, not raw prompts, credentials, or claims. The digest must be independently computed/verified by the trusted Resolver; merely echoing client input is not a valid implementation. A successful admission is neither Runtime acceptance nor protected-action authorization.

## Tests and evidence

The regression suite covers positive admission/event correlation, malformed selector rejection before resolution, each target mismatch, digest mismatch, missing/invalid principal snapshot, and denial without persistence. The real PostgreSQL test covers exact replay, policy revocation on replay, changed policy revision conflict and one durable intent/Outbox event.

Do not infer any passing test status from this document. Inspect the exact PR head's CI results, including the PGTEST_DSN-enabled suite.

## Remaining release gates

- Implement and independently review the actual authenticated principal/policy resolver with issuer/audience, credential lifetime, actor delegation, tenant/project, release and immutable request/config authority.
- Persist and retrieve the immutable execution input/reference according to the owner-ratified ACP/Runtime contract; this slice stores only the digest, not input bytes.
- Ratify the service-owned wire schema and implement the authenticated StartRun adapter plus joint PostgreSQL/Temporal lost-ACK and restart tests.
- No public mutating API, production dispatch, G01/G05 promotion, Guard Permit issuance, or provider release is enabled by this change.


## v12 catalog origin and current continuation authority (ACP #64)

The preceding description records the initial development slice. The staged
Golden Path now implements immutable execution input, actual issuer
introspection/catalog admission, authenticated Runtime StartRun and
UNKNOWN reconciliation; see the exact evidence in the P0 roadmap. v12
adds the following current authority boundary without changing ownership:

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
