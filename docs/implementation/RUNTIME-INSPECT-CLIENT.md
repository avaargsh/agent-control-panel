# Runtime Inspect boundary — v1 compatibility and v2 full-binding recovery

## Current candidate: 2026-11-18, ACP #61 / Runtime #37

For a newly admitted RunIntent, ACP persists exact input bytes and a principal
snapshot before StartRun. The v1 correlation-only GET is insufficient
recovery proof: an earlier conflicting Runtime acceptance with the same
tenant/intent/digest may have a different principal, policy or input.

Use the authenticated, read-only `POST /internal/v2/run-intents:inspect`
with the **same strict v2 acceptance envelope**, built from the committed
ACP bytes and snapshot. Runtime derives the issuer from the verified peer,
and compares tenant, RunIntent, digest, Agent, Release, Session, normalized
JSONB input, snapshot version, Project, Subject, Actor, policy revision and
config digest in one committed SELECT. An exact match returns existing
Runtime-issued Run/Workflow IDs and `created:false`. An explicit mismatch
returns HTTP 409, including legacy Runtime Runs without the required
snapshot. Foreign tenant and unobserved committed acceptance remain
`ABSENT_UNCERTAIN`. This route cannot create a Run or issue a Permit.

ACP's ReconcileOnce selects the full-binding inspector for persisted input;
a missing v2 adapter, unavailable endpoint, corrupt input or invalid answer
cannot downgrade to GET v1. The explicit legacy NULL input path remains
development compatibility only. A lost conflict ACK must end in
MANUAL_REVIEW after authoritative inspection, not ACCEPTED. Absence/timeout
remains UNKNOWN and never permits StartRun retry.

Transport uses the same TLS 1.3/SPIFFE client and lease deadline;
no forwarded user credentials, redirects, automatic POST replay or proxy.
Raw task input is bounded and not emitted in audit or error messages.
Nothing in this read contract grants model/tool/sandbox egress.

Runtime pinned candidate: [#37](https://github.com/avaargsh/agent-runtime/pull/37),
`3b7b5579442a629a5b7a35962a5f2c0b2cfd4d42`,
[PG17/race verification](https://github.com/avaargsh/agent-runtime/actions/runs/44248994491).
ACP [#61](https://github.com/avaargsh/agent-control-panel/pull/61) contains
the exact pinned two-process proof; see its latest CI rather than assuming
that a prior head passed. Production IdP/catalog, least-privilege roles,
dispatch-time revocation, authorized runtime execution, independent review
and G01–G05 service-owner gates remain pending. No claim of final absence.

---

## Historical v1 design and initial evidence

The following section is retained as historical context, not as the current
input-bearing recovery contract.


Status: **local code and mTLS simulation verified; no deployed Runtime wiring, StartRun or cross-service production acceptance**.

Parent convergence: ACP PR #13 was merged on 2026-11-05 into the still-Draft
Inbox PR #7 branch. PR #14 was retargeted from the merged #13 branch to
`feat/inbox-consumer` (PR #7). This does not merge either PR into `main`.
Revalidate PR #14 against the current PR #7 exact head whenever the parent changes.

## Compatibility baseline

Observed Runtime implementation: `avaargsh/agent-runtime` commit
`489ab1140dc670fe32b82b50c2d28eba3927b353`,
`internal/acphttp/handler.go` and `internal/run/intent.go`.
This is an **implementation observation, not a ratified cross-repository wire contract**.
ACP [issue #10](https://github.com/avaargsh/agent-control-panel/issues/10)
and Runtime [issue #20](https://github.com/avaargsh/agent-runtime/issues/20)
must ratify the principal/policy context before adding StartRun.

The client issues only:

```http
GET /internal/v1/run-intents/{run_intent_id}?tenant_id={tenant_id}&request_digest={sha256_digest}
Accept: application/json
```

A `200 FOUND` response must contain exactly the returned tenant, RunIntent ID,
request digest, Runtime-issued UUID `run_id`, workflow
`agent-run/v1/{run_id}`, and `created` boolean. Malformed, duplicate-key,
unknown-field, changed-identity or inconsistent receipts fail closed.

The only valid current absence response is exactly
`{"status":"ABSENT_UNCERTAIN"}`. This is **not** a durable final-absence
barrier: it **must not** become ACP `RuntimeNotFoundFinal`, unlock
`UNKNOWN→PENDING`, or authorize a new StartRun. A Runtime 404, timeout,
bad TLS, 5xx, malformed response or invented `NOT_FOUND_FINAL` is also
not final absence. Explicit 409 maps to conflict; 401/403 maps to
denied service authentication/authorization. No ambiguous response mints
an ACP Run ID.

## Trust and deployment requirements

`runtimeinspect.NewClient` requires a single explicit HTTPS origin,
trusted roots, ACP client certificate and an exact expected Runtime SPIFFE
URI SAN. TLS 1.3 and the server's normal DNS/IP SAN validation are required
alongside the SPIFFE URI and verified certificate chain. Redirects and
environment-derived proxies are disabled. Inspect sends no human bearer
token or forwarded principal headers.

The caller is responsible for loading and rotating certificates securely,
restricting network access, configuring Runtime's corresponding ACP
workload allowlist, and wiring an authenticated durable response into
ACP's own tenant/policy-aware reconciliation worker. There is no public
write route or production listener in this PR.

## Evidence and remaining gates

- Go unit tests exercise strict JSON and scope correlation, bad statuses,
  uncertain absence, invalid identifiers and unsafe transport config.
- Synthetic TLS test server presents real CA-signed server/client
  certificates with SPIFFE SANs. Tests exercise TLS 1.3 mTLS, wrong Runtime
  SPIFFE identity and TLS 1.2 downgrade rejection.
- The local transport test does **not** prove connection to deployed
  `agent-runtime`, principal/policy snapshot integrity, Runtime temporal
  crash recovery, broker ACK/DLQ, quorum final-absence lookup or staging
  golden-path acceptance.
- Do not merge before parent #7 and upstream contract G01–G05
  acceptance. Evidence stays scoped to the exact PR head and CI run.

### Disposable public Issue round-trip

For a developer-operated integration check, use fresh loopback PostgreSQL
databases named `acp72_disposable` and `runtime72_disposable`, and an isolated,
TLS-enabled test realm (`/realms/acp-ci`) with the disposable issuer clients
defined in [the issuer fixture](../../scripts/test-real-oidc-admission.sh).
Set `ACP_DATABASE_URL` and `ACP_RUNTIME_DATABASE_URL` to the respective
`postgres://` DSNs with `sslmode=disable`. Set the `ACP_REAL_IDP_ISSUER`,
`ACP_REAL_IDP_CA`, `ACP_REAL_IDP_SECRET` and `ACP_REAL_RUNNER_SECRET` fixture
values. Build `./cmd/acp-api` from the verified Runtime commit
`037888dddc6de90de3a9a18dead86efbe8fbf0fb` and set `ACP_RUNTIME_API_BIN` to
that executable. Do not set `ACP_GOLDEN_PATH` or use long-lived infrastructure.

```sh
ACP_CROSS_SERVICE=1 ACP_REAL_IDP=1 ACP_DISPOSABLE_ISSUE_RECOVERY=1 \
  go test -race -count=1 -v -run '^TestDisposableIssueGoalLostACK$' ./internal/runtimeinspect
```

The test reads public `avaargsh/tmp#1` and its pinned main commit, submits
through the ACP HTTPS handler, and verifies same-request replay and denial
after disposable membership revocation. It then drops a successful Runtime
acceptance response, kills and restarts the Runtime API, and recovers the
same Run after killing an ACP reconciler. The resulting database contains
one Run, one start request and one matching principal snapshot. The public
repository is read-only in this test. It does not consume the start request,
execute tools, start Temporal, grant a permit, or prove a production release.
Discard both databases and the issuer realm after the run.
