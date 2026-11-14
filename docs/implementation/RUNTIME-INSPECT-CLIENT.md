# Read-only Runtime Inspect boundary — Draft PR #14, based on Inbox PR #7

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
