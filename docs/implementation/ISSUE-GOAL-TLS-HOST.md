# M0 GoalSubmit opt-in TLS host (candidate, no Runtime dispatch)

**Status:** candidate feature on stacked PR #86. This command starts a real TLS listener but only accepts a PostgreSQL-authoritative ACP **RunIntent**, not a Runtime Run, Agent execution, GitHub pull request, Guard Permit or approved release. It is not enabled in the default read-only ACP binary. Do not call this production ready without independent review and live provider acceptance.

## Authority wiring

`cmd/acp-goal-api` composes existing implementations, without creating any additional identity, database, workflow or permission authority:

```text
Client POST /api/v1/goals:submit (direct TLS; local loopback only)
    → strict immutable Issue Goal proposal and opaque Bearer header
    → TLS-validating OAuth RFC7662 introspection + ACP CatalogPolicy preflight
    → exact trusted tenant/project/agent/release/session + repo/branch/rules/budget scope
    → read-only public api.github.com Issue and pinned commit/branch checks
    → fresh OAuth/CatalogPolicy resolution and DB-row-locked authorization
    → one ACP PostgreSQL RunIntent + Outbox, or exact idempotent replay
    → HTTP 201/200 (run_intent_id, NOT runtime_run_id)
```

The host fails closed on missing config, wildcard/non-loopback listeners, absent TLS key/cert, a certificate whose validity window, SAN, key usage or EKU does not match the listener, missing/overly permissive/symlinked secret files, untrusted IdP CA, incorrect source selector and absent migrated DB tables. The TLS certificate must be valid for the exact numeric loopback address (normally `127.0.0.1`) used by `ACP_GOAL_LISTEN_ADDR`. The outbound GitHub hostname is fixed by `issuegoal.PublicIssueReader`; no caller-provided GitHub token, private repo or redirect is supported.

## Run in an isolated development environment

Prerequisites: Go pinned by `go.mod`, PostgreSQL 16 with all ACP migrations applied by a **separate migration job**, a catalog containing authorized tenant/project/release/session/principal/membership, an OAuth introspection issuer with a trusted CA and client credentials, and a direct TLS server certificate for `127.0.0.1`. The server itself **will not create a database schema, bootstrap users or mint OAuth tokens**. Before binding, it checks the complete RunIntent/Outbox/admission catalog relation set and verifies that every embedded migration has exactly one matching ledger entry with the expected version, filename and SHA-256 checksum (including `version=12, name=0012_run_intent_admission_origin.sql`). Missing, extra or checksum-drifted migration history is rejected. `ACP_GOAL_ENV` defaults to production semantics; `ACP_GOAL_ALLOW_UNPROTECTED_TEST_BRANCH=true` is accepted only when `ACP_GOAL_ENV=development` or `test`, and must never be used in production.

Keep database DSN and OAuth introspection secret in private local files. The host requires the files be regular, nonempty, at most 64 KiB and not readable by group/others (for example `chmod 0600`). Do not commit either file. For a remote PostgreSQL host, the DSN must enable verified TLS. Local PostgreSQL can use Unix sockets or loopback in the isolated test environment.

```sh
# The following paths and identifiers are EXAMPLES: supply real operator resources.
export ACP_GOAL_LISTEN_ADDR=127.0.0.1:9443
export ACP_GOAL_TLS_CERT_FILE=/run/acp/tls/server.crt
export ACP_GOAL_TLS_KEY_FILE=/run/acp/tls/server.key
export ACP_GOAL_PG_DSN_FILE=/run/acp/secrets/postgres-dsn
export ACP_GOAL_OAUTH_CA_FILE=/run/acp/ca/issuer-ca.pem
export ACP_GOAL_OAUTH_ENDPOINT=https://issuer.example/realms/acp/protocol/openid-connect/token/introspect
export ACP_GOAL_OAUTH_ISSUER=https://issuer.example/realms/acp
export ACP_GOAL_OAUTH_AUDIENCE=acp-control-plane
export ACP_GOAL_OAUTH_CLIENT_ID=acp-resource
export ACP_GOAL_OAUTH_CLIENT_SECRET_FILE=/run/acp/secrets/introspection-client
export ACP_GOAL_TENANT_ID=tenant-a
export ACP_GOAL_PROJECT_ID=project-a
export ACP_GOAL_AGENT_ID=coding
export ACP_GOAL_RELEASE_ID=release-v1
export ACP_GOAL_SESSION_ID=session-1
export ACP_GOAL_GITHUB_REPOSITORY=owner/repo
export ACP_GOAL_TARGET_BRANCH=main
export ACP_GOAL_RULES_DIGEST=sha256:REPLACE_WITH_ACTUAL_64_CHARACTER_LOWERCASE_HEX
export ACP_GOAL_MAX_TOKENS=1000
export ACP_GOAL_MAX_RUNTIME_SECONDS=600
export ACP_GOAL_MAX_SANDBOX_SECONDS=300

# Default: require GitHub branch protection. Only for disposable demos,
# explicitly opt out when the chosen public branch has no protection:
# export ACP_GOAL_ALLOW_UNPROTECTED_TEST_BRANCH=true

go run ./cmd/acp-goal-api
```

No untrusted HTTPS reverse proxy inference is supported: the listener itself requires a TLS handshake. Binds other than a numeric loopback address are rejected; remote access, production ingress and multi-tenant hosting are not included. The runtime does not expose a health/read API; use platform process supervision and a separate deployment readiness gate.

## Prepare and submit a real public Issue

Use `go run ./cmd/acp-goal snapshot --issue-url https://github.com/owner/repo/issues/1` to obtain the public Issue digest, then build a manifest with the same exact repository/branch, current integration branch tip SHA, separately pinned experiment SHA, operator-approved rule digest, configured target identifiers and an in-ceiling budget.

```sh
go run ./cmd/acp-goal inspect --file /tmp/acp-issue-goal.json
go run ./cmd/acp-goal prepare --file /tmp/acp-issue-goal.json > /tmp/acp-proposal.json

# Use a private short-lived Bearer header file; never put tokens in URLs,
# manifests, curl verbose logs or GitHub Actions artifacts.
# The private file contains: Authorization: Bearer <actual-token>
curl --silent --show-error --cacert /run/acp/ca/goal-server-ca.pem \
  --header @/run/acp/secrets/goal-bearer-header \
  --header 'Content-Type: application/json' \
  --data-binary @/tmp/acp-proposal.json \
  https://127.0.0.1:9443/api/v1/goals:submit
```

### Submit with the non-dispatch CLI

The optional CLI subcommand accepts the **prepared** JSON emitted by `acp-goal prepare`, not the original manifest. It sends one direct HTTPS POST to the numeric-loopback Goal API, with a dedicated PEM trust anchor and bearer credential read from a private regular file (`chmod 0600`). It never takes the Bearer in a command-line argument, follows redirects, or honors proxy environment variables.

```sh
go run ./cmd/acp-goal submit \
  --file /tmp/acp-proposal.json \
  --url https://127.0.0.1:9443/api/v1/goals:submit \
  --token-file /run/acp/secrets/goal-bearer \
  --ca-file /run/acp/ca/goal-server-ca.pem
```

On `201` and `200`, the CLI checks the server's schema and request digest against the exact immutable prepared input, checks the RunIntent receipt fields and status/created consistency, and prints only the verified acceptance JSON. It will not call a GitHub write API or execute Runtime work. On any TLS, HTTP, or invalid-receipt error, no acceptance JSON is emitted. A network timeout has an **unknown outcome**; check the authoritative ACP database before replaying the same idempotency key.

### Crash-safe local attempt hold record (opt-in)

For a Goal whose HTTP acceptance ACK could disappear after PostgreSQL commit, add `--hold-record` to `acp-goal submit`. This option writes and synchronizes one **private, non-authoritative attempt marker before sending the POST**. A failed write, existing path, symlink, relative path, or missing/non-private parent prevents the network request. The file remains after a verified 201/200; it describes the attempt, not its eventual outcome.

```sh
install -d -m 0700 /run/acp/goal-hold
go run ./cmd/acp-goal submit \\
  --file /tmp/acp-proposal.json \\
  --url https://127.0.0.1:9443/api/v1/goals:submit \\
  --token-file /run/acp/secrets/goal-bearer \\
  --ca-file /run/acp/ca/goal-server-ca.pem \\
  --hold-record /run/acp/goal-hold/attempt-001.json
```

The `acp.goal-submit-hold/v1` JSON includes only the tenant/project/agent/release/session selectors, original `idempotency_key`, `request_digest`, and conservative `UNKNOWN/HOLD` disposition. It **never** contains a bearer, raw execution input, server response, or Runtime identity. The parent directory must already be private (0700); the newly created file is 0600 and cannot overwrite earlier attempt evidence. A new attempt needs a distinct operator-approved filename; do not generate a new filename simply to bypass an existing HOLD. Keep selectors private and follow ordinary retention controls.

A marker is **not** evidence that the server committed or rejected a RunIntent, and `UNKNOWN/HOLD` remains conservative even when the CLI separately printed a valid acceptance receipt. On transport ambiguity, stop and reconcile the original tuple with ACP's authenticated PostgreSQL authority and Runtime's separate authoritative records; an absent database row at one instant is **not** a final absence certificate. Never blindly POST again or infer execution success from this file. The current Goal HTTP host has no read-only lookup endpoint; this option does not create one or bypass branch protection.

The CLI deliberately only permits a direct numeric loopback endpoint and a bounded TLS server response. It cannot currently connect through remote ingress or a proxy; production host deployment and genuine OAuth/GitHub/DB joint validation remain separate acceptance gates.

Expected: HTTP `201` for the first authorized request and `200` for an exact same-key replay, both with the *same* `run_intent_id` and canonical digest; there is **no** `run_id` and no dispatch receipt. A reused key with changed input should result in `409`. Revoke the membership, retry, and expect denial without a new DB row or GitHub source request. For timeouts or ambiguous external responses, inspect the existing database and authoritative source; never blindly synthesize success.

### Evidence and known limitations

- Non-network config rejection tests cover invalid TLS identity, expired/not-yet-valid certificate, symlinked secret, unsafe branch override and invalid host configuration: `go test ./cmd/acp-goal-api`.
- With `PGTEST_DSN`, a disposable-schema integration test runs the real repository migrations and verifies the startup gate rejects a missing v12 admission-origin migration: `go test -run TestVerifyAuthoritySchemaRequiresLatestAdmissionMigration ./cmd/acp-goal-api`.
- Exact-head Go/PG workflow must also pass all race-enabled tests.
- `TestCatalogGoalHTTPRealTLSIntrospectionAndPostgres` runs a real TLS HTTP listener, test TLS issuer, existing CatalogPolicy and real PostgreSQL/Outbox when `PGTEST_DSN` is present. The GitHub reader in this test is **a fixture**, not a real GitHub attestation.
- An isolated, hosted **live-public-GitHub + disposable Keycloak + real PostgreSQL admission** was independently confirmed on [workflow #44865914591](https://github.com/avaargsh/agent-control-panel/actions/runs/44865914591) at its exact HEAD. See the [live-provider acceptance evidence and reproduction](ISSUE-GOAL-LIVE-ACCEPTANCE.md), including a separate failed rerun and the distinction between mandatory first admission and optional live-source replay. A later [independent Goal API + Goal CLI process-level CI run #44866565087](https://github.com/avaargsh/agent-control-panel/actions/runs/44866565087) also passed in a disposable test environment: it started `cmd/acp-goal-api`, used `acp-goal submit`, verified one authoritative RunIntent/Outbox and the exact input, then denied an explicit replay after revoking RUNNER. See [process-level operator acceptance](ISSUE-GOAL-OPERATOR-PROCESS-ACCEPTANCE.md). Neither run proves an externally deployed production service or protected-branch release. There is no signed ruleset authority, enforced budget consumption, GitHub PR creation, Sandbox/Verifier/Guard effect or fully vetted deployment.
- Public GitHub Issues can change or be closed; their snapshot and pinned branch HEAD must be freshly re-observed on each authorized submission, including replay.
- Operator must independently verify the exact HEAD SHA, authenticated GitHub logs, failure/negative matrix, database role least privilege, branch protections and a separate reviewer before promoting this candidate.

Related: [HTTP handler contract](ISSUE-GOAL-HTTP.md), [input preparation](ISSUE-GOAL-PREPARE.md), [PR #86](https://github.com/avaargsh/agent-control-panel/pull/86).
