# M0 operator-process acceptance: Goal API + Goal CLI (non-dispatch)

## Confirmed execution and boundaries

**Observed PASS:** [GitHub Actions #44866565087](https://github.com/avaargsh/agent-control-panel/actions/runs/44866565087), source commit `fde186eb56c9a51fa51d23b440f22ca15fa3c007`. In the job logs, `TestRealOIDCServiceAccountCatalogAdmission` and `TestRealGoalHTTPKeycloakGitHubPostgres` both passed. The latter reports an **independent Goal API and CLI** process-level PASS, not an in-process handler-only test.

The command in `scripts/test-real-oidc-admission.sh` builds **two real release executables** from the exact CI checkout:

```sh
go build -trimpath -o "$root/acp-goal-api" ./cmd/acp-goal-api
go build -trimpath -o "$root/acp-goal" ./cmd/acp-goal
export ACP_REAL_GOAL_API_BIN="$root/acp-goal-api"
export ACP_REAL_GOAL_CLI_BIN="$root/acp-goal"
export ACP_REAL_GOAL_PROCESS=1
export ACP_REAL_GOAL_E2E=1
go test -race -count=1 -v \
  -run '^TestRealGoalHTTPKeycloakGitHubPostgres$' ./internal/goalhttp
```

`root` is an ephemeral temp directory. Both binaries and generated credentials are removed on job exit; they are not published or installed on the host.

The test under `internal/goalhttp/live_operator_process_test.go`:

1. Uses actual **read-only** `api.github.com` Issue #70, current `main` integration SHA and independently fetched parent/experiment SHA, with a canonical prepared input.
2. Boots the existing pinned, disposable TLS Keycloak test realm and PostgreSQL 16 test service, migrates a separate schema and creates an explicitly scoped RUNNER membership.
3. Issues a short-lived Keycloak service-account bearer; generates a separate ephemeral self-signed HTTPS certificate with **127.0.0.1 IP SAN** and a trusted PEM CA.
4. Starts `acp-goal-api` with a loopback socket, owner-private DSN/client-secret/token files, explicit test-only unprotected-branch policy, exact repository and budget, and a dedicated database `search_path`. Waits for a **verified TLS handshake**, not a `sleep` or an invented health endpoint.
5. Executes `acp-goal submit` as a **different OS process** with a prepared Goal file, TLS CA and private bearer file. Requires an exact `acp.issue-goal-acceptance/v1` acceptance receipt, status `PENDING`, `created=true` and the original request digest.
6. Queries the authoritative PostgreSQL schema: exactly **one** RunIntent, **one** Outbox event and byte-for-byte identical accepted execution input.
7. Downgrades the authorized catalog membership to VIEWER and invokes the same independent CLI again; requires nonzero exit/no successful JSON, and exactly the original RunIntent/Outbox cardinality. No automatic retry or GitHub write.
8. Terminates the API process with SIGTERM and requires graceful shutdown within a bounded cleanup interval. All test database records and secrets are disposable.

The ordinary non-live `go test -race -count=1 ./...` workflow compiles these tests, but **does not run** the live process path unless `ACP_REAL_GOAL_PROCESS=1` and the disposable CI environment and binaries exist. The dedicated live-issuer workflow must report `--- PASS: TestRealGoalHTTPKeycloakGitHubPostgres`; zero tests or skipped tests are failures in its shell harness.

## What this does *not* prove

- No main branch protection: the demo's `RequireProtectedBranch=false` exception is valid **only** under explicit `ACP_GOAL_ENV=test`; production remains fail-closed.
- No independently signed acceptance-rule authority or production budget/Permit checks.
- No public deployment, multi-tenant remote ingress, persistent service supervision, or high-availability acceptance.
- No Temporal Runtime Run, Sandbox/AgentD tool execution, independent Verifier, human-approved GitHub PR creation, or completed Issue-to-PR Golden Path.
- A test-local self-signed certificate and disposable Keycloak realm do not establish enterprise PKI/IAM operational readiness.
- The test covers a **first real submission** plus a role-revoked **denied replay**. It does not guarantee that re-observing live public GitHub repeatedly will always succeed: see the distinct live-provider replay success and HTTP 503 uncertainty in [live acceptance evidence](ISSUE-GOAL-LIVE-ACCEPTANCE.md).

**Approval boundary:** #86 remains Draft on the stacked #82 → #85 → #86 path. No merge or full-M1 production claim without exact-HEAD hosted CI, independent review and protected-source/signed-rule evidence.
