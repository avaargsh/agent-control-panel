# M0 live public-provider admission acceptance (CI, non-dispatch)

**Scope:** this is an isolated, opt-in provider-integration acceptance for ACP's
RunIntent GoalSubmit endpoint. It is **not** an execution, independent Verifier,
protected GitHub effect, or production-release claim.

## What was actually verified

The pinned [Live OIDC service-account workflow](
../../.github/workflows/real-oidc-admission.yml) calls
`scripts/test-real-oidc-admission.sh`. In the disposable CI job it:

1. Creates a one-day test CA and a TLS-only Keycloak realm (pinned container
   digest, no ingress outside loopback), with a short-lived OAuth client-credentials
   service account; **no real deployment secrets**.
2. Starts PostgreSQL 16, migrates an isolated, disposable schema, and inserts
   the ACP tenant/project/principal/RUNNER membership/release/session authorities.
3. Fetches the **actual public** GitHub Issue
   [#70](https://github.com/avaargsh/agent-control-panel/issues/70),
   current `main` commit and its first parent from `api.github.com`.
   These live selectors form the immutable Issue Goal request; no provider
   response is invented.
4. Issues a real Keycloak access token only after setup, then calls the actual
   `goalhttp.NewHandler` over a local test TLS listener with the existing
   OAuth introspector, live CatalogPolicy, trusted fixed-origin public GitHub
   reader, PostgreSQL RunIntent repository and Outbox.
5. Requires HTTP **201** with `PENDING` and a bound request digest; queries
   PostgreSQL to prove **one** RunIntent, **one** Outbox and the exact accepted
   immutable execution input. No fake Runtime Run ID is accepted.

The integration test resides in
`internal/goalhttp/live_provider_e2e_test.go` and requires
`ACP_REAL_GOAL_E2E=1` plus `GITHUB_ACTIONS=true`. Missing credentials,
provider failures, invalid identities, stale Issue/branch observations or
database disagreement must fail. It never creates or changes GitHub Issues,
branches, commits or pull requests.

## Evidence and the external replay distinction

- **Confirmed live first admission and real-provider replay (one successful
  run):** [Actions #44865914591](https://github.com/avaargsh/agent-control-panel/actions/runs/44865914591),
  exact HEAD `f65d26155e9955f1503351fc900d893cadef621d`. Both the
  disposable Keycloak/PG identity test and `TestRealGoalHTTPKeycloakGitHubPostgres`
  completed PASS. The latter verified HTTP 201 then HTTP 200 with the same
  RunIntent ID, and PostgreSQL remained at one intent/one event.
- **A prior live rerun did not pass:** [Actions #44865832430](https://github.com/avaargsh/agent-control-panel/actions/runs/44865832430)
  returned HTTP 503 during its second upstream-sourced submission after an
  initial HTTP 201. The logs do **not** establish whether this was a transient
  upstream GitHub availability/rate-limit response, a changed source, or an ACP
  internal failure. It must not be presented as confirmed GitHub rate limiting.
- To avoid an externally unstable *second* public read making the required
  Pull Request gate nondeterministic, the default live gate now requires
  **the first real admission and its durable PostgreSQL evidence**.
  Set `ACP_REAL_GOAL_LIVE_REPLAY=1` **in the disposable CI job only** to
  additionally require a second real-source replay. This does not bypass the
  normal resolver or source verifier; it changes only how much optional
  live-provider re-observation the test demands.
- Exact-key replay, permission revocation during source read, source timeout
  with explicit retry, client response loss and Outbox uniqueness are covered
  separately by the deterministic, race-enabled HTTPS/PostgreSQL test suites.
  Passing those tests is not evidence that public GitHub will always respond.

## Reproduction and safety

The checked-in workflow runs the script against disposable CI resources.
Operators should inspect the **precise commit SHA** and the associated GitHub
Actions logs for the issuer startup, real GitHub observation, GoalSubmit
receipt and PostgreSQL check. Never copy the example CI token or client secret
to a deployed environment.

```sh
# Executed only inside the disposable CI job, which supplies PGTEST_DSN:
bash scripts/test-real-oidc-admission.sh

# For stricter live-provider re-observation within the same disposable CI job:
ACP_REAL_GOAL_LIVE_REPLAY=1 bash scripts/test-real-oidc-admission.sh
```

The branch `main` was **not protected** when the test was created. Only this
isolated test allows `RequireProtectedBranch=false` while keeping the
target repository, Issue, branch and budget pinned. This is not a production
policy exception, branch-protection attestation or signed acceptance-rules
check. The TLS listener is an in-process host with real dependencies; the
separate opt-in `cmd/acp-goal-api` process plus `acp-goal submit` still
requires operator deployment evidence.

**Remaining release blockers:** genuine protected-branch rule evidence,
signed acceptance-rule bytes and trusted authority, independent review of
the stacked PRs #82 → #85 → #86, a real operator host/CLI transcript,
revocation/UNKNOWN recovery across independently deployed services, Runtime
dispatch, Sandbox, independent Verifier and an explicitly approved GitHub PR
write. None is authorized by the M0 receipt.
