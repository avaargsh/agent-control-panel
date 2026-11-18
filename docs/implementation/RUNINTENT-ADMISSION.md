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
