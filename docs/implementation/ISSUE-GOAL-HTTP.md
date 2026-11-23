# M0 Issue Goal submission HTTP contract (candidate, non-dispatch)

This patch adds `internal/goalhttp.NewHandler` for exactly one route:

```http
POST /api/v1/goals:submit HTTP/1.1
Content-Type: application/json
Authorization: Bearer <opaque-oauth-access-token>

{"schema":"acp.issue-goal-submission/v1", "...":"..."}
```

The request body is the **entire JSON output** of `acp-goal prepare`, not the original manifest. Do not put the Bearer token inside the manifest or source snapshot.

The host **must** explicitly create the handler with:
- A genuine TLS listener (direct TLS; cleartext and untrusted proxy TLS termination are rejected).
- A request-scoped `GoalServiceFactory` that resolves the presented OAuth token using the existing TLS-validating RFC7662 introspector, the live ACP CatalogPolicy authority and a single ACP PostgreSQL RunIntent repository. Neither caller identity nor policy revisions are ever read from the request JSON.
- An operator-configured, independently sourced `admission.TrustedGitHubIssueVerifier`. This verifier checks exact target/repository/branch/rules-digest/budget allowlist and reads real GitHub Issue+commits before the existing admission transaction. A forged client-side snapshot digest is not a grant.
- Pre-existing validated database schema and least-privilege ACP writer credentials. This handler creates no schema and does not directly write a second data authority.

The handler enforces TLS, a single bounded Bearer header, JSON only, strict untrusted proposal decoding and a 64 KiB request bound **before** asking for a request-scoped authenticated service. It neither caches secrets nor echoes underlying errors in responses. `Cache-Control: no-store` is set.

**Return shape:** On first accepted RunIntent the response is HTTP `201`; exact idempotent replay is HTTP `200`. Both return a scope-bound immutable request digest, the ACP-owned `run_intent_id`, current **RunIntent status** (normally `PENDING`) and boolean `created`. This is **not** a Runtime `run_id` or proof of work completion.

On errors, HTTP `400` is malformed input, `401` unauthenticated, `403` policy/source denied, `409` incompatible idempotency replay, and `503` unavailable authority/provider or unexpected server failure. Error bodies contain generic codes only.

## Current gate

An **opt-in, loopback-only TLS host candidate** is now available in `cmd/acp-goal-api`; see [the host guide](ISSUE-GOAL-TLS-HOST.md). It uses the real OAuth introspector, ACP CatalogPolicy, PostgreSQL/Outbox, and the fixed-origin public GitHub reader, but does not change the default read-only ACP server. The integration suite additionally runs an actual HTTPS HTTP endpoint + test HTTPS issuer + PostgreSQL with a **fixture GitHub reader**. Do not treat this as a hosted live-GitHub + real deployed IdP + PostgreSQL end-to-end acceptance or proof of production readiness.

This does not verify signed rule bytes, enforce token/runtime/sandbox consumption ceilings, dispatch an agent, allocate a sandbox, grant a protected effect, create a GitHub PR, or run independent Verifier acceptance. The upstream PR dependency order is **#82 → #85 → this PR**. No auto-merge.

Next gate: exercise a live public GitHub Issue request using the opt-in TLS host and independently configured real OAuth/Catalog/DB sources; then verify replay, revocation during source read, timeout/UNKNOWN and recoverable Outbox behavior. Independent review and current exact-head CI remain prerequisites before declaring M0 complete.
