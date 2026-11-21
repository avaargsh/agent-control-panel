# Issue Goal input preparation (M0 candidate, non-dispatch)

This is the first **offline** user-facing step toward ACP's GitHub Issue → PR Golden Path. It prepares a strictly validated, immutable input proposal; it **does not by itself submit a Goal**, admit a RunIntent, start a Runtime Run, contact GitHub, enforce budgets, run a model, or grant any protected operation. An internal adapter can now pass independently verified input to existing authenticated admission, but no public authenticated submit route is wired.

## Reproduce

From the repository root, with the Go version pinned by `go.mod`:

```bash
# Replace all example IDs, commit SHAs, digest and issue URL with real values.
cp docs/examples/issue-goal.example.json /tmp/acp-issue-goal.json
# Edit /tmp/acp-issue-goal.json before using it for a real goal.
go run ./cmd/acp-goal prepare --file /tmp/acp-issue-goal.json > /tmp/acp-proposal.json
cat /tmp/acp-proposal.json
# Also supported: cat /tmp/acp-issue-goal.json | go run ./cmd/acp-goal prepare --file -
```

The example uses **syntactically valid but deliberately fictitious** SHAs, rule digest, identifiers, and Issue. A successful local `prepare` is never evidence that those resources exist, are trusted, or have been accepted by ACP.

The result has `schema=acp.issue-goal-submission/v1`, ACP admission selectors, a caller-chosen idempotency key, `request_digest`, and `execution_input_base64`. Decode the last field to recover **exact JSON bytes**; do not parse/re-serialize them before comparing the digest. The digest uses the existing `runintent.ExecutionInputDigest` versioned framing, scoped to tenant/project/agent/release/session/idempotency key. There is no client-authenticated identity or Permit in this result.

## Contract and safety

- Only canonical HTTPS URLs of the form `https://github.com/OWNER/REPO/issues/N` are accepted. No URL credentials, ports, queries, fragments, or percent-encoded path aliases. This is parsing only, **not a GitHub existence/permission check**.
- The Issue snapshot is pinned by an independent `issue_snapshot_digest` (SHA-256). The CLI **does not verify** the digest or capture the snapshot; the trusted source verifier must do so against actual GitHub content, and persistent byte-addressed snapshot retrieval remains a separate integration gate.
- Experiment and integration baselines are two separately named **40-character commit SHAs**. Reusing one SHA for both is allowed; changing either changes the digest. Branch is a constrained short ref name, not a verified protected target.
- Acceptance rules are pinned by the shape `sha256:<64 lowercase hex chars>`; their bytes/signature must be verified by a separate rules authority before execution.
- Budget requests must be positive and bounded (10M tokens, 24h runtime, sandbox time no more than runtime). **These are requests, not live quotas or enforcement.** Admission and executor still need to verify live policy and budget ceilings.
- Unknown fields, duplicate JSON keys (also escaped spelling collisions), unsupported versions, invalid scopes, oversized documents, unsafe branches and malformed digests fail closed. Input is limited to 32 KiB.
- Repeating the same manifest produces the same exact input bytes/digest. A replay with the same idempotency key but changed pinned content must **conflict at the authoritative PostgreSQL RunIntent admission boundary**, not silently start a second Run. An offline digest does not itself provide database-level idempotency.

## Mandatory next integration gate

Wire the new **internal**, non-dispatch `admission.Service.AdmitPreparedIssueGoal` adapter to a real, independently authenticated Issue/baseline/rule/budget source verifier, real OAuth introspection and current CatalogPolicy, then verify PostgreSQL replay/Outbox and Runtime ID projection. The adapter currently depends on a trusted verifier injected by the host and is **not wired to a user-facing HTTP route**. Never accept the proposal JSON as an authorization assertion: the server must independently decode/validate scope (using `issuegoal.DecodePrepared`), recalculate the input digest from exact bytes, verify external source evidence, and recheck current authorization. Keep Runtime/Temporal Run IDs owned exclusively by agent-runtime.

Before claiming M0 complete, demonstrate real tenant-isolated PostgreSQL admissions, identical replay yielding one RunIntent/Outbox, changed-content conflict, revoked actor denial, wrong-scope denial, signed release/rules existence, and an operator-facing Run view. Protected action/PR creation remains blocked on EngageGuard, Sandbox and Independent Verifier gates (#70–#72).

### Focused regression

```bash
go test -race -count=1 ./internal/issuegoal ./cmd/acp-goal ./internal/admission
# The repository's full workflow also runs gofmt, go mod verify/tidy, go vet ./..., go test -race -count=1 ./...
```


## Public Issue snapshot (read-only)

From the repository root, inspect a public open GitHub Issue and obtain a
content-addressed digest for the existing manifest's `issue_snapshot_digest`:

```bash
go run ./cmd/acp-goal snapshot \
  --issue-url https://github.com/avaargsh/agent-control-panel/issues/70
```

The CLI sends exactly one unauthenticated read-only request to
`https://api.github.com/repos/<owner>/<repo>/issues/<number>`.
The endpoint is fixed and cannot be redirected by a user URL. TLS verification,
a 10-second timeout, response-size limit and no-redirect policy are enforced.
The CLI emits only the version, Issue URL, numeric Issue ID, updated timestamp
and digest, **not** the Issue body. The Issue text remains untrusted input.

The digest version is `acp.github-issue-snapshot/v1`. Its SHA-256
preimage uses Go's `encoding/json` (UTF-8, no indentation), with
keys in this exact order:
`schema, issue_url, issue_id, number, state, title, body, updated_at`.
A null Issue body is normalized to the empty string; `updated_at` is the
original RFC3339 value. The digest itself is **not** part of the preimage. See
`TestPublicIssueReaderCanonicalDigestAndChangeDetection` for the
independently pinned golden vector.

**Scope:** Public open Issues only. This is a GitHub TLS API observation,
not a GitHub-signed attestation, immutable stored copy or complete Source
Verifier. It neither verifies baseline commits nor acceptance-rule signatures,
release/budget policy or user authorization. A trusted server must re-fetch and
compare the snapshot and independently verify all other preconditions before
using `AdmitPreparedIssueGoal`. It does not submit a RunIntent,
dispatch a model, create a PR or authorize a protected effect.

Local focused acceptance:
```bash
go test -race -count=1 ./internal/issuegoal ./cmd/acp-goal
```


## Public Baseline inspection (optional CLI, non-authoritative)

After obtaining a real public Issue snapshot with `acp-goal snapshot`, edit
the Goal manifest with that `issue_snapshot_digest`, a real full
`experiment_baseline_sha`, and the **exact current branch HEAD** as
`integration_baseline_sha`. A real Issue and actual commit IDs must be
substituted for the deliberately fake values in the example.

```sh
go run ./cmd/acp-goal inspect --file /tmp/acp-issue-goal.json
```

The new `inspect` command first checks the immutable manifest; then it
reads the current public Issue and requires the content digest to match.
It reads `GET /repos/{owner}/{repo}/branches/{target_branch}` from the
fixed GitHub API hostname and requires the observed branch tip to equal
the exact integration SHA. It then reads both
`GET /repos/{owner}/{repo}/git/commits/{full_sha}` endpoints and requires
the returned SHA to match. When both SHA values are identical, the object
is fetched once. All endpoints are constructed from canonical selectors:
no configurable host, no credential, no redirect and no HTTP write.
Failed source, stale Issue, moved branch, bad commit ID, rate limit,
response ambiguity and timeout are **fail-closed**.

The output schema `acp.public-goal-inspection/v1` deliberately uses
`status=public-source-observed-only`, alongside immutable request digest
and observed branch tip. **This is not GoalSubmit, authorization, a signed
GitHub statement, commit ancestry validation, verified rule content,
release/budget approval, or a durable source snapshot.** Even when
`inspect` succeeds, the server must independently verify these inputs,
and maintain its OAuth/CatalogPolicy admission and independent source
authority before writing RunIntent. The branch may move after inspection;
a fresh authoritative recheck remains required.


## Internal trusted GitHub source verification

The `admission.NewTrustedGitHubIssueVerifier` adapter now supplies the
existing `IssueGoalSourceVerifier` boundary. It is internal-only and
not yet wired to a production HTTP endpoint. Its trusted configuration is
host-owned (`TrustedGitHubIssuePolicy`), with an exact ACP Target
(tenant/project/agent/release/session), public repository, target branch,
operator-approved acceptance rules digest, maximum requested token/runtime/
sandbox budgets, and optional protected-branch requirement.

For a configured source verifier, `AdmitPreparedIssueGoal` performs:

1. Validate immutable proposal bytes and compute scope-bound request digest.
2. Authenticate the current caller and check CatalogPolicy **before any
   GitHub request** (unauthorized requests cannot trigger provider egress).
3. Fail closed on a target/repository/branch/rules-digest/budget mismatch,
   before any provider read.
4. Re-fetch public Issue and validate the versioned Issue ID/content digest.
5. Re-fetch exact GitHub baseline commits and compare integration SHA with
   observed current target branch HEAD, optionally requiring branch protection.
6. Re-authenticate/authorize on the same exact bytes, then use the existing
   PostgreSQL-authoritative RunIntent/Outbox transaction.

The source verifier makes no GitHub writes, mints no credentials and grants no
Guard Permit. Its operator-configured rules **digest** is only an allowlist
constraint: this implementation does **not** yet independently verify rules
bytes or a cryptographic release signature. The budgets are admission ceilings,
not actual Runtime token or Sandbox time enforcement.

This boundary does **not** prove the Issue's original content was durably
retained; the GitHub API observation can change later. A production Source
Evidence plane, signed rules authority, release-bound authorization, configured
server API, Runtime dispatch and independently verified Issue→PR completion
are still separate, required gates. No operator should treat a public CLI
inspection receipt as authentication or execution authorization.
