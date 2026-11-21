# Issue Goal input preparation (M0 candidate, non-dispatch)

This is the first **offline** user-facing step toward ACP's GitHub Issue → PR Golden Path. It prepares a strictly validated, immutable input proposal; it **does not submit a Goal**, admit a RunIntent, start a Runtime Run, contact GitHub, enforce budgets, run a model, or grant any protected operation.

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
- Experiment and integration baselines are two separately named **40-character commit SHAs**. Reusing one SHA for both is allowed; changing either changes the digest. Branch is a constrained short ref name, not a verified protected target.
- Acceptance rules are pinned by the shape `sha256:<64 lowercase hex chars>`; their bytes/signature must be verified by a separate rules authority before execution.
- Budget requests must be positive and bounded (10M tokens, 24h runtime, sandbox time no more than runtime). **These are requests, not live quotas or enforcement.** Admission and executor still need to verify live policy and budget ceilings.
- Unknown fields, duplicate JSON keys (also escaped spelling collisions), unsupported versions, invalid scopes, oversized documents, unsafe branches and malformed digests fail closed. Input is limited to 32 KiB.
- Repeating the same manifest produces the same exact input bytes/digest. A replay with the same idempotency key but changed pinned content must **conflict at the authoritative PostgreSQL RunIntent admission boundary**, not silently start a second Run. An offline digest does not itself provide database-level idempotency.

## Mandatory next integration gate

Add an authenticated M0 `GoalSubmit` adapter that passes this exact input to **existing** `admission.Service.AdmitWithInput`, with real OAuth introspection and current CatalogPolicy, then verifies PostgreSQL replay/Outbox and Runtime ID projection. Never accept the proposal JSON as an authorization assertion: the server must independently decode/validate scope, recalculate the input digest from exact bytes and recheck current authorization. Keep Runtime/Temporal Run IDs owned exclusively by agent-runtime.

Before claiming M0 complete, demonstrate real tenant-isolated PostgreSQL admissions, identical replay yielding one RunIntent/Outbox, changed-content conflict, revoked actor denial, wrong-scope denial, signed release/rules existence, and an operator-facing Run view. Protected action/PR creation remains blocked on EngageGuard, Sandbox and Independent Verifier gates (#70–#72).

### Focused regression

```bash
go test -race -count=1 ./internal/issuegoal ./cmd/acp-goal
# The repository's full workflow also runs gofmt, go mod verify/tidy, go vet ./..., go test -race -count=1 ./...
```
