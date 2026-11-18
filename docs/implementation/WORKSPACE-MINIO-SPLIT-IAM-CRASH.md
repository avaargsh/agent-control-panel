# P0-2B5d — Real MinIO scoped service identities across SIGKILL/restart

**Scope:** non-production acceptance combining PR #44 (real PostgreSQL16 + MinIO child process SIGKILL across four fault phases) with PR #46 (true server-enforced scoped writer and reader service principals). This is **not** production Cell/Temporal takeover, Object Lock, G01–G05 or authority to call S3 DeleteObject. Issues #35, #38, #43, #45 and #47 remain OPEN.

## Why both previous tests are necessary but insufficient

Earlier SIGKILL acceptance used a combined bootstrap-capable CI MinIO identity for upload, recovery and reopened reads. Earlier IAM acceptance showed independently scoped `PutObject`-only and `GetObject`-only users, but within one running Go process. This follow-up verifies the **intersection**: three truly independent test-executable OS process lifetimes, each connected to separately surviving PostgreSQL16 and real MinIO server processes, with per-process IAM credentials appropriate to its phase.

## OS process credential allocation

The parent controls a disposable PG schema with a previously pinned ACP RunIntent, Session, DAS and Workspace; the test binary spawns its own child process using `exec.CommandContext`. The parent strips MinIO bootstrap, unrelated tenant/test identities, AWS SDK environment credentials and any embedded writer identity from all children by default. It explicitly re-adds only the needed approved test identity. Children assert they did not inherit bootstrap/foreign tenant identities, and they fail if a reader-only child receives even the *presence* of a writer credential.

| Process and phase | Server IAM identity received | Allowed effect |
|---|---|---|
| A: crash before PUT, after PUT, after Stage, after CAS | independent scoped writer + scoped reader | conditional digest-addressed PUT, independently signed GET/hash; then actual parent SIGKILL |
| B: recover **before PUT** only | writer + reader | record object missing as UNKNOWN; create a **new explicit v8 IntentID**, do one trusted conditional PUT and real byte verification |
| B: recover after PUT, after Stage, after CAS | **reader only** | do scoped GET/rehash, reconcile Stage/CAS/immutable ACK replay; **no writer credential** |
| C: reopen after all four phases | **reader only** | reopen and SHA256-check committed bytes, replay immutable receipt, reject forged tenant scope; **no writer credential** |

All four phase names use distinct digest keys per credential mode, so the earlier combined-identity test cannot pre-create an object that invalidates the before-PUT missing-object expectation. The parent checks the actual `SIGKILL` signal exit, pre-crash PG intents/stages/manifests and post-recovery exactly one ref plus revision 1, and correct UNKNOWN evidence. It also validates read-only role markers emitted by the actual child, not merely the parent test selection.

The new `TestMinioChildCredentialEnvironmentIsLeastPrivileged` is a separate fast deterministic test that supplies deliberately dangerous bootstrap/foreign/alternative AWS environment variables and asserts that they never propagate to any recovery or reopen child. It also verifies the exact exception for an explicitly authorized new attempt after a crash before any remote PUT.

## Real provider and evidence caveats

- The real MinIO setup uses the official historical SHA256-pinned MinIO server and `mc` client, and actual server IAM policies installed before either split-role test starts. No bootstrap administrator credentials are passed to the new split-IAM SIGKILL test step.
- Server-denied `PutObject` for a reader-only identity is covered by the existing scoped IAM HTTP 403 test; the process test guarantees that a reader-only process cannot also obtain the writer key via the inherited environment. This is test harness credential confinement, not general OS process/secret-manager isolation.
- A successful signed PUT followed by SIGKILL before local ACK/Stage remains `UNKNOWN` until subsequent independent reader byte verification; never repeat the same IntentID as a blind remote effect.
- The current historical MinIO IAM writer policy **does not enforce unconditional overwrite protection**. PR #48 demonstrated a valid scoped writer can bypass `If-None-Match` and replace digest-addressed bytes with a raw signed unconditional PUT. That known critical safety blocker remains Issue #47. Separate manual approved-provider WORM acceptance has NOT RUN.
- Even successful nonproduction SIGKILL tests cannot establish actual Temporal Attempt fencing, Runtime/CCP Cell destruction, EngageGuard permit binding, provider IAM credential expiry/rotation, approved retention/version pinning or protected external DELETE.
- No new production service runtime, public API, schema migration, `DeleteObject` method, GC execution worker, or provider privilege escalation is introduced.

## CI acceptance

The opt-in real MinIO + PostgreSQL16 workflow runs `go test -race -count=1 -v` for `TestWorkspaceRealMinIOSplitIAMProcessSIGKILLRecovery`, then checks explicit PASS for all four subtests, an actual SIGKILL marker for each, and **reader-only reopen** markers for all four phases plus **reader-only recover** markers for the three post-PUT/Stage/CAS phases. If the real server test is skipped, a role is missing, a child inherits unrelated keys, or any phase is absent, the CI job fails. Go1.27.4 PostgreSQL16 full gofmt/vet/race and other pre-existing checks remain required.

Do not close #43 or #45 based solely on this bounded acceptance. Later work still needs a supported immutable provider backend and actual multi-service Cell/Temporal lifecycle evidence; keep all production deletion disabled.
