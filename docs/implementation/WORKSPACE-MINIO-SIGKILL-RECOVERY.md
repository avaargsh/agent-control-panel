# P0-2B5a — Actual OS SIGKILL and multi-process PG/MinIO recovery

**Scope:** a bounded, nonproduction fault-injection test added to the real MinIO + PostgreSQL 16 compatibility workflow. This is **not** Cell teardown, production S3/IAM/retention verification, or authorization to delete remote blobs. Issue #43 remains OPEN for identity policy and full execution-Cell recovery; #35 and #38 remain OPEN.

## Process boundaries tested

An opt-in Go race test `TestWorkspaceRealMinIOProcessSIGKILLRecovery` spawns fresh copies of the compiled test executable via `os/exec`. The child reconnects to the existing *separately running* PostgreSQL server and real MinIO server using a pinned, already-created ACP Workspace/RunIntent/Session/DAS lock and a unique disposable PostgreSQL test schema. This test is **never** invoked by a product API.

Each of four subtests uses three independent OS process lifetimes:

1. **Process A** persists the immutable v8 UploadIntent before any signed MinIO PUT. It advances exactly to the named fault point, sends a marker *after* that durable state boundary, and is then forcibly killed by the parent with `SIGKILL`. The parent verifies the actual signaled exit status, PostgreSQL intent/stage/manifest row counts and that no premature commit occurred.
2. **Process B** is a new OS process, opens the same independent PG+MinIO services, and verifies real bytes through a scoped signed GET before creating/replaying the Stage and CAS. For a missing object, it records `UNKNOWN`, refuses to treat the original idempotency key as retryable PUT, and creates a **new explicit upload intent** for the subsequent authorized PUT. For a real post-PUT lost ACK, it appends `UNKNOWN` *before* GET reconciliation, then appends `VERIFIED` after bytes match. No blind second PUT is performed on an existing IntentID.
3. **Process C** is a third independent OS process which reopens the immutable committed report and replays the exact existing CommitID/expected revision without creating a second manifest or changing receipt. It also rejects a forged tenant lock.

| Fault point | Process A persisted state | Expected recovery |
|---|---|---|
| `before-put` | UploadIntent only; object absent | UNKNOWN and explicit *new* attempt; then byte-verified Stage/CAS |
| `after-put` | UploadIntent + real MinIO PUT/GET, no Stage/ACK | UNKNOWN observation → real GET verification → Stage/CAS, no new PUT |
| `after-stage` | Stage verified and durable; no manifest | Idempotent Stage replay → CAS |
| `after-cas` | Manifest and refs committed, ACK not returned | Immutable CAS ACK replay → byte-verified read |

Post-recovery parent assertions require exactly one committed v7 retention-ref row and Workspace revision 1 per disposable PG schema. All four phases must log their own explicit `--- PASS` and a verified `SIGKILL` marker; CI fails if the test is skipped or a phase is omitted.

## Trust and evidence boundaries

- Real MinIO and PG16 processes persist *independently of killed test workers*; the parent owns the isolated fixture and cleans it up only after all processes have exited. The parent does not alter upstream production services, credentials or buckets.
- The test continues to use the **official historical MinIO RELEASE.2025-09-07T16-13-09Z binary** verified by SHA256 `7c5bd8512c6e966455b1d198209358b2d191c77a83ab377c4073281065fb855f` from PR #42. It is a compatibility fixture, not a supported production server.
- Real S3 conditional PUT and GET with exact SHA256/size checks are exercised; MinIO's privileged fixture credentials remain CI-only. No production `s3blob.Store.Delete`, GC worker, remote destructive operation, or additional authority writer is introduced.
- A test-process `SIGKILL` **does not prove** an actual Cell shutdown, Runtime/Temporal attempt takeover, Kubernetes UID fencing, IAM/Object Lock/versioning, service-authenticated principal resolution, token revocation, provider crash persistence or G01–G05.
- The subtest named `after-put` kills *after* the remote signed PUT and its response were observed in the killed process, then **before local durable Stage/ACK**. This simulates loss of locally durable ACK evidence; it does not simulate a packet-level aborted transfer mid-stream.
- CI does not attempt to reopen MinIO after killing the MinIO server itself; only upload worker processes are terminated. Separate server restart and storage durability must be proven independently.

## Remaining Issue #43 work

1. Test genuine least-privilege writer/reader identities and MinIO IAM/bucket policies: unscoped GET/PUT, overwrite, rootless DELETE, service credential rotation; fail-closed unknown permissions.
2. Prove real Cell/Runtime/Temporal attempt termination/recovery and Provider UID/namespace evidence under authenticated ACP/EngageGuard/CCP boundaries.
3. Replace the 2025 legacy MinIO fixture with a security-reviewed supported S3 backend or reproducible vetted source build prior to production claims.
4. Independently prove versioning/Object Lock/retention, revocation/expiry, and safe irreversible S3 deletion with separate guarded execution.

Neither a local GC Claim nor these process tests are approval to issue DeleteObject. Keep #35/#38/#43 open until their full gates are genuinely satisfied.
