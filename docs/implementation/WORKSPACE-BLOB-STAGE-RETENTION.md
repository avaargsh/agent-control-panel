# P0-2B2: Workspace blob stage/retention evidence (v7)

Status: **development-only PostgreSQL slice**. It strengthens the ACP Workspace creation/commit evidence chain. It is *not* production object retention, actual MinIO certification, a distributed transaction or automatic garbage collection.

## Authority and lifecycle

- ACP owns the authoritative Workspace/Session/RunIntent and immutable DAS release binding. S3/MinIO owns object bytes, never Session or manifest revision.
- Each `StageWorkspaceAsset(lock,stageID,asset,leaseSeconds,verifier)` validates the exact persisted DAS lock, requires an existing Workspace and a server-side object verifier, then records an immutable stage receipt with a **database-clock** expiration. The lease is bounded (1–86400 seconds); the same stage ID cannot be changed or extended by replay.
- The new `CommitStagedWorkspace` path uses the same PostgreSQL transaction as v6 manifest CAS. It requires unexpired staged bytes and revalidates actual object content through its verifier. It writes the Workspace revision, immutable manifest receipt, and each per-path blob retention reference **atomically**. A stale CAS or stage validation failure commits none.
- A retry after lost ACK returns the original receipt, *only* when the exact manifest and immutable per-asset references match. It does not create an additional revision.
- The old `CommitWorkspace` path remains for source compatibility, including historical v6 metadata. New object-store integrations should use the strict staged path; the old path cannot establish staging evidence.
- `ListExpiredBlobCandidates` is deliberately **read-only**. It excludes any digest referenced by any stage-era commit and by **all historical v6+ manifests**, including past revisions no longer in the current snapshot. No byte deletion API, tombstone write or auto-GC worker is enabled.

## Evidence and invariants

- SQL v7 is additive and checksum-ledger-protected. It binds immutable stage rows to `run_capability_locks` by tenant, principal, Workspace, Session and DAS digest, and retention refs to a committed revision.
- Both tables have `FORCE ROW LEVEL SECURITY` policies on tenant+principal, immutable UPDATE/DELETE/TRUNCATE guards, and migration-time schema/ACL/trigger validation.
- Integration tests: real PostgreSQL, idempotent stages and mismatched replay, expired/absent stage rollback, CAS/commit reference atomicity, tenant rejection, immutable receipts, and read-only historical protection.
- End-to-end *development simulation* includes actual HTTP S3-compatible bytes + real PostgreSQL + a fresh Repository verified read. It is **not** a successful MinIO backend run.

## Remaining Issue #35 blockers

1. Controlled real MinIO/S3 signed-request acceptance and immutable bucket IAM/Object Lock/versioning. Historical Quay MinIO mirror returned 401; the manual workflow needs an approved digest-pinned deployment.
2. Stage before upload: a crash/restart-safe upload-intent journal, failure recovery and retention race handling across PostgreSQL and S3 (no distributed exactly-once claim).
3. Two-stage GC including claim fencing, retention grace, fresh manifest/ref recheck, separate least-privilege delete authority, audit trail, retry/UNKNOWN state and actual remote deletion proof. Candidate enumeration alone never authorizes deletion.
4. Real authenticated principal/entitlement gate, service role separation, user-facing Workspace API, and Cell creation/teardown with independent Runtime/CCP/EngageGuard G01–G05 evidence.

**A passing repository test does not attest that a particular object remains durable after a future provider-side delete or access-policy change.**
