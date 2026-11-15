# P0-2B3B — PostgreSQL-only Workspace GC claims and fencing

This is an internal **development-only, non-destructive** claim protocol, not a physical garbage collector. Its database evidence never authorizes S3/MinIO `DeleteObject` and does not create a GC worker or an external provider operation.

## Authority and serializability

ACP remains the only writer for Workspace identity, revision, immutable manifest and referenced asset ledger. GC claims use one mutable, tenant+Workspace+SHA256-keyed `workspace_gc_claims` row with a monotonic `generation`, trusted `holder_id`, and a server-clock lease bounded to 1–300 seconds. Every acquisition, new generation, or eligibility denial can append immutable `workspace_gc_observations`.

All claim operations obtain the ACP-scoped `research_workspaces` row `FOR UPDATE` before checking historical retention or changing a claim. New upload intents also take that row lock before inserting intent evidence. New verified stages take it after reading object bytes but before writing Stage. Both legacy `CommitWorkspace` and strict `CommitStagedWorkspace` acquire the same row lock through CAS UPDATE and refuse any new manifest asset whose digest currently has a live GC claim; refusal rolls back the revision. Existing committed idempotency replays remain read-only.

These boundaries serialize *committed metadata references* against claims. They cannot prove external S3 objects have not been changed by privileged operators, and they do not turn a local claim into a lease covering remote deletion.

## Eligibility fail-closed policy

A claim requires at least one **expired, verified Stage** and no still-live Stage for the same scoped digest. Any reference in **any** historical immutable v6+ JSON manifest, including a superseded revision, blocks the claim. v7 committed reference rows are a second independent retention barrier.

Any v8 upload intent with a future deadline blocks the claim, as does an expired intent whose latest observation is absent or not `VERIFIED`. A missing/unknown/lost-ACK object is **not proven safe to delete**. A read-only `ClaimWorkspaceBlob`, `RenewWorkspaceGCClaim`, or `CheckWorkspaceGCClaim` validates these conditions under the Workspace lock; active rival holder, expired old holder or invalid generation fail closed.

A same-holder retry returns the identical live claim **without renewing** its expiry. Renew always increases generation and invalidates the old one; an expired claim may be reclaimed only with a strictly greater generation.

## Evidence and limitations

- Additive v9 SQL migration includes FORCE RLS for tenant+owner principal, exact Workspace FK, immutable identity and append-only audit guards, and checksum/drift verification.
- Tests use PostgreSQL 16 with race enabled, real DB-clock expirations, concurrent collectors, generation fencing, legacy v6 and v7 historical Manifest protection, active stage/upload denial, new write-path GC conflict and nonowner RLS.
- No S3 DELETE, GC tombstone, distributed transaction, automatic orphan cleanup, remote object proof, credential broker or production IAM is provided. GC claim metadata cannot ever be presented as a real-service cleanup authorization.
- Future destructive worker (outside this PR) requires separately authorized identity, EngageGuard Permit, immutable ActionHash, tightly scoped object key, fresh claim/retention verification at a serialized irreversible boundary, approved real MinIO/S3 deletion test, observability, and UNKNOWN/audit/restart handling. The owner must solve concurrency between Postgres commit and S3 DELETE; a DB check alone is **insufficient**.

Issue #40 covers this metadata-only slice. Parent #38 and storage backend gate #35 remain open until real provider, Cell teardown, authorization, recovery and correct deletion claims have been demonstrated.
