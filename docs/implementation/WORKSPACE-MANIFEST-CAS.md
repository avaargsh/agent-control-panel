# P0-2A — Workspace manifest CAS, ACP Session / Thread binding

Status: implemented development repository slice (PR #34), **not** an S3/MinIO object-store integration, authenticated public API, production deployment or real Cell execution proof.

## Ownership and identities

- ACP owns Workspace identity and tenant/principal scope. User-facing **Thread** reuses ACP's existing `SessionID`; LangGraph checkpoint IDs, if introduced later, are runtime references and do not create a competing Session authority.
- `research_workspaces` stores one owner principal and monotonic `manifest_revision` for `(tenant_id,workspace_id)`. The same owner may attach additional Sessions through separate, ACP-pinned `RunIntent` locks.
- `workspace_manifest_commits` is append-only. A commit is bound by a composite foreign key to the exact `run_capability_locks` row, including tenant, principal, Workspace, Session and immutable DAS release digest. Run IDs and execution state remain Runtime-owned.
- No cell-local path, provider secret or caller-supplied object key becomes authoritative. The manifest contains relative logical paths and content digest/byte length only.

## Transaction boundary

`OpenWorkspace(ctx, pinnedLock)` verifies the lock persisted by ACP before creating or reading the Workspace identity.

`CommitWorkspace(ctx, pinnedLock, {CommitID, ExpectedRevision, Assets}, verifier)`:

1. Validates and canonicalizes a *complete* snapshot with unique paths, lowercase SHA256 digests, size limits and bounded count.
2. Begins a PostgreSQL transaction and revalidates the precise persisted DAS/Session lock. RLS policy variables are bound **only from a trusted caller's lock**, never raw HTTP request fields.
3. Reads an existing receipt by `(tenant,workspace,CommitID)`; an exact replay returns its original immutable receipt without verifying/uploading objects again. Conflicting replay fails closed.
4. Requires an `AssetVerifier` for every nonempty manifest; it must verify tenant/Workspace-scoped **immutable object bytes** using an actual trusted object-store adapter. This repository intentionally contains no S3 implementation, so no deployed nonempty commit is authorized until that adapter exists.
5. Executes `UPDATE ... WHERE manifest_revision=ExpectedRevision RETURNING manifest_revision`; zero rows means stale CAS.
6. Inserts a receipt with new revision, previous revision, original RunIntent, Session, DAS digest, content hash and JSONB manifest, then commits both mutations atomically.

A lost-ACK replay uses the same CommitID + content and receives the prior receipt; a *different* CommitID at a stale revision fails. A client-generated CommitID is an idempotency namespace, not an authorization key.

## Data integrity and recovery

- PostgreSQL migration v6 is additive and recorded in the existing checksum ledger. Existing v1–v5 records are preserved. Migration verification checks relation durability, FORCE RLS, tenant/principal policies, immutable mutation triggers, exact ownership FKs and the pinned lock unique index.
- `ReadWorkspaceSnapshot` reconstructs the latest committed manifest from PostgreSQL and recomputes its canonical digest; a missing or corrupt committed revision fails closed.
- Workspace storage is metadata-only in this slice. No implied S3 consistency, orphan reclamation, staged upload protocol, object proof, provider callback, distributed exactly-once behavior or Cell persistence.
- A non-owner restricted PostgreSQL role is exercised in integration tests for both tenant and principal boundaries. The policy is *defense-in-depth* and cannot replace real OIDC/SPIFFE authentication or an authorized entitlement source.

## Pending gates for Issue #33

- Trusted S3/MinIO staging/upload/verifier, immutable object namespace, HEAD+content checksum provenance, retention and orphan GC.
- Strict user/tenant/Workspace authorization at a production API enforcement point, and a privileged migration role separate from application role.
- Production crash/restart and object-store interruption proof with actual bytes; currently only PostgreSQL metadata reconstruction is tested.
- Runtime Run/Attempt evidence receipt linking and LangGraph checkpoint references, OpenSandbox SPI and verified external resource release.
- Recheck G01–G05 before promoting any cross-service execution or protected effect. No such claim is made here.

Do not equate passing isolated PostgreSQL tests with persisted document bytes.
