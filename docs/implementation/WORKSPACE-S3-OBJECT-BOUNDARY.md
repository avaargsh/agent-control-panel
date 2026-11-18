# P0-2B1 — Workspace S3-compatible signed-byte boundary

**State:** internal Go S3 SigV4 adapter and PostgreSQL verified-read integration. This is a bounded development slice, not a complete production object-store pipeline. Issue #35 remains open until an approved real MinIO/S3 deployment, retention and recovery prove all gates.

## Authority

- ACP PostgreSQL remains authoritative for Workspace identity, owner, Session (Thread), pinned DAS release, manifest revisions and immutable receipts.
- Blobstore is an **internal-only** data-plane adapter invoked **after** trusted ACP principal/Workspace authorization. It does not authenticate Agent requests or mint new tenant identities.
- S3 object key is generated server-side: `/<bucket>/v1/tenant/<tenant>/workspace/<workspace>/sha256/<digest-hex>`; the agent supplies **neither** credentials nor raw S3 object keys.
- The object store does not own the Run, Session, Workspace revision, subscription or lifecycle of an execution Cell.

## Implemented boundary

1. `s3blob.New(Config)` requires explicit endpoint, bucket, region, access key and secret. Remote endpoints require HTTPS; only loopback HTTP can be enabled for disposable tests. Redirects are disabled, and credentials are never placed in URLs.
2. `Upload(ctx,tenant,workspace,logicalPath,reader)` validates logical path and tenant/workspace IDs, limits object size to **8 MiB**, computes SHA256 from actual bytes, and uses AWS SigV4 to submit a conditional `PutObject` (`If-None-Match: *`). A pre-existing digest key (412) is *not* trusted as identical until its bytes verify.
3. `VerifyAsset` issues a signed GET and reads the actual bytes. It never trusts ETag, HEAD-only existence, caller-supplied object metadata or user-stated digests. It verifies **both** exact byte count and SHA256.
4. `CommitWorkspace` continues to validate the trusted persisted DAS lock and perform PostgreSQL CAS+receipt atomically. It requires a trusted verifier for nonempty assets and checks the S3 object before recording the new manifest.
5. `ReadVerifiedWorkspaceAsset` first authenticates the pinned lock through ACP persistence, loads the latest committed manifest, refuses uncommitted paths and then calls the trusted byte verifier/reader.

This provides scoped byte-integrity verification at the *time of access*. It does **not** guarantee an external administrator will never delete/overwrite objects. Object Lock, IAM bucket policy, retention and audit are separate deployment controls.

## Test evidence and limits

- `internal/workspace/s3blob/store_test.go`: real HTTP request/response bytes against an in-process disposable S3 protocol simulation; verifies conditional put, repeat upload, foreign scope, corrupt/missing data, redirects, unsupported endpoint and size/path limits.
- `internal/runintent/postgres/workspace_object_integration_test.go`: real PostgreSQL v6 commit and fresh Repository metadata read; verified HTTP object read fails when bytes are changed/deleted.
- `internal/workspace/s3blob/minio_integration_test.go`: a separate, **opt-in** real MinIO API integration that creates a disposable bucket, signs SigV4 requests and tests actual Put/Get/412, corruption and deletion.
- `.github/workflows/workspace-minio.yml`: manual-only gate requiring an **operator-approved image pinned by SHA256 manifest digest**. The historical upstream Quay image returned 401 during PR run #43605382515; do not treat this as a successful MinIO test and do not substitute an unverified public mirror.

## Not yet proven / required before Issue #35 closure

- Actual MinIO/S3 instance E2E using an approved digest-pinned image/endpoint, including an object-verified report after destroying its execution Cell.
- Staged upload state, object retention references, crash-safe orphan collection, safe cleanup after DB rollback, expired grants and live revocation.
- Trusted principal/entitlement and credential broker integration, narrow bucket IAM/conditional-write enforcement, object versioning/locking, encryption, audit, rotation and 8 MiB+ multipart streaming.
- Cross-service Runtime/CCP/EngageGuard G01-G05 and deployment acceptance.

**Do not merge an execution-enabling integration based solely on this internal adapter's HTTP simulations.**
