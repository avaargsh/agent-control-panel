# P0-2B5b-A — Real MinIO service identity separation and scoped IAM

This is **development-only nonproduction provider IAM evidence**, not a production security certification. Parent Issue #45 remains open until server-enforced write-once retention, credential revocation/rotation and approved production provider behavior are demonstrated. Issues #35, #38 and #43 remain open for broader actual storage, crash and Cell lifecycle gates.

## Principals and policy provenance

The real MinIO workflow uses the official historical server binary `minio/minio RELEASE.2025-09-07T16-13-09Z`, pinned and SHA256-verified as in PR #42. It separately downloads the official `minio/mc RELEASE.2025-08-13T08-35-41Z` Linux amd64 binary, pinned to its upstream GitHub Release asset digest `sha256:01f866e9c5f9b87c2b09116fa5d7c06695b106242d829a8bb32990c00312e891`.

The workflow gives the bootstrap administrator a **single, isolated CI provisioning step**, with a temporary private `MC_CONFIG_DIR`. It generates per-run random service secrets and masks them. It installs the exact checked-in JSON policies below on the real server via `mc admin policy create/attach`. The subsequent IAM tests receive **only** their scoped identities; MinIO root credentials and policy-management privileges are not passed to their Go tests.

| Identity | Allowed server IAM operation | Server-side S3 resource scope |
|---|---|---|
| `acp-ci-writer` | `s3:PutObject` only | `research-artifacts/v1/tenant/tenant-integration/workspace/workspace-1/sha256/*` |
| `acp-ci-reader` | `s3:GetObject` only | the same exact prefix |
| `acp-ci-other` | `s3:PutObject`, `s3:GetObject` | `research-artifacts/v1/tenant/tenant-iam-b/workspace/workspace-iam-b/sha256/*` |
| `acp-ci-denied` | none | no policy attached |
| `acp-ci-access` | CI-only MinIO bootstrap administrator | never passed to `TestMinIORealScopedIAM` or `TestWorkspaceRealMinIOScopedIAMPG` |

The exact policy JSON is retained in `.github/fixtures/minio/iam-writer-a.json`, `iam-reader-a.json` and `iam-tenant-b.json` and is not read from an external mutable URL.

## Minimal production-code change

`SplitRoleStore` composes **two distinct trusted `s3blob.Store` instances** that target the same provider endpoint, region and bucket:

- Its writer issues one conditional content-addressed `PutObject` using `If-None-Match: *`, with the same 8 MiB bound, canonical manifest path validation and SHA256 digest as the existing adapter.
- Its reader independently performs `GetObject` and rehashes actual scoped bytes. `Upload` can only succeed when both operations succeed. `ReadAsset` and `VerifyAsset` use the **reader-only principal**.
- The existing `Store.Upload` retains its original combined-identity behavior. No product `DeleteObject` method, GC worker, principal minting, cross-service claim or external user authentication is introduced.
- `SplitRoleStore` cannot establish that a provider identity has any real permission merely by comparing access-key identifiers: **server IAM is authoritative**. The test's actual 403 response matrix is required.

## Tested and untested behavior

`TestMinIORealScopedIAM` makes **real signed S3 requests**, asserting:

- Writer PUT with `If-None-Match: *` can create an asset, but writer GET and DELETE are `403`.
- Reader can re-read and SHA256-verify the asset, but reader PUT and DELETE are `403`.
- Second tenant cannot GET/PUT the first tenant's prefix, but can PUT/GET its own.
- A valid MinIO user with no policy cannot GET, PUT or list buckets. Neither scoped service identity can list buckets.
- A conditional duplicate PUT returns `412 Precondition Failed` and the adapter accepts it only when the independently authorized reader confirms the exact bytes. A forbidden GET remains `ErrStorage` (not falsely `ErrObjectMissing`).
- `TestWorkspaceRealMinIOScopedIAMPG` completes a real ACP v8 pre-upload intent, verified v7 Stage, v6 manifest CAS and persisted retention refs with the **two-role adapter**. A new Repository reopens the report bytes and rejects foreign-tenant lock replay.

The MinIO workflow explicitly asserts each test PASS; no missing env variable or skipped test can silently pass.

## Explicit unfinished security work

**This policy alone DOES NOT enforce unconditional write-once storage.** A user permitted `s3:PutObject` to a key might be able to re-PUT to the same key *without* the conditional header when bypassing this adapter. MinIO's `If-None-Match` API handling and a successful `412` only protect compliant clients. **Do not claim server-enforced immutability or production retention** until there is separate verified bucket/policy enforcement for conditional writes or independently approved versioned Object Lock. Audit, versioning, policy revocation, secret rotation, TTL/credential expiry and production backend security are still NOT proven.

No real Cell shutdown, Kubernetes/Temporal Attempt recovery, credential broker, signed identity token or G01–G05 is implied. Historic legacy MinIO and mc binaries are exact-SHA compatibility fixtures, not maintained 2026 production components. The fixture's admin still tests corruption/deletion in separate earlier provider tests against disposable objects. **Do not introduce an actual product DeleteObject endpoint or auto GC based on this IAM evidence.**
