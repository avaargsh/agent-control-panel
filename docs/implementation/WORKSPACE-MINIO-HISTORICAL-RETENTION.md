# P0-2B6 — Real MinIO + PG16 historical Workspace retention acceptance

**Scope:** real, non-production historical retention verification on the existing SHA256-pinned MinIO compatibility server and PostgreSQL16. It is **not** provider-enforced WORM, Object Lock, immutable version-ID proof or authorization to delete objects. Issue #47 remains **OPEN**.

## Why this slice

Earlier tests proved one successful scoped IAM Upload + Stage + CAS and genuine process SIGKILL recovery. They did not jointly exercise the **same logical asset path across two distinct content SHA256 keys and a third empty manifest revision**, verify both old objects independently after the last revision, or attempt database GC for both historical digests.

The new `TestWorkspaceRealMinIOHistoricalRetainedBytesPG` runs in the existing official legacy MinIO CI fixture with **independently provisioned** writer-only and reader-only service principals (no fixture administrator exported). The reader hashes actual remote bytes, not ETag or cached row metadata.

## Real external evidence assertions

1. A pinned ACP Workspace opens with revision 0.
2. A real scoped MinIO writer uploads bytes for `reports/historical-minio.md` at digest A, a different read-only principal verifies the content, and PostgreSQL16 commits an immutable Stage + Manifest receipt revision **1**.
3. New report bytes at **the same logical path** produce a new digest B and independent upload intent; revision **2** Stage + Manifest CAS succeeds; a fresh repository's current logical path reads digest B.
4. An empty revision **3** removes the path from the *current* manifest, not from historical retention. A fresh repository must return `ErrWorkspaceAssetNotFound` for the removed current path. This is important: the retained history must not be silently promoted into the live manifest.
5. A distinct reader-only principal fetches and SHA256-verifies BOTH A and B raw bytes after revision 3. Fresh repository replays of historical CommitIDs still return exactly the immutable original receipts.
6. PostgreSQL `ClaimWorkspaceBlob` for either digest MUST return `ErrGCNotEligible`; the append-only observation ledger records two `RETAINED` decisions and **no** GC claims. Verify exact two stage rows, two revision-bound retention references, three manifest receipts and matching revision/digest/path/size records.

The CI step requires `--- PASS` and the exact `REAL MINIO HISTORICAL RETENTION PASS` marker, runs `go test -race -count=1`, and is **before IAM reader-account revocation**. It fails closed on missing identities, unknown bytes, missing refs or GC unexpectedly being granted.

## What this does not prove

- The historical MinIO server itself is **known to allow** a valid scoped writer to bypass `If-None-Match: *` and overwrite a digest key with unconditional `PutObject` (PR #48 negative evidence, still valid after independent signer PR #51). This test uses a compliant ACP writer and **cannot establish server WORM**.
- The current production `ReadVerifiedWorkspaceAsset` API reconstructs only the **latest** Workspace manifest; reading older bytes in this acceptance test requires an already trusted, revision-bound `workspace.Asset` and the separate reader-only adapter. This is **not** a new public historical-read API and does not authorize arbitrary historical reads.
- PostgreSQL append-only refs and denied GC claims are **not** AWS S3/Object Lock version-pinned receipts, physical deletion prevention, or retention policy enforcement against privileged provider identities.
- No product `DeleteObject`, GC worker, overwrite API, new DB schema, new principal or production bucket operation is introduced.

## Remaining gates

Issue #47 needs a separately approved and supported backend to demonstrate **real server-side 403** on independently signed fresh-key and existing-key unconditional PUTs, with successful conditional positive controls, CopyObject / multipart / Object Lock/version-ID cases, provider restart, IAM mutation and historical retained-key evidence. #35, #38, #43 and #45 remain open. No G01–G05 claim or physical deletion is authorized.

The real MinIO compatibility test is integrated in `.github/workflows/workspace-minio-release.yml`. An exact-head hosted Actions pass, rather than static source review, is necessary before internally merging this bounded test-only slice.
