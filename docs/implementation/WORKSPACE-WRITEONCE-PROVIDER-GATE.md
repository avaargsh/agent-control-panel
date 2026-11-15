# P0-2B5c-A — Real legacy MinIO overwrite failure, separate approved-provider WORM gate

**Status:** bounded non-production threat-model test and a **currently unproven, opt-in** provider acceptance contract. This is not a production S3 retention deployment and does not close Issue #47. No product S3 `DeleteObject` or GC execution has been enabled.

## Security boundary and authoritative facts

PR #46 demonstrated real MinIO service principal separation, tenant prefixes and `If-None-Match: *` returning HTTP 412 for a duplicate *compliant* PUT. However, the MinIO writer's checked-in IAM policy simply permits `s3:PutObject` for the tenant/Workspace digest prefix. A valid writer using an independent SigV4 client is **not** restricted by ACP's own conditional-PUT helper.

The real legacy-provider test `TestMinIOLegacyUnconditionalOverwriteGap` now **must** demonstrate, on the official SHA256-pinned 2025 MinIO release in a disposable CI bucket:

1. A writer-only identity conditionally PUTs a real SHA256-addressed asset and the *distinct* read-only identity verifies the original bytes.
2. A second conditional PUT to the same key returns HTTP 412.
3. The same valid writer sends a new independently signed **unconditional PUT** to that exact key with *different bytes of identical length*. On the historical unversioned MinIO server, this returns **HTTP 200**, and the independent reader's real raw GET sees the modified bytes.
4. The normal verified reader rejects the corrupted content with `ErrIntegrity`, not a success or object-missing claim.

A **green legacy MinIO gap test is negative security evidence** (a reproduced vulnerability), **not** an accepted write-once provider. The S3 adapter still detects digest mismatches on future reads, but it cannot restore overwritten original data or promise immutable historical retention.

## Approved provider contract (NOT yet executed)

A separate `TestApprovedS3WriteOnceSecurityGate` is selected only after explicit `S3BLOB_WORM_GATE_APPROVAL=approved-disposable-provider`, an approved **HTTPS-only** server endpoint, a dedicated bucket named `acp-writeonce-probe-*`, the exact provider Region and two distinct least-privilege service identities. It creates **only disposable canary objects** using server-derived digest keys. It never deletes objects or touches a production tenant bucket.

It requires all of the following real-provider outcomes:

| Operation | Required response / evidence |
|---|---|
| First writer `PutObject` with `If-None-Match: *` | 200; separate reader hashes exact payload and size |
| Second conditional write of same key | 412 |
| **Raw, independently signed unconditional** writer PUT of *different* bytes to the existing key | **403 from provider**, not from Go client or in-process mock |
| Reader after the forbidden overwrite | SHA256 and size still match the original |
| Writer `DeleteObject`, reader `PutObject`, writer PUT across tenant prefix | 403 |
| Writer attempting GET | Forbidden and classified as `ErrStorage` rather than `ErrObjectMissing` |

Source: AWS S3 official [Enforce conditional writes on buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html). AWS documents `s3:if-none-match` in bucket policies, including the `Null` condition for missing headers. This is not a claim that historical community MinIO implements the same IAM condition; the [MinIO PBAC documentation](https://github.com/minio/docs/blob/main/source/administration/identity-access-management/policy-based-access-control.rst) lists only a subset of supported condition keys and does **not** list `s3:if-none-match`.

A **template**, not an installed security policy, is retained as `.github/fixtures/aws-s3/writeonce-bucket-policy.template.json`. It has a single explicit `Deny` on `s3:PutObject` for missing `s3:if-none-match`, with the disposable tenant/Workspace digest prefix. The operator must replace `acp-writeonce-probe-REPLACE` with the actual approved scratch bucket, separately provision a scoped writer identity policy with no additional bypass grants, and validate the final policy on the target provider. This template assumes ACP's **single-PUT <=8 MiB** operation: no multipart policy exemption is added. Any future multipart path needs its own `s3:ObjectCreationOperation` review and negative tests, not silent broadening.

The manual workflow `.github/workflows/workspace-writeonce-approved.yml` uses the `acp-writeonce-acceptance` GitHub Environment, explicit dispatch authorization, HTTPS/bucket/region checks, and separately provisioned environment secrets. The operator must independently configure required reviewers, protected environment controls, and approved disposable endpoint; **their existence/configuration has not been verified**. Missing secrets, an unapproved bucket, mismatched credentials, an HTTP endpoint, a skipped test, a 200/204 from raw unconditional overwrite, or absent explicit PASS marker causes FAIL. Neither this workflow nor the approved provider is currently asserted to have run successfully.

## Mandatory remaining checks for Issue #47

The current gate covers a single existing-key conditional/unconditional S3 PUT, byte-integrity, basic tenant and DELETE separation. Full Issue #47 acceptance still requires a security-supported provider/version and independent evidence for concurrent writers, CopyObject and multipart rejection, object versioning/deletion markers or a correctly verified Object Lock and pinned version ID when used, bucket policy mutation privileges, historical manifest retention across revisions, provider restart and operational audit. If versioned bucket reads are adopted, ACP receipts must pin the exact version ID; **Object Lock protects versions, not the meaning of the mutable unversioned current-key lookup**. See [MinIO Object Lock guidance](https://docs.min.io/aistor/administration/object-locking-and-immutability/) for version/delete-marker semantics.

ACP still owns tenant/Workspace/Session/RunIntent/DAS, v8 UploadIntent, v7 Stage/retention receipts and v9 database-only GC claims. Neither a database claim nor a compliant client header supplies a cross-system irreversible-effect guarantee. #35, #38, #43, #45 and #47 remain OPEN. No production deletion or G01–G05 promotion is authorized.

## Evidence discipline

- Legacy negative proof: only count as **observed** after exact-head real MinIO CI logs show the named test actually ran and printed `EXPECTED SECURITY BLOCKER`.
- Approved provider positive proof: **unverified** until an approved provider's exact-head manual workflow records the raw 403 and preserved bytes, with exact backend version, deployed policy and IAM evidence. A skipped test does not count.
- Changing a denied/unsafe outcome into a passing policy assertion without provider-side evidence is prohibited.
