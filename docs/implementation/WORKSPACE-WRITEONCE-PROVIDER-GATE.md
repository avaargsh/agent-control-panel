# P0-2B5c-A — Real legacy MinIO overwrite failure, separate approved-provider WORM gate

**Status:** bounded non-production threat-model test and a **currently unproven, opt-in** provider acceptance contract. This is not a production S3 retention deployment and does not close Issue #47. No product S3 `DeleteObject` or GC execution has been enabled.

## Security boundary and authoritative facts

PR #46 demonstrated real MinIO service principal separation, tenant prefixes and `If-None-Match: *` returning HTTP 412 for a duplicate *compliant* PUT. However, the MinIO writer's checked-in IAM policy simply permits `s3:PutObject` for the tenant/Workspace digest prefix. A valid writer using an independent SigV4 client is **not** restricted by ACP's own conditional-PUT helper.

The real legacy-provider test `TestMinIOLegacyUnconditionalOverwriteGap` now **must** demonstrate, on the official SHA256-pinned 2025 MinIO release in a disposable CI bucket:

1. A writer-only identity conditionally PUTs a real SHA256-addressed asset and the *distinct* read-only identity verifies the original bytes.
2. A second conditional PUT to the same key returns HTTP 412.
3. The same valid writer sends a new independently signed **unconditional PUT** to that exact key with *different bytes of identical length*. On the historical unversioned MinIO server, this returns **HTTP 200**, and the independent reader's real raw GET sees the modified bytes.
4. The normal verified reader rejects the corrupted content with `ErrIntegrity`, not a success or object-missing claim.

The negative legacy MinIO witness and the manual positive approved-provider gate use a **separate, test-only SigV4 signer** (`internal/workspace/s3blob/raw_sigv4_security_test.go`) for PUT/GET/DELETE and one-winner concurrent PUT requests. It independently constructs canonical headers, payload SHA256, credential scope and HMAC signatures rather than calling ACP's production `Store.signedRequest`. This prevents tests from accidentally treating a production signer defect as an IAM denial. The historical disposable MinIO suite is the **positive control for the unconditional-signature variant**: the same independently signed unconditional PUT must produce HTTP 200 and mutate the canary, while conditional creation succeeds and duplicate conditional writes yield 412. If the raw signer is malformed, the legacy witness fails instead of recording a false-negative security finding. Test-only unit checks also inspect the authorization header's signed-header list and payload hash. **Neither this control nor a signed request alone proves an approved provider WORM policy is installed.**

A **green legacy MinIO gap test is negative security evidence** (a reproduced vulnerability), **not** an accepted write-once provider. The S3 adapter still detects digest mismatches on future reads, but it cannot restore overwritten original data or promise immutable historical retention.

## Approved provider contract (NOT yet executed)

A separate `TestApprovedS3WriteOnceSecurityGate` is selected only after explicit `S3BLOB_WORM_GATE_APPROVAL=approved-disposable-provider`, an approved **HTTPS-only** server endpoint, a dedicated bucket named `acp-writeonce-probe-*`, the exact provider Region, two distinct least-privilege writer/reader identities and a third **disposable, independently authorized copy-capable probe identity**. It creates **only disposable canary objects** using server-derived digest keys. It never deletes objects or touches a production tenant bucket.

It requires all of the following real-provider outcomes:

| Operation | Required response / evidence |
|---|---|
| First writer `PutObject` with `If-None-Match: *` | 200; separate reader hashes exact payload and size |
| Second conditional write of same key, including changed payload | 412; original SHA256 bytes remain unchanged |
| **Raw, independently signed unconditional** writer PUT of *different* bytes to an existing key | **403 from provider**, not from Go client or in-process mock |
| **Raw, independently signed unconditional** writer PUT to a *never-created* key in the same prefix | **403** even before any object exists; a subsequent conditional first PUT of that same key succeeds with 200 and is byte-verified; later unconditional PUT remains 403 |
| Reader after the forbidden overwrite | SHA256 and size still match the original |
| Writer `DeleteObject`, reader `PutObject`, writer PUT across tenant prefix | 403 |
| Writer attempting GET | Forbidden and classified as `ErrStorage` rather than `ErrObjectMissing` |
| Reader GET outside its tenant prefix; writer/reader list buckets; unsigned request | Provider rejects each, without in-process ACL shortcuts |
| Four simultaneous conditional PUTs of one new digest key | Exactly one 200, three 412; independent reader verifies winning bytes |

Source: AWS S3 official [Enforce conditional writes on buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes-enforce.html). AWS documents `s3:if-none-match` in bucket policies, including the `Null` condition for missing headers. This is not a claim that historical community MinIO implements the same IAM condition; the [MinIO PBAC documentation](https://github.com/minio/docs/blob/main/source/administration/identity-access-management/policy-based-access-control.rst) lists only a subset of supported condition keys and does **not** list `s3:if-none-match`.

A **template**, not an installed security policy, is retained as `.github/fixtures/aws-s3/writeonce-bucket-policy.template.json`. It has a single explicit `Deny` on `s3:PutObject` for missing `s3:if-none-match`, with the disposable tenant/Workspace digest prefix. The operator must replace `acp-writeonce-probe-REPLACE` with the actual approved scratch bucket, separately provision a scoped writer identity policy with no additional bypass grants, and validate the final policy on the target provider. This template assumes ACP's **single-PUT <=8 MiB** operation: no multipart policy exemption is added. Any future multipart path needs its own `s3:ObjectCreationOperation` review and negative tests, not silent broadening.

The checked-in AWS policy TEMPLATE is guarded by a table-driven static regression test that rejects weakened conditions, widened resource/action scope and changed DENY semantics. This protects review integrity, **not** the real provider's deployed bucket policy. AWS official documentation also notes that conditional-write bucket policies block `CopyObject` into the protected prefix and that multipart operations have separate `s3:ObjectCreationOperation` semantics. Those alternate API pathways and IAM/policy mutation must be evaluated independently before production promotion.

The manual workflow `.github/workflows/workspace-writeonce-approved.yml` uses an unprivileged main/SHA preflight before the `acp-writeonce-acceptance` GitHub Environment, explicit dispatch authorization, HTTPS/bucket/region checks, and separately provisioned environment secrets. The operator must independently configure required reviewers, protected environment controls, and approved disposable endpoint; **their existence/configuration has not been verified**. Missing secrets, an unapproved bucket, mismatched credentials, an HTTP endpoint, a skipped test, a 200/204 from raw unconditional overwrite, or absent explicit PASS marker causes FAIL. Neither this workflow nor the approved provider is currently asserted to have run successfully.

## P0-2B5g-A: fail-closed manual dispatch and environment credential governance

The manual `workspace-writeonce-approved.yml` is a protected **non-production test only** and must not be mistaken for provider installation, credential certification or release approval. On GitHub, `workflow_dispatch` can run against a selected branch or tag; `GITHUB_SHA` identifies the selected ref's commit at dispatch. It is unsafe to assume that the mere presence of an `environment:` name protects its secrets. The separate GitHub Environment settings are part of the trust boundary.

**Repository-workflow controls added here:**

1. The new first `validate-acceptance-ref` job receives **no S3 credentials**. It requires `GITHUB_REF=refs/heads/main`, a 40-character lowercase `expected_sha` from the operator, and equality with `GITHUB_SHA`. It also requires the exact disposable-provider authorization string before the protected job is eligible. Any mismatch **fails the entire workflow**, rather than producing an apparently green skipped provider gate.
2. The only secret-bearing `approved-s3-writeonce` job depends on that successful preflight and separately requires `github.ref == 'refs/heads/main'`. `actions/checkout` pins `inputs.expected_sha` and disables persisted GitHub checkout credentials; a second SHA check validates the checked-out HEAD **before** executing S3 test code.
3. The user-facing `authorization=approved-disposable-provider` string is **not authentication**. An independently configured GitHub Environment reviewer/branch restriction, trusted bucket identities and exact code review are mandatory.

**Settings that repository code cannot attest or install:** in repository Settings → Environments → `acp-writeonce-acceptance`, require human reviewers, disable administrator bypass where available, restrict deployments to **Selected branches and tags → branch `main` only**, and store the S3 probe writer/reader/copier secrets **only as environment secrets**. Avoid the weaker **Protected branches only** fallback while `main` is not actually protected: GitHub documents that this mode can admit all branches if no repository branch protection rule exists. Separately configure and verify a `main` Ruleset requiring review and exact-head status checks; workflow-generated evidence is merely advisory without repository settings enforcement.

**Observed read-only repository state at this change:** GitHub's `GET /repos/avaargsh/agent-control-panel/branches/main` reports `protected=false` and required status checks disabled, with main SHA `52f05d603ff1f42e9317dbe91407635b5bb1319c`. This is a **P0 governance release blocker**, not a check that this PR can repair through file edits. GitHub Environment reviewers, selected-branch policies and secret placement have **not** been independently inspected. Do not mark the manual acceptance as approved until those actual settings have been verified. A branch attacker able to rewrite a workflow file cannot be stopped by a guard contained only in that same workflow; server-side Environment branch restrictions are essential.

Official GitHub references: [workflow_dispatch selected ref and SHA](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows), [Environment secrets and protection rules](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments), [Manage environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments).

## P0-2B5g: independently authorized raw CopyObject matrix (contract ONLY, NOT RUN)

AWS S3 documents that a conditional-write bucket policy rejects an unconditional `CopyObject` into the protected prefix with **403**, while a conditional `CopyObject` may return **501**. This is **not** evidence that any configured provider enforces the policy; the existing AWS bucket-policy file is just an uninstalled review template.

The manual provider gate now requires a **third distinct scoped copy-probe identity**, bound only to the disposable canary bucket:

- `ACP_WORM_TEST_COPY_ACCESS_KEY` and `ACP_WORM_TEST_COPY_SECRET_KEY`, configured solely as protected GitHub Environment secrets.
- The copy-probe principal needs `GetObject` on the existing test-only source digest, `PutObject` for **conditional writes** to the exact protected test digest prefix, and `GetObject`/`PutObject` for the narrow **non-protected** `validation/copy-positive/*` scratch prefix. No `DeleteObject`, list-all-buckets or policy-admin permission is needed. Do not reuse the bootstrap administrator, normal production writer or reader identities.
- **Positive control A:** a raw, independently signed `CopyObject` from an existing disposable source to the *unprotected* `validation/copy-positive/*` prefix must return real HTTP 200 with a CopyObjectResult body; a fresh, independently signed GET from the **same copy identity** must reproduce the original bytes. A 403 due to missing source GET, invalid signature or absent copy rights is **not** WORM evidence.
- **Positive control B:** the **same** identity must successfully create and byte-verify a new protected digest key using its independently signed `If-None-Match: *` PUT (HTTP 200). This proves the identity has valid target-prefix write permissions, rather than receiving 403 for lack of `PutObject`.
- **Negative control:** this identity's independently signed, **unconditional** `CopyObject` to an existing protected key and to an absent protected key must each receive real provider HTTP 403; the previously committed bytes must remain unchanged, the absent key must still be absent, and subsequent legitimate conditional creation of that absent digest key must succeed with verified bytes. Source and destination must be **different** keys to avoid a trivial self-copy error.

The `X-Amz-Copy-Source` header is included in the independent test-only SigV4 canonical signed headers, not generated by `Store.signedRequest`. The manual workflow requires a dedicated `APPROVED COPY WORM CONTRACT PASS` log marker in addition to the existing PUT marker, and rejects skipped tests or missing third-party credentials. These new requests can create disposable canary objects only. They **never** delete buckets or objects.

**Status remains NOT RUN** until an independently reviewed supported HTTPS backend, bucket policy, separate service identities and exact-head manual workflow are provisioned and executed. A successful unit test of the signer is **not** a passed real CopyObject policy gate. Multipart completion, `UploadPartCopy`, alternate IAM routes, Object Lock/version IDs and approved provider restart remain separately blocked.

## Mandatory remaining checks for Issue #47

The approved gate additionally starts **four simultaneous conditional PutObject requests** for one new digest key, requiring exactly one HTTP 200 and three HTTP 412 responses and then byte-verifying the winner. It tests both raw unconditional writes against a **fresh digest key** and an already present key, each returning 403, while preserving legitimate conditional creation and rejecting changed-payload conditional replays. This is still **unexecuted** until an approved provider is configured. Full Issue #47 acceptance still requires a security-supported provider/version and **execution of the new unrun CopyObject acceptance**, plus independent evidence for multipart rejection, object versioning/deletion markers or a correctly verified Object Lock and pinned version ID when used, bucket policy mutation privileges, historical manifest retention across revisions, provider restart and operational audit. If versioned bucket reads are adopted, ACP receipts must pin the exact version ID; **Object Lock protects versions, not the meaning of the mutable unversioned current-key lookup**. See [MinIO Object Lock guidance](https://docs.min.io/aistor/administration/object-locking-and-immutability/) for version/delete-marker semantics.

ACP still owns tenant/Workspace/Session/RunIntent/DAS, v8 UploadIntent, v7 Stage/retention receipts and v9 database-only GC claims. Neither a database claim nor a compliant client header supplies a cross-system irreversible-effect guarantee. #35, #38, #43, #45 and #47 remain OPEN. No production deletion or G01–G05 promotion is authorized.

## Evidence discipline

- Legacy negative proof: only count as **observed** after exact-head real MinIO CI logs show the named test actually ran and printed `EXPECTED SECURITY BLOCKER`.
- Approved provider positive proof: **unverified** until an approved provider's exact-head manual workflow records the raw 403 and preserved bytes, with exact backend version, deployed policy and IAM evidence. A skipped test does not count.
- Changing a denied/unsafe outcome into a passing policy assertion without provider-side evidence is prohibited.

### P0 follow-up: independent reader authorization and secret-free dispatch rejection

The secret-free preflight rejects missing or incorrect disposable-provider authorization before the Environment job is eligible. This string is an explicit operator acknowledgement, not identity or authentication. The protected job retains its redundant check. The real-provider matrix now also requires a conditional first PUT signed by the reader principal to return 403; the same fresh key must then accept a legitimate writer conditional PUT (200) and verify exact bytes. An unconditional reader PUT alone could be denied by the global WORM policy even if the reader had PutObject rights. This is a test-only correction; approved provider execution and server-side Environment settings remain unverified.
