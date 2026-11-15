# P0-2B4 — Controlled REAL MinIO protocol acceptance

**Status:** development-only, opt-in provider interoperability test. This scope is different from **production object retention, least-privilege credentials, Cell teardown and real GC deletion acceptance**, which remain blocked by Issues #35 and #38.

## Upstream provenance

The official `minio/minio` repository now distributes its community edition **as source**. Previously released precompiled assets are legacy and not maintained. The prior `quay.io/minio/minio:RELEASE.2025-09-07T16-13-09Z` image pull returned 401 before any backend could run ([failed historical workflow](https://github.com/avaargsh/agent-control-panel/actions/runs/43605382515)). We do not swap in a non-audited image mirror.

For compatibility testing only, `.github/workflows/workspace-minio-release.yml` downloads the **official GitHub Release binary** without using Docker Hub/Quay. Its exact fixed asset:

- Upstream release: [minio/minio RELEASE.2025-09-07T16-13-09Z](https://github.com/minio/minio/releases/tag/RELEASE.2025-09-07T16-13-09Z)
- Binary filename: `minio.linux-amd64.RELEASE.2025-09-07T16-13-09Z`
- Upstream GitHub Release API `assets[].digest`: `sha256:7c5bd8512c6e966455b1d198209358b2d191c77a83ab377c4073281065fb855f`
- The CI **fails closed** unless the downloaded binary matches that digest exactly, and also asserts the executable release version. No `latest` URL or untrusted mirror is used.

A successful run validates the **historical binary's S3 semantics**; it does *not* assert that an unmaintained release is secure/suitable for production. Later CI can replace it with a reviewed pinned-source MinIO build, but only after its provenance, license and security policy are reviewed. Keep `workspace-minio.yml` manual-only for separately operator-approved digest-pinned container acceptance.

## Real data-plane evidence

The workflow starts a disposable real MinIO process on `127.0.0.1:9000` and PostgreSQL 16 in a separate service. It executes two targeted `-race` tests:

1. `TestMinIOBackend` in `internal/workspace/s3blob` creates the test-only bucket using real SigV4, verifies conditional PutObject/GET/repeated PutObject(412), cross-tenant 404, and fail-closed response to **test-fixture-only privileged overwrite and deletion**. This test's DELETE call never exists in the production `Store` API.
2. `TestWorkspaceRealMinIOPGReconcile` in `internal/runintent/postgres` creates the real ACP pinned RunIntent/Workspace in PostgreSQL, records v8 UploadIntent **before** a real MinIO PUT, deliberately loses the transport ACK *after* the successful real MinIO write, and requires a fresh ACP `Repository` instance to re-read exact remote bytes before creating the v7 Stage and v6 committed manifest/retention refs. The same IntentID is retried without a second remote PUT. A new Repository verifies the committed report bytes via real MinIO, and foreign-tenant access is denied.

This bridges the existing Go+HTTP simulator with actual server-side SigV4 parsing and storage. The tests are still **within an isolated CI runner**, not an operational Cell restart with provider UID and authenticated entitlement boundary. No real GPU resources, runtime Run, Temporal activity restart or Guard Permit are involved.

## Gates still open

- MinIO/AWS S3 with approved supported release, production IAM/least-privilege credentials, retention/Object Lock/versioning, encryption and security acceptance
- Stronger restart/SIGKILL proof: upload during process termination, new OS process with preserved Workspace PG/S3, cleanup of expired intents
- Independently authorized real deletion worker with fresh irreversible-boundary fence and manifest lock, full delete audit, provider IAM, UNKNOWN reconciliation and G01–G05 evidence
- Authenticated ingress/revocation controls and Cell teardown with real Runtime/CCP/EngageGuard evidence

**Do not close Issue #35 or #38 from a successful standalone MinIO compatibility test.**
