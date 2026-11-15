# P0-2B3A: durable pre-PUT intent and UNKNOWN reconciliation

Status: **internal development repository slice only**. Follows Workspace v6 (Manifest CAS), v7 (staged/committed object refs), and signed S3 bytes adapter (PR #36). Issue #38 remains OPEN for GC fencing, external resource ownership and real provider acceptance.

## Ordering and ownership

- The trusted ACP adapter owns the tenant, principal, Workspace, Session, RunIntent, pinned DAS digest and upload evidence. Runtime does not gain a second Workspace/Session authority. S3 holds bytes, not ownership.
- `BeginWorkspaceUpload` atomically persists one immutable `workspace_upload_intents` row (v8) **before any remote PUT**. The row binds the exact caller-resolved RunIntent/Session/DAS digest, expected asset SHA256/size/logical path and a bounded database-clock lease (1–86400 seconds). Idempotent replay cannot silently renew a deadline or mutate expected bytes.
- `UploadWorkspaceObject` first prevalidates a bounded <=8 MiB input stream's *actual SHA256 and length*. Only then does it persist the intent and invoke one trusted backend PUT. A duplicate IntentID only attempts read-only byte reconciliation, never a second PUT.
- A lost/ambiguous PUT ACK appends an immutable `UNKNOWN` observation; it never converts UNKNOWN into FAILED, publishes a manifest, creates a verified Stage or deletes remote bytes.
- `ReconcileWorkspaceUpload` loads the exact pinned/authorized intent, checks the **server-side PostgreSQL clock** against its deadline, re-reads actual scoped bytes via the trusted `AssetVerifier`, validates the deadline again, then creates the v7 Stage idempotently and appends `VERIFIED`. The preexisting `CommitStagedWorkspace` still re-verifies bytes before database CAS and persists object refs atomically. A cancelled request may leave only the durable intent, which is by design reconcilable.
- The legacy direct `StageWorkspaceAsset` and `CommitWorkspace` APIs stay available for source compatibility, so not *every* Workspace commit requires a v8 intent until a trusted ingress adapter expressly selects the stricter flow.

## Schema and evidence

- v8 adds immutable `workspace_upload_intents` and append-only `workspace_upload_observations`, with tenant+principal FORCE RLS, composite FKs to exact pinned RunIntent/Session/DAS scope and immutable trigger guards. An observation FK binds the exact owner principal, not tenant alone.
- Migration v8 is embedded, checksum-ledger-verified, schema/trigger/policy drift-checked; upgrading historical fixture tests strips future schema in dependency order.
- Real PostgreSQL 16/race tests cover durable intent before a fake network effect, duplicate/concurrent intent registration, lost PUT ACK with bytes already stored, fresh Repository reconciliation and staged Manifest commit, same-key no-rePUT, foreign principal denial, malformed/expired leases, wrong digest prevalidation and forced-RLS drift.
- Signed HTTP S3-simulator + PG integration now exercises the pre-PUT intent -> signed actual-byte PUT -> verified v7 Stage -> CAS -> reopen/read path. This test is **not a real MinIO/S3 provider acceptance test**.

## External/production gates not passed

1. Approved, digest-pinned real MinIO/S3 instance and signed Put/Get acceptance with bucket IAM/Object Lock, immutable retention and per-principal credential brokering. The historical upstream Quay image previously returned HTTP 401 before a test could start.
2. Provider UID/namespace/attempt journal, liveness and SIGKILL recovery in a real execution Cell, authoritative subscription revocation and authenticated API.
3. Two-phase, fenced GC claims; recheck every historical manifest/reference under an authoritative claim before deletion; separate delete service identity; receipts for UNKNOWN outcomes. **No S3 DELETE API exists in this PR.**
4. G01–G05 cross-service Runtime/EngageGuard/CCP evidence and production launch authorization.

Do not conflate an append-only PostgreSQL upload observation or simulated HTTP byte verification with actual provider-side object permanence.
