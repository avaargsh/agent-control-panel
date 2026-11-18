# ADR-005 — Subscription Researcher DAS Release Lock (P0-0)

**Status:** Proposed implementation slice. Local pure-Go domain tests passed; no authenticated API, database, entitlement service, real Agent Harness or sandbox integration is claimed.

## Problem

The proposed 4as subscription research product separates three lifetimes:

1. **DAS package release (read-only):** professional researcher instructions, Skills, references and execution requirements; an immutable version points to a content digest.
2. **Workspace / Session (read-write, persistent):** user-owned research materials and long-lived conversation/work identity; a product Thread maps to the existing ACP-owned Session identity instead of creating a competing Session authority.
3. **Cell (ephemeral):** a provider-owned code execution environment; it is not the authoritative owner of user files, Run state, billing or subscriptions.

The ACP already owns AgentBundle, AgentRelease, Session and RunIntent. Runtime owns Run/Attempt and Temporal; the Compute Control Plane owns compute allocations; SandboxProvider owns the actual sandbox lifecycle; EngageGuard owns protected effects. This ADR does not redefine those writers. See ADR-001 and ADR-004.

## Decision

Keep the P0 capability release binding inside ACP, not in a new microservice. The selected DAS release is a read-only package reference used by an ACP AgentBundle/AgentRelease, not a replacement for the latter. Each new RunIntent must be pinned to:

- authenticated tenant and principal;
- existing ACP AgentRelease, Workspace, Session and RunIntent IDs;
- DAS package ID, release version and exact lowercase sha256 artifact digest;
- subscription ID and authorization policy revision.

The package version is for human-visible release selection; the **digest** is the exact artifact identity. Even a request for 'latest' must resolve to a digest **before** execution. A new DAS release does not silently upgrade an in-flight RunIntent.

The new internal/researchlock Go package implements a **pure-domain validation boundary only**:
- deny unpublished, malformed or mismatched release selections;
- deny tenant/principal/package entitlement mismatches;
- deny missing policy revision and revoked/not-yet-valid/expired grants;
- bind a fixed tuple of run, workspace, Session, release and entitlement evidence;
- allow exact lock replay and reject conflicting replay.

Input authenticity is explicitly *outside* this package: an authenticated server-side adapter MUST obtain the Release from a trusted immutable catalog and the Entitlement from its authoritative store. These Go structs are never proof of authentication and MUST NOT be decoded directly from an untrusted request and treated as authorized.

## Proposed data and execution boundaries (not implemented)

- **DAS catalog / entitlement:** ACP-controlled bounded module, with immutable signed/reviewed OCI artifact references, one authoritative entitlement writer, version-aware cancellation/revocation policy and no provider secrets in bundles.
- **Workspace:** ACP owns workspace identity/ACL; a dedicated workspace asset store may own content revisions with an explicit service contract. Workspace files live in S3-compatible objects, with PostgreSQL manifest revisions, expected_revision CAS and tenant-scoped access; Cell files are only a projection or uncommitted scratch.
- **Thread:** user-facing alias for the existing ACP Session identity; LangGraph checkpoint references belong to Runtime/Agent harness and are not a second Session writer.
- **Run:** ACP stores the pinned lock **atomically with RunIntent and Outbox** using tenant-scoped uniqueness and replay comparison. Runtime carries a read-only pinned reference; it must not issue or mutate ACP release records.
- **Cell:** SandboxProvider owns sandbox ID and lifecycle; Runtime requests via a provider-neutral adapter, CCP only owns capacity when needed. Physical release requires inspect/absence evidence; ambiguous outcomes remain UNKNOWN.

### Launch sequence (target)

1. Authenticate caller and derive tenant/principal from verified identity.
2. Check workspace and Session scope against the ACP authority.
3. Read one published immutable DAS release and one active, tenant-scoped entitlement from server-side authority. Verify digest provenance/signature on artifact retrieval.
4. Resolve the capability lock and write it transactionally with the new RunIntent, using a unique idempotency key. For a duplicate intent, load its stored lock **first** and compare rather than resolving a new 'latest'.
5. Once accepted, Runtime acquires sandbox execution through a separately verified provider interface and surfaces only references to Workspace, Session and DAS. Revalidate revocation and EngageGuard approvals at protected action boundaries.
6. Commit workspace assets through expected_revision; release Cell only after provider confirmation.

No distributed exactly-once guarantee is implied.

## Alternatives rejected

- **Whole DeerFlow as authority:** useful Harness reference but must not own ACP tenant, release, entitlement, Run or resource authority.
- **Treat sandbox filesystem as Workspace:** loses user assets on reclamation and breaks cross-run concurrency.
- **Duplicate Thread identity in LangGraph:** creates competing session authorities. Use ACP Session with LangGraph checkpoint IDs as references.
- **Bind mutable version strings only:** allows in-flight artifact drift; require content digest.

## Proven in this slice

The local, standard-library-only Go package tests demonstrate: valid pin, replay conflict, malformed digest, unsupported state, cross-tenant/principal/package mismatch, missing policy revision, revoked grant, and temporal validity boundaries. Run with the repository's standard go test and race commands on the PR exact head.

## Not proven / required follow-ups

1. PostgreSQL release-lock schema + atomic RunIntent/Outbox transaction + tenant RLS + restricted-role migration and restart/replay tests.
2. Authenticated publisher/entitlement reader; cryptographic artifact provenance, entitlement revocation and cancellation behavior.
3. Workspace manifest versioning, ACL, concurrent CAS commits and durable S3-compatible object lifecycle.
4. Agent Harness adapter and separate SandboxProvider SPI; OpenSandbox first, CubeSandbox comparative benchmark.
5. Runtime/CCP/EngageGuard cross-repository acceptance and real provider release evidence. No G01-G05 or production gate is claimed green.

Do not merge an execution-enabling integration merely because this isolated domain slice passes.
