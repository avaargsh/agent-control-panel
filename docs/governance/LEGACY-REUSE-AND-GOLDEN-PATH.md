# Legacy capability reuse and acceptance plan — ACP vNext

Status: **PROPOSED / NOT RATIFIED** (2026-11-07).
Scope: `agent-control-plane` and `temp-runner` evidence mapped into `avaargsh/agent-control-panel`.
Target review: [ACP governance PR #4](https://github.com/avaargsh/agent-control-panel/pull/4). This document is **not** a wire contract, a migration authorization, or proof of a working deployment.

## Source and evidence boundaries

1. The former `avaargsh/agent-control-plane` repository currently returns 404 to the available GitHub connection. The pinned `agent-control-plane` revision in [temp-runner/stack-lock.json](https://github.com/openarc-labs/temp-runner/blob/main/stack-lock.json) is historical evidence of a source reference, **not** a verified accessible checkout or a passing test in the new architecture. Historical AgentBundle/Release, EvalGate, approval/credential and governance semantics are **reuse candidates** until source code and compatibility tests can be inspected.
2. The renamed/transferred [`openarc-labs/temp-runner`](https://github.com/openarc-labs/temp-runner) is a **disposable cross-repository integration harness, not a SandboxProvider or product-side runtime**. Its [README](https://github.com/openarc-labs/temp-runner/blob/main/README.md) specifies an immutable four-source Golden Incident lock, a kind/Temporal scenario, negative approval and recovery checks, and Actions artifacts. That locked stack targets legacy repositories, **not** the new ACP/Runtime/Guard/Compute authority set.
3. The [Authority Diff experiment](https://github.com/openarc-labs/temp-runner/blob/main/experiments/effective-authority-diff/ADMISSION_CAPABILITY_DRAFT.md) produces read-only, content-addressed signals. Its admission adapter is a draft; no ADMIT/DENY/PROMOTE, side effect or policy authority may be inferred from its output. A separate independent validation set is required before promoting it out of temp-runner.
4. The [workspace isolation PR #19](https://github.com/openarc-labs/temp-runner/pull/19) is design-only (worktree-first experiments); it is not evidence of deployed workspace isolation or a Sandbox service.
5. ACP `main` contains architecture material, while the Go foundation, persistence and message recovery reside in **unmerged Draft PRs**. All implementation claims below remain scoped to individual branches until tested on an exact merged head.

## Capability ownership map (reuse behavior, not legacy code)

| Historical capability or experiment | New single authority / integration | Preserve and prove | Do **not** port into ACP |
| --- | --- | --- | --- |
| AgentBundle, Release, immutable release inputs, EvalGate | **ACP** owns Bundle/Release intent and release decision references; evidence source retains original facts | Digest-pinned bundle and release revision; promotion must fail closed on missing/invalid source evidence and unapproved protected effects | Old Run executor, mutable evaluation results copied into ACP or a self-asserted `release_promotable` flag |
| Canonical agent/session identity, federation and context projection | **ACP** owns Agent, SessionIdentity and versioned binding/policy refs | Tenant/project isolation; stable Session across multiple Runtime-issued Runs; no raw secrets/context bytes in releases | Sandbox UID/Temporal workflow ID as Session identity; unscoped context/credential forwarding |
| Old control-plane Run lifecycle and dispatch coordination | **ACP** owns RunIntent + Outbox; **Runtime** owns Run/Task/Attempt and `run_id`/`workflow_id`; **Temporal** owns history | Atomic RunIntent+Outbox, scope-bound idempotency, digest conflicts, lost-ACK inspection, lease/fence and restart recovery | ACP-owned Run state machine, Temporal workflow starter or second Run ID allocator |
| Approval, action-bound credential, version/hash validation | **EngageGuard** owns Action, Approval, trusted ActionHash, one-time Permit and action Operation Journal | Bound actor/tenant/policy/release/action, expiry/revocation, canonical request hash, same-key exact replay and mismatch rejection | ACP as Permit signer, cached UI approval as execution grant, bearer token exposure |
| Resource admission and provider lost-ACK handling | **Compute Control Plane** owns Workload/Allocation/ComputeOperation; provider/Kubernetes/Kueue owns observed resource facts | Same operation ID after retry; inspect UNKNOWN before further mutation; generation fencing; exact UID/delete finality | Second scheduler, direct unguarded provider write or ACP compute operation journal |
| Sandbox/workspace isolation and credential/egress restrictions | Selected **SandboxProvider** and trusted gateway; ACP holds intent and opaque binding refs | Scoped workspace claim, identity/egress policy, inspect/release, revocation and concurrent-claim conflict tests | Importing temp-runner workflows as a production SandboxProvider |
| Effective Authority Diff and Golden Incident replay | Read-only **external evidence producers**; ACP references digests; existing admission/Guard makes decisions | Freeze source revisions and authority digest before review; reject changed deployment facts; retain artifact provenance | Making analyzer output a Permit, admission decision or source of truth |
| Cross-repository acceptance harness | Disposable `temp-runner`-style **test-only** pipeline | Immutable SHA lock, verified checked-out commits, adversarial fixtures, crash/replay receipts and retained artifacts | Treating CI green or simulated kind tests as real provider, production or security acceptance |

Follow [governance v0.3](./PLATFORM-v0.3.md) and [ADR-0003](./ADR-0003-ACP-RUNTIME-EVIDENCE-DATA-BOUNDARY.md) where they differ from older ACP `main` baseline wording. In particular, **RunIntent is not Run** and **temp-runner is not SandboxProvider**. Those old baseline descriptions must be reconciled before architecture ratification; this document does not silently rewrite published API versions.

## Two separate Golden Paths and release gates

### A. Read-only identity/recovery path — G01/G02/G05 prerequisite

`authenticated principal → ACP RunIntent (PG transaction + Outbox) → authenticated Runtime accept/inspect → Runtime-issued Run ID → Temporal → read-only Decision → EvidenceRef projection`

Acceptance requires:

- Duplicate tenant-scoped `Idempotency-Key` with the exact digest returns the same RunIntent and no extra outbox fact; changed digest, actor, policy/release snapshot or tenant fails closed.
- Runtime is the only source of `run_id` and canonical `workflow_id` (`agent-run/v1/{run_id}` in the present draft). ACP cannot mint one after a timeout.
- Lost StartRun ACK, broker duplicate/delayed delivery and restart preserve one authoritative Run mapping. Runtime inspect `ABSENT_UNCERTAIN`, 404, timeout, 5xx or invalid mTLS **never** become `NOT_FOUND_FINAL` or authorize a fresh StartRun. Until a definitive authority-backed absence barrier exists, retain UNKNOWN / RECONCILING or manual intervention.
- A stale outbox or inbox owner cannot ACK, settle or persist a Runtime receipt; replay after process kill reuses the original idempotency/digest, not a new Run.
- No protected provider action is enabled; a read-only success does not pass G03 or G04.

### B. Protected-effect Golden Incident — G03/G04 after A

Recreate the `temp-runner` fault model with new source repositories, not a renamed legacy acceptance result:

1. Pin exact ACP, Runtime, Decision, EngageGuard, Compute and Sandbox-adapter source revisions; verify every checkout before starting the scenario. Preserve an immutable lock and tested environment manifest.
2. Freeze release, actor/policy, requested action and effective-authority facts. A non-matching or unrelated approval must not change the target; an exact matching approval may only lead to the Guard-owned Permit/one-time claim.
3. In the historical `checkout-api` scenario, only the exact permitted action can scale **2 → 4** replicas. Duplicate approval delivery must not create another authorized action or second provider mutation.
4. Lose the provider ACK after a possible side effect. Inspect the provider-visible stable operation ID and exact resource UID before retry; reject concurrent owner takeover and stale generation. UNKNOWN cannot be asserted FAILED or SUCCESS without an authoritative receipt.
5. After a verified effect, terminal Runtime replay reuses the one durable Guard/provider receipt and does not reattach or re-execute. Verify post-action SLO/Prometheus evidence and immutable lineage to release/RunIntent/Run/operation.
6. Release promotion requires independent evaluation of complete source evidence; neither a green unit suite nor a UI status nor an unverified Authority Diff alone grants promotion.

The historical [Golden Incident README](https://github.com/openarc-labs/temp-runner/blob/main/README.md) defines the old scenario. **No new-architecture six-service E2E has been established by this proposal.** Any real GPU, live Kubernetes isolation or production claim requires its own environment-specific proof, separate from kind/fake-provider results.

## Minimum acceptance record

Each assertion must contain: exact source and dependency commit SHAs; test entrypoint; clean environment and versions; operator/actor identity class (without credential bytes); immutable RunIntent/Run/operation IDs; input/policy/release digests; scenario and injected fault; observed receipts + raw log/artifact links; verifier result; and a limitation statement. Classify every capability as **designed**, **implemented**, **locally tested**, **live integration tested**, or **unknown**. A result from one stage must not be promoted to a stronger stage.

| Priority | Current ACP slice | Existing branch/PR | Next verification; **not yet accepted** |
| --- | --- | --- | --- |
| P0 | Go RunIntent invariants | [#2](https://github.com/avaargsh/agent-control-panel/pull/2) | Reconcile ID ownership with governance and signed principal/policy binding |
| P0 | PostgreSQL RunIntent+Outbox | [#5](https://github.com/avaargsh/agent-control-panel/pull/5) | Real PG idempotency, immutable policy snapshot, crash windows |
| P0 | Leased publisher | [#6](https://github.com/avaargsh/agent-control-panel/pull/6) | Stale-lease fencing and no ACK before durable settlement |
| P0 | Ordered Inbox and broker settlement | [#7](https://github.com/avaargsh/agent-control-panel/pull/7), [#17](https://github.com/avaargsh/agent-control-panel/pull/17) | Exact merged-tree PostgreSQL + real JetStream ACK/DLQ, duplicate/gap and restart checks |
| P0 | Authenticated read-only Runtime Inspect | [#14](https://github.com/avaargsh/agent-control-panel/pull/14) | Ratify Runtime principal/policy contract; real mTLS and lost-ACK inspect before StartRun |
| P1 | Bundle/Release, EvidenceIndex, sandbox binding | No accepted end-to-end ACP implementation identified | Versioned API contracts, tenant AuthZ, immutable evidence lookups, separate SandboxProvider contract |

## Merge and migration discipline

Keep this work in the existing governance Draft PR #4; **do not create another independent architecture Draft chain**. Code merges remain parent-first and exact-merged-head tested. PR #14 and #17 are sibling integrations over Inbox #7, not independent evidence that either includes the other.

Do not revive or vendor the inaccessible legacy Control Plane, create a second desired-state writer, introduce a custom sandbox/SQL/workflow engine, or alter production provider paths based on `temp-runner` experiments. The next executable milestone is **authenticated ACP↔Runtime read-only RunIntent recovery with real PostgreSQL+Temporal**; only then extend the disposable integration harness to protected effects.
