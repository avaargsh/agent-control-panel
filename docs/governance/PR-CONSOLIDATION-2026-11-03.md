# 26-PR cross-repository review and convergence checkpoint

Observed: 2026-11-03. **Audit snapshot, not merge approval or a production readiness attestation.**
Source: the actual GitHub PR metadata, complete changed-file patch lists, review discussion, and workflow results on the inspected heads.

## Scope and exact open PR inventory (26)

| Repository | Open PRs | Count | Ownership |
|---|---|---:|---|
| [EngageGuard](https://github.com/avaargsh/EngageGuard/pulls) | #1, #2, #5, #6, #7, #8, #9, #10, #11, #12 | 10 | Protected action, policy/approval, Permit, action-level journal and receipt |
| [agent-control-panel](https://github.com/avaargsh/agent-control-panel/pulls) | #1, #2, #4, #5 | 4 | Agent/Release/Session and RunIntent authority |
| [compute-control-panel](https://github.com/avaargsh/compute-control-panel/pulls) | #1, #2 | 2 | Compute Workload/Allocation/ComputeOperation; Kueue/K8s/provider remain execution authorities |
| [agent-runtime](https://github.com/avaargsh/agent-runtime/pulls) | #1, #2, #3, #6, #7 | 5 | Run/Task/Attempt and Temporal orchestration |
| [agent-decision](https://github.com/avaargsh/agent-decision/pulls) | #8, #10 | 2 | Bounded decision proposal and immutable DecisionRecord |
| [GRPO-Rag](https://github.com/avaargsh/GRPO-Rag/pulls) | #1, #2, #4 | 3 | Separate RAG/GxP research and S1 platform workstream; **not** a sixth Agent Control Plane authority |

The existing `governance/pr-topology.v0.3.json` is a **historical, 2026-11-02 observation**, not a current 26-PR live gate. It contains closed runtime #4 (merged into its stacked parent), closed Guard #4 (not merged), omits multiple currently open PRs, and deliberately excludes the independent GRPO-Rag workstream. Its `--live` mode is expected to flag drift until a separately reviewed and pinned platform-only snapshot replaces it. Do **not** bypass its failure or treat its old 16-PR count as present-day authority.

## Stacked dependencies (not 26 independent merge candidates)

- **Guard:** #1 -> #2 -> #5 -> #7 -> #8 -> #9 -> #10 -> #11. #6 is a parallel test-only child of #5 and must be ported/retained before canonical hash promotion; #12 is a parallel mTLS child of #9. Neither #6 nor #12 implicitly includes the later #11 ledger repairs.
- **ACP:** #1 architecture and #4 governance are proposals off main; #2 Go foundation off main -> #5 PostgreSQL repository on #2. Ratify contract owners before merging standalone foundations.
- **Compute:** #1 architecture and #2 Go/PostgreSQL foundation are parallel main-based PRs; ensure domain vocabulary and contract tests agree.
- **Runtime:** #1 -> #2 -> #3 -> #6 -> #7. Runtime #4 is already merged into the #3 lineage; do not revive its closed PR. Runtime #2 reports `mergeable=false` despite an earlier green CI run.
- **Decision:** #8 Go Core -> #10 Outbox. Per-step evidence bindings remain normative; never remove them in an Outbox cleanup.
- **RAG:** #1 GxP experimental policy, #2 strict provider model response identity, and #4 budget holds are parallel main-based slices, none of which establishes a production end-to-end model gateway.

No approval of side effects, no automatic merge of stacked children into `main`, no branch force-push or deletion.

## Verified changes during this review

1. [Decision #10](https://github.com/avaargsh/agent-decision/pull/10): a shallow `Record.Plan.Steps[i].EvidenceRefs` clone could alias nested evidence data across returned records. Added a failing regression test (test-only commit `d638ad6e`, CI 41489559286 failed) and restored deep copy (fix `4b4d6f1e`, CI 41489595411 succeeded; subsequent current-HEAD workflow was also green).
2. [Runtime #7](https://github.com/avaargsh/agent-runtime/pull/7): HTTP SPIFFE identity gate did not check completed TLS 1.3 handshake or reject multiple URI SANs; configuration accepted an empty-query URI marker. Added negative tests and corrected handler/test fixtures (commits `22e812bc`, `9c6c5730`, `89add49a`). Exact patched-HEAD workflow 41489741975 succeeded. This does **not** replace a real mTLS listener handshake, rotation, revocation or signed per-tenant delegation test.
3. [RAG #2](https://github.com/avaargsh/GRPO-Rag/pull/2): live PR was non-Draft while the description said Draft and current head had no associated CI; converted back to **Draft**, retained `mergeable=false`. No code or authorization gate was relaxed.
4. [ACP #5](https://github.com/avaargsh/agent-control-panel/pull/5): checked a failed intermediate CI 41488733439 (all PG integration tests rejected migration schema); latest subsequently observed head `86b9dc0e` had successful workflow 41489121117. Older failed evidence is superseded, not silently rewritten. Database migration fail-closed remains a key regression test.

At the inspected instant, 23 of the 26 open PRs had an associated successful workflow for their then-current head. Guard #1 and Compute #1 are docs-only and had no associated workflow; RAG #2 also had none. This is not a complete multi-repository integration result.

## Remaining hard gates and release decision

| Gate | Requirement | Release disposition |
|---|---|---|
| G01 ACP -> Runtime | Durable RunIntent acceptance, same-key replay and lost-ACK recovery; only Runtime creates Run/Workflow IDs; no `ABSENT_UNCERTAIN` promotion to final absence | **BLOCKED**: no validated cross-service crash/restore golden path |
| G02 Decision -> Runtime | Go Decision Core v1 vs Python/TS Framework DecisionTurn are distinct interfaces; pinned schemas, authenticated Runtime/Run and immutable evidence binding | **BLOCKED**: adapters, version cross-tests and full replay evidence |
| G03 Runtime -> Guard -> executor | Stable caller submission key; Guard-owned operation ID and ActionHash; authorization, one-use Permit, post-crash reconciliation, trusted receipt and real executor | **BLOCKED**: no end-to-end protected execution with verified authorization and UNKNOWN recovery |
| G04 Guard -> Compute | Permit bound to exact Workload/Operation and tenant; provider state authoritative; Kubernetes/Kueue/DRA integration and provider UID exact deletion proof | **BLOCKED**: FakeProvider/PG success is not a real provider/Kubernetes admission test |
| G05 cross-service runtime | Temporal Server/Worker restart, outbox/inbox delivery, stale fencing, duplicate messages, tenant isolation and read-only SRE replay | **BLOCKED**: no real six-service E2E acceptance |

Additional separate RAG gate: GxP #1 is an assembly policy only; embedding #2 is not yet mergeable/current-head verified; budget #4 is admission-only, not wired to authenticated production ModelGateway, secret resolver, price book, provider journal or source-verified citations.

## Merge/convergence order

1. Resolve Runtime #2 and RAG #2 `mergeable=false`, re-run CI on the actual merge head, and restore accurate active PR inventory.
2. Ratify **single protocol owners**: ACP RunIntent, Runtime Run, DecisionRecord, Guard Action/Permit and ComputeOperation. Delete duplicate normative wire claims, not legitimate compatibility test fixtures.
3. Review/land **parent before child** (or selectively port a child's validated fix into the intended parent); preserve Guard #11 composite FK integrity and #12 authenticated identity adapter without assuming one child includes the other.
4. Prove G01 and G02 with a *real* PostgreSQL + Temporal read-only flow, including lost ACK, restart, replay, lease fencing, idempotency conflict and trust revocation. Only then activate protected paths through G03/G04.
5. Keep GRPO-Rag as an independent S1/GxP workstream. Archive superseded legacy plans; do not reactivate `gpu-compute-platform` or `agent-decision-lab` as active implementation owners.

**Decision:** all 26 stay under review; no production readiness declaration or automated merge. CI-green is necessary but insufficient. Each independently executed gate must pin exact commits, negative cases, operator authority and observable recovery evidence.
