# Cross-repository governance delta — 2026-11-04 (non-approving)

> **Authority:** observation only. This checkpoint does not supersede service-owned wire contracts, change G01–G05 from BLOCKED, approve PRs, or authorize Rust cutover. Evidence shown below was queried from GitHub PRs and Actions on 2026-11-04. Every head/CI pairing must be refreshed after a new push or parent change.

## Live identity reconciliation

A read of **currently open PR identities** in all six active infrastructure repositories returned **37 open PRs**: `agent-infra` 1, `agent-control-panel` 6, `compute-control-panel` 6, `agent-runtime` 12, `agent-decision` 2, `EngageGuard` 10. The legacy `governance/pr-topology.v0.3.json` contains an earlier **five-repository** open-PR observation and is **STALE**. Its successful local validation is not live topology evidence. `audit_pr_topology.py --live` MUST remain fail-closed until a reviewed, exact-head *six-repository* snapshot and validator are published. Do not bypass a live drift failure.

### Confirmed changed lifecycle

| Repo / PR | Observed state | Exact head observed | Evidence | What is NOT proven |
| --- | --- | --- | --- | --- |
| [Rust agent-infra #11](https://github.com/avaargsh/agent-infra/pull/11) | **MERGED** | `9849de54d36a199973ae0f35ec14ca1252608ad4` | Generic bounded Outbox Relay and event-specific transition-ACK semantics | No real Temporal Server, Rust Runtime cutover, protected effects or staging recovery |
| [Rust agent-infra #14](https://github.com/avaargsh/agent-infra/pull/14) | **OPEN / DRAFT** | `967b042bccba28bc197b5147dcba283e34dd7353` (later than initial `17b1de6`) | Initial CI [#41828146876](https://github.com/avaargsh/agent-infra/actions/runs/41828146876) **FAIL** at standalone Rust formatting; new head CI [#41828495039](https://github.com/avaargsh/agent-infra/actions/runs/41828495039) was running at observation | SDK compile and real Temporal worker/runtime/staging parity not yet accepted |
| [Compute #2](https://github.com/avaargsh/compute-control-panel/pull/2) | **MERGED** | `6e039b61cc420e4cec5689dcfd6bbc6fc4d45170` | Go/PostgreSQL foundation enters repository lineage | No live Provider/Kueue/DRA outcome |
| [Compute #11](https://github.com/avaargsh/compute-control-panel/pull/11) | **CLOSED / NOT MERGED** | `01feee55eb9f46b1f84d3caf662606d25493a815` | Historical exact-head PostgreSQL CI success [#41778745396](https://github.com/avaargsh/compute-control-panel/actions/runs/41778745396) | Do **not** count closed, unmerged PR #11 as a merge; verify any replacement/consolidated implementation in its actual main commit separately |
| [Compute #23](https://github.com/avaargsh/compute-control-panel/pull/23) | **OPEN / DRAFT** | `47219103d2e2f9d02daba9d4805447ba8fad9281` | Exact-head [#41812252270](https://github.com/avaargsh/compute-control-panel/actions/runs/41812252270) SUCCESS for calculator/E1 evidence derivation | Trusted production collection/ledger postings absent |
| [Compute #26](https://github.com/avaargsh/compute-control-panel/pull/26) | **OPEN / DRAFT** | `ae158a57aa2f283fea4dfa0ca4bfd367ac2ed11f` | Exact-head [#41812691473](https://github.com/avaargsh/compute-control-panel/actions/runs/41812691473) SUCCESS for immutable PG EvidenceSet | No live Provider/Kueue/DRA collector |
| [Runtime #21](https://github.com/avaargsh/agent-runtime/pull/21) | **OPEN / DRAFT** | `7b232fa8996e33fc827e8bfa133b25ec5c033a8d` | Merged-parent [#41827394704](https://github.com/avaargsh/agent-runtime/actions/runs/41827394704) SUCCESS | Production detector, Vault, managed keys, streaming/tool egress and real Temporal acceptance missing |
| [Runtime #8](https://github.com/avaargsh/agent-runtime/pull/8) | **OPEN / DRAFT** | `1e0c3867b6918bc2996524d94b401a066e07083d` | Prior [#41786965221](https://github.com/avaargsh/agent-runtime/actions/runs/41786965221) FAIL: malformed digest fixture and gofmt; three repair commits changed only fixture and formatting; new [#41828688710](https://github.com/avaargsh/agent-runtime/actions/runs/41828688710) pending/in-progress at checkpoint | No latest green until fresh run passes; child #9 must synchronize parent before release |
| [Decision #12](https://github.com/avaargsh/agent-decision/pull/12) | **OPEN / DRAFT** | `04b131033103f9c20526efb91475b33c5ef38a0b` | Exact-head [#41827065928](https://github.com/avaargsh/agent-decision/actions/runs/41827065928) SUCCESS | Unicode key hardening is not production tenant authority or Evidence provenance |
| [Guard #18](https://github.com/avaargsh/EngageGuard/pull/18) | **OPEN / DRAFT** | `1fd9058a564ba07e13ea96142015b8b87c52efc0` | Exact-head [#41594909226](https://github.com/avaargsh/EngageGuard/actions/runs/41594909226) SUCCESS | SPIFFE principal resolver alone is not deployed TLS listener, Permit or trusted executor |

## New P0 governance observations

1. **G01 — immutable source + single writer.** ACP RunIntent has no independently demonstrated immutable input-ref authority chain; Go Runtime remains the writer. The merged Rust relay changes no routing permission. Rust cutover remains `cutover_authorized=false`; do not use bare absence or timeout to cross-route an outstanding intent.
2. **G02 — qualified Proposal identity.** The proposed registry currently lists `proposal_id` under DecisionRecord, while Runtime #8/#9 implements durable TurnIntent and execution Proposal. This is an **unratified naming/authority collision**, not proof of two writers of the same object. Owners must explicitly distinguish Decision PlanCandidate identity from Runtime execution Proposal identity and record wire namespaces before any registry reassignment. Neither silently aliases the two.
3. **G03 — Guard accepted submission snapshot.** [Guard issue #19](https://github.com/avaargsh/EngageGuard/issues/19) remains blocked: the current acceptance path must preserve an immutable source submission and authoritative Guard-resolved ActionRequest/ActionHash before any Permit migration. Legacy WorkspaceWrite-specific hash/Permit code is not a generic replacement.
4. **G04 — Compute evidence boundary.** Deterministic calculator and immutable evidence persistence cannot be promoted to production metering or provider-execution authority without trusted collector, tenant/auth scope, actual Allocation/Provider observation and G03 Permit binding.
5. **G05 — real E2E.** Per-repository PostgreSQL/race CI and synthetic Golden Paths do not prove real Temporal worker restart, authenticated cross-service ACK loss, double-dispatch absence, Guard receipt validation, or staging deployment recovery. Maintain BLOCKED.

## Ordered next actions and minimal regressions

| Order | Owner | Blocker | Required regression before promotion |
| --- | --- | --- | --- |
| P0-1 | Runtime | #8 broken CI; #9 stacked against changed parent | Valid sha256-prefix fixture, exact-head gofmt/vet/race/PG17; then reconcile child #9 and rerun merged-head tests with concurrent correction/Commit, rollback, same-key replay |
| P0-2 | ACP + Runtime | G01 immutable input and lost ACK | Restart ACP + Runtime after committed Run acceptance and dropped HTTP ACK; identical replay finds canonical Run/workflow, changed digest conflicts, uncommitted absence stays ABSENT_UNCERTAIN |
| P0-3 | Decision + Runtime | G02 overlapping IDs/wire versions | Consumer-driven Go/Python/TS vectors; Decision PlanCandidate vs Runtime execution Proposal remain distinguishable; Runtime-issued run_id and invocation_id remain stable |
| P0-4 | Guard | G03 #19 durable snapshot/Permit | Restart after ACCEPTED, recover original immutable submission; resolve pinned ActionHash; changed policy/actor/contract must invalidate prior authorization; one-time Permit claim and UNKNOWN do not double-dispatch |
| P0-5 | Compute + Guard | G04 real Provider attribution | Provider Inspect verifies exact UID/generation, UNKNOWN may retry only with authoritative NOT_APPLIED_FINAL; corrupt/cross-tenant evidence fails closed |
| P0-6 | Rust + ACP + Temporal | Rust adapter parity / G01 | Actual Temporal Server start/duplicate/revision ACK/timeout, crash/restart, route-epoch rollback with single writer; child workflow receipt bound to event_id and Run revision |
| P0-7 | All | G05 | Staging Golden Path across PG, Temporal, Decision, Guard, Compute, authenticated edge, kill/ACK-loss and receipt verification |

## Evidence and revalidation policy

The four grades are **已实现 / 测试通过 / 真实环境验收 / 当前未知**. An exact-head green CI only supports *测试通过* for the tested scope. Any new head SHA, parent/base SHA, checked-in schema, or runtime contract makes downstream merged-head evidence **过期 / 需复验** until a fresh run on the new merged tree. In-progress and failed CI never count as a pass. All listed PRs remain subject to individual review and approval.
