# Cross-repository PR topology and P0 merge gates

Status: **PROPOSED sequencing / no automatic merges**.
Governance anchor: https://github.com/avaargsh/agent-control-panel/issues/3.

## Current branch topology (observed 2026-11-02)

| Repo | Latest observed open Draft PR topology | Governance handling |
|---|---|---|
| agent-control-panel | #1 architecture (main), #2 Go RunIntent (main), #5 PostgreSQL RunIntent (base #2), #4 governance (main) | #5 must remain stacked after #2; #1/#4 proposals not silently authoritative |
| agent-runtime | #1 baseline (main) → #2 Temporal Spike (base #1) → #3 reliability (base #2) → #4 PostgreSQL RunStore (base #3) | Preserve sequential review and ancestry |
| agent-decision | #8 Go Core (main) → #10 transactional Outbox (base #8). Legacy #1/#2/#3/#7 are no longer in the open-PR snapshot; do not delete their reviewed code without diffing. | Prefer Go Core #8 mainline; #10 as stacked Outbox |
| EngageGuard | #1 baseline (main) → #2 ActionHash (base #1), with competing siblings #4 and #5 (both based on #2). Prefer #5 as a candidate submission boundary; selectively port relevant #4 validation, do NOT merge both as if sequential. | #4/#5 parallel conflict recorded; no simultaneous independent merge |
| compute-control-panel | #1 architecture (main); #2 Go/PG/FakeProvider (main) | Keep FakeProvider evidence distinct from provider production approval |

**No PR is declared superseded, approved or merged by this matrix.** No existing branch is closed, rebased or rewritten automatically.

## Hard gates by service

| Gate | Owners | Blocker |
|---|---|---|
| G01 RunIntent/start idempotency/Run ID | ACP + Runtime | https://github.com/avaargsh/agent-control-panel/issues/3 |
| G02 Decision Core vs adapter wire schema | Decision + Runtime | https://github.com/avaargsh/agent-decision/issues/9 |
| G03 Guard Operation ID and ActionHash | Guard + Runtime | https://github.com/avaargsh/EngageGuard/issues/3 |
| G04 Compute Permit and provider reconciliation | Compute + Guard | https://github.com/avaargsh/compute-control-panel/issues/3 |
| G05 real PostgreSQL + Temporal read-only SRE golden path | Runtime + Decision | https://github.com/avaargsh/agent-runtime/issues/5 |

## Integration order

1. Ratify ADR-0001, Run ownership and Guard ActionRequest identity/hash ADR with consumer owners.
2. Freeze unique, versioned wire protocols and publish source-commit pins, fixtures and compatibility tests.
3. Integrate ACP RunIntent persistent idempotency and Runtime RunStore, with duplicate/lost-ACK tests.
4. Integrate Go Decision Core immutable records to Temporal Activity, with read-only SRE evidence verification.
5. Integrate EngageGuard journal/Permit with same-key replay and UNKNOWN crash tests; protected effects remain disabled beforehand.
6. Integrate Compute FakeProvider, then Kubernetes/Kueue and Sandbox with exact UID deletion verification.
7. Only then mark P0 golden path end-to-end complete and promote individual Draft PRs.

## Required PR body evidence

Every implementation PR must state exact base/head and dependencies, authoritative contract revision, tested source SHA, unit vs integration test coverage, affected domains, P0 threat/failure scenario, migration/rollback, unresolved blockers and explicit non-goals.

The proposal's CI checks a local manifest, not branch protection. Repository branch protection and cross-repo required checks must still be separately configured and verified.

## Observed live PR topology audit

The observation at `governance/pr-topology.v0.3.json` records current PR numbers, full source SHAs, head/base branches, mandatory gates and explicitly unresolved parallel branches. It is **not approval** and does not silently refresh.

- Default CI: `python scripts/audit_pr_topology.py` checks internal lineage, no self-approval, candidate conflict acknowledgement and blocker gates.
- Optional live check: `GH_GOVERNANCE_READ_TOKEN=<read-only-token> python scripts/audit_pr_topology.py --live`. An access/permission failure is an error, not an empty list. The separate token is required for private repositories.
- A SHA change, added/closed PR or missing parent will generate a **drift error**. The governance PR #4 is self-modifying: its head SHA may change as this same audit file is edited; only its existence is checked for live head drift.
- The CI workflow does not yet enforce cross-repository branch protections, so this is a human-reviewed audit; no action is auto-merged/closed.


## Guard contract authority correction

External Runtime→Guard ingress must use **ActionSubmission v1** from EngageGuard PR #5 candidate; the operation_id-bearing `ActionRequest` is a Guard-internal resolved record and cannot be sent by Runtime. The v0.3 registry pins these as distinct blocked contracts. Guard #4/#5 are sibling changes sharing a parent branch; do not merge both independently. Keep #4's validation improvements only after diff/review against #5. The database claim, hash, Permit and reconciliation remain G03 blockers.
