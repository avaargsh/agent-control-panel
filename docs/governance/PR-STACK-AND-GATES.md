# Cross-repository PR topology and P0 merge gates

Status: **PROPOSED sequencing / no automatic merges**.
Governance anchor: https://github.com/avaargsh/agent-control-panel/issues/3.

## Current branch topology (observed 2026-11-03)

This document covers **22 open infrastructure PRs across five repositories**.
The separate 3 open GRPO-Rag PRs are tracked as an independent S1/GxP
workstream; do not treat them as Control Plane implementation dependencies.
See `governance/pr-topology.v0.3.json` for exact reviewed heads.

| Repository | Open branches and ancestry | Integration decision |
|---|---|---|
| agent-control-panel (4) | #1 architecture; #2 Go foundation → #5 PostgreSQL; #4 governance | Preserve single ACP RunIntent authority; #5 stacks on #2 |
| agent-runtime (5) | #1 → #2 Temporal → #3 reliability → #6 RunIntent → #7 authenticated HTTP | Runtime #4 was merged into stacked #3 ancestry; do not reopen it |
| agent-decision (1) | #8 Go Decision Core; #10 transactional Outbox **merged into #8 branch** | Review #8 current head for both core and outbox, never double-merge #10 |
| EngageGuard (10) | New candidate: #5 → #14 → #16 → #17 → #18; #15 compatibility sibling from #5. **Legacy blocked lineage:** #9 (parent #8 closed unmerged) → #10 → #11; #12 branches from #9 | New #17 replaces old #9 ingress; new #18 replaces old #12 principal resolver. Retain useful Permit/Intent/Audit integrity from old #10/#11 by selective reviewed port only |
| compute-control-panel (2) | #1 architecture and #2 Go/PG/FakeProvider off main | Closed #6 must not reappear in the open inventory; provider production acceptance remains G04 |

`lineage_state=retired-parent-blocked` is intentionally **not** permission to
merge. The validator accepts an orphan only when the exact closed, unmerged
parent PR number, head branch and 40-character SHA are pinned. The label
propagates through its live children; neither approval nor production dispatch
follows. The existing retired branches remain open until all reviewed reusable
fixes are covered by replacement tests.

The GitHub `mergeable` flag and green branch CI are independent of the
cross-service security/recovery gates. No PR is automatically marked approved
or merged by the manifest.

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

Runtime → Guard ingress uses the unified `ActionSubmission v1` from new
EngageGuard #5. The operation-ID-bearing resolved `ActionRequest` is
Guard-internal and never accepted as caller-controlled identity. The new
acceptance stack (#14, #16, #17, #18) is a **Draft candidate**, not a
production enforcement path.

The old #9/#10/#11/#12 chain is based on the retired #8 migration parent.
Its one-time Permit/Intent/Audit integrity and v3 composite foreign keys are
reviewed implementation ideas that must be explicitly transplanted and
retested on the unified schema; do not merge the old chain as if it were a
successor. Until a real permit, trusted executor and UNKNOWN reconciliation
are proven, **protected side effects remain disabled**.
