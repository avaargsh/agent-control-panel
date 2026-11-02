# Cross-repository PR topology and P0 merge gates

Status: **PROPOSED sequencing / no automatic merges**.
Governance anchor: https://github.com/avaargsh/agent-control-panel/issues/3.

## Current branch topology (observed 2026-11-02)

| Repo | Open Draft PRs | Role / handling |
|---|---|---|
| agent-control-panel | #1 architecture; #2 Go RunIntent foundation (both based on main) | Reconcile architecture before integrating schema/Go foundation |
| agent-runtime | #1 baseline → #2 Temporal Spike → #3 reliability → #4 PG RunStore | Stacked PR bases; review ancestry and green code before promotion |
| agent-decision | #8 Go-first Core (main); #3 SRE Core (main) → #7 PG/outbox (base #3); #1 plugin baseline (main) → #2 Python host (base #1) | Choose #8 as candidate Core. Diff and selectively port #3/#7; isolate #1/#2 framework work |
| EngageGuard | #1 baseline → #2 ActionRequest/Hash | Block contract merge until operation ID and canonical hash fixed |
| compute-control-panel | #1 baseline; #2 Go/PG foundation (both based on main) | Retain state machine/schema; test real storage and FakeProvider |

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
