# P0 Sandbox stack & postfault: independent review / main-promotion ledger

**Snapshot date:** 2026-11-23. **Disposition: HOLD / no main merges / NOT an independent review.**
**Tracking:** [Governance blocker #107](https://github.com/avaargsh/agent-control-panel/issues/107), [source ownership and execution #70](https://github.com/avaargsh/agent-control-panel/issues/70).

This is a source-pinned decision packet for *external human reviewers*, not a generated sign-off. The historical governance topology documents predate this stack and must not be mistaken for its approvals. Do not set `ready_for_review`, enable auto-merge, issue `APPROVE`, promote production execution or merge into `main` on the basis of this packet alone.

## Observed protected-target controls

At snapshot, `main=468c13bdb499dc3f33e4073cf58b8a31ff04dccc`, the branch endpoint reported `protected=false`, `required_status_checks.enforcement_level=off`, and the repo rulesets listing returned `[]`. An attempt to read the detailed main branch protection endpoint through the connected integration returned HTTP **403**. **No existing server-side reviewer or CI enforcement can be asserted.**

**Repository owner/admin must separately configure and independently verify**:

1. Rule targeting `main` with PR-only merging, no direct pushes, force-push or deletion, enforced rules without admin bypass, required resolution of blocking review conversations.
2. At least **two non-author human approvals** on P0 migration/tenant isolation/sandbox-security changes: one independent PostgreSQL/RLS/Sandbox reviewer and one cross-service ACP/Runtime/Guard boundary reviewer. Author comments, bots, generated reports and AI-assisted self-review do not satisfy this. Dismiss stale approvals after newer commits; require last push approval by a different eligible person. Add verified `CODEOWNERS` for relevant paths only after real, willing owners are identified (a guessed username is not security).
3. Required **GitHub job check contexts** resolved from exact check runs after the rule is installed: Go + PostgreSQL + Race, Sandbox PG16/CommandJournal/tenant negative tests, legacy compatibility, PR evidence declaration, and scope-appropriate postfault full Golden Path. Do not assume the workflow display title is the enforceable check context. Pin to the currently reviewed integration revision, fail on missing/skipped checks.
4. Verify active rule API/UI and a deliberately unapproved test PR on the actual target before considering enforcement active. Without that evidence, **policy as Markdown is advisory only**.

## Exact-head stack inventory

| Review order | PR | Feature HEAD | Base and authority boundary | Current disposition |
|---|---|---|---|---|
| 1 | [#81](https://github.com/avaargsh/agent-control-panel/pull/81) | `a2b6ea8b040180760e81273f16206e0742e86274` | `main`; isolated Sandbox DB / non-dispatch command+outbox | Draft; 0 reviews; CI at exact feature HEAD passed, current `main` is 5 commits ahead of its merge-base |
| 2 | [#83](https://github.com/avaargsh/agent-control-panel/pull/83) | `b2bfa21277621d5af0463329b5d19974a59ee00b` | #81 branch; pre-Permit lease intent CAS/outbox | Draft; 0 reviews; existing-base CI passed |
| 3 | [#84](https://github.com/avaargsh/agent-control-panel/pull/84) | `e9d74571b16d1c994037bdb7e13b3af4cfa5ba50` | #83 branch; diagnostic read-only CLI/revocation | Draft; 0 reviews; existing-base CI passed |
| 4 | [#102](https://github.com/avaargsh/agent-control-panel/pull/102) | `7abe480007692e370c790957baf12acf923b36c6` | #84 branch; Command/Outbox tenant RLS, privilege hardening | Draft; 0 reviews; existing-base CI passed |
| separate P0 | [#91](https://github.com/avaargsh/agent-control-panel/pull/91) | `3cbf2263567e68b1f6ed59b0bc743ed69f9fcb58` | `main`; same-Run signed postfault evidence acceptance only | Draft; 2 owner `COMMENTED` (not human independent approvals); full Golden Path **BLOCKED** |

The stack #81 → #83 → #84 → #102 was ancestry-verified: each child's merge-base is its exact parent HEAD, `behind=0` relative to that parent. #91 is a **separate branch**, not an implied fifth serial child. GitHub's `mergeable=true` describes a code merge calculation, not policy readiness.

## Independent review work order

**Review A — Standards/security engineering (external Sandbox/PG reviewer):**

- Verify isolated DB vs ACP authority. Review migrations 0001–0012 in final cumulative order, additive/rollback safety, outbox atomicity and immutability, `CommandID` idempotency, request digest and per-tenant isolation.
- Attack PostgreSQL role boundaries: direct and delegated `NOINHERIT/SET ROLE`, `pg_*` capability groups, arbitrary-schema DDL, external table/column/sequence grants, `SECURITY DEFINER`, search path, RLS owner/BYPASSRLS, LOGIN/OID reuse, post-COMMIT revocation and principal eviction.
- Confirm actual per-PR diff and newly inherited parent changes, transaction/restart/parallel contention behavior, and source-pinned PG16 negatives. **Unit green is not physical/provider proof.**
- Give GitHub **APPROVE** only if scope-safe and exact HEAD/target integration is reviewed; otherwise formal **REQUEST_CHANGES** with path/line, exploit/negative case, fix and re-test evidence.

**Review B — Spec/authority/production SRE (external ACP/Runtime/Guard owner):**

- Validate spec [#70](https://github.com/avaargsh/agent-control-panel/issues/70): Runtime alone owns Run/Attempt, Guard alone owns Scope/Permit authorization, Sandbox alone owns Lease/AgentD process and journal, Compute alone owns provider Allocation/release; no second execution authority or API that trusts caller-supplied identity.
- Verify no dispatch path in #81–#102, none of the PRE-PERMIT records become a Permit or `UNKNOWN`/EXITED terminal provider receipt; `sandboxctl` is an untrusted local snapshot only.
- Review #91 signer trust roots and original receipt provenance, independently sourced Run/fault expected values, replay/time/JSON alias/canonical path denial, fresh `InspectCount` and journal version, preserved workspace bytes, Guard Permit Epoch vs Runtime breaker Epoch. No mock Ed25519 signatures or local OS test artifact may count as an actual four-source recovery proof.
- Confirm [same-Run Golden Path #45046073260](https://github.com/avaargsh/agent-control-panel/actions/runs/45046073260) fails with `EXTENDED GOLDEN PATH BLOCKED` until original Runtime/Sandbox/AgentD/Guard receipts exist. This failure is a **mandatory protected-effect blocker**, not a flaky CI to silence.

## Final merge sequence and stop rules

1. **STOP** until main is actually server-protected; external eligible reviewers are nominated and explicitly requested; exact HEAD approvals, comment resolution and required statuses pass.
2. **Only scoped non-dispatch code** may be considered for serial protected merging: #81 first against latest `main`, then #83, #84 and #102 one by one. Revalidate each merge against the current target. Prefer ordinary merge commits to **preserve stacked SHA ancestry**; avoid blind squash/rebase while child PRs depend on original ancestor commits. After the parent merges, retarget just the next child to `main`, inspect the exact diff and rerun integration CI; obtain refreshed independent human approval before its merge. This is a conditional process, **not advance authorization**.
3. After each actual merge, record target SHA, merged commit SHA, approved feature HEAD, reviewer handles + review commit, required job runs and exact target state, migration/rollback proof, and the unchanged non-dispatch feature flag/permission scope. An unexpected SHA, stale approval or missing source evidence means **HALT**, not retry/force.
4. Keep #91 **Draft and unmerged for full protected-path acceptance** while there is no genuine same-Run trusted Guard issuer/PEP, real Sandbox lease/workspace continuity, AgentD `UNKNOWN → InspectCommand → terminal or HOLD` source receipt, separate signed trust keys, provider UID absence/release and current CI. Do not edit failing Golden Path to green or use a database snapshot as physical evidence.
5. Production G01–G05 promotion requires a **separate**, human-signed service/physical release decision after all live tests and rollback drills. Landing data structures on `main` never confers permission to execute a protected command.

## Executable premerge policy auditor — advisory until server-side Ruleset enforcement

The source-pinned read-only checker is `scripts/check_p0_merge_readiness.py`, with fail-closed regression cases in `tests/test_p0_merge_readiness.py`. It contains **no** GitHub approval, reviewer invitation, merge, branch-setting or provider write API. It consumes independently queried REST metadata in **live mode**, never a user-authored offline snapshot as release authority, and returns a nonzero NO-GO for any missing, truncated, inaccessible or stale input.

To use it from a trusted operator checkout, inject a separately authorized **read-only governance token** via a secret manager into `ACP_GOVERNANCE_READ_TOKEN` (never commit or log it). Supply the current full 40-hex source HEAD and current target `main` SHA **explicitly**:

```sh
python3 scripts/check_p0_merge_readiness.py \
  --repository avaargsh/agent-control-panel \
  --pr 81 \
  --expected-head a2b6ea8b040180760e81273f16206e0742e86274 \
  --expected-main 468c13bdb499dc3f33e4073cf58b8a31ff04dccc
```

This is a **dated illustrative invocation**. Before a live review, replace both hashes with newly verified GitHub source and target SHAs, then require a source-pinned human review of any changed policy. If the token lacks access to branch protection, check runs or reviewer collaborator permissions, the preflight is **BLOCKED**; HTTP 403 must not become `[]` or `APPROVED`.

The checker requires: open non-Draft PR targeting current main; no main SHA or HEAD drift; authoritative main branch protection/review/check settings; strict current-base required job checks; at least two distinct **eligible non-author human** `APPROVED` reviews on the exact HEAD and no outstanding `CHANGES_REQUESTED`; stale-review dismissal, last-push approval, admin enforcement and conversation resolution. For stacked #83/#84/#102, it separately loads the pinned parent PR, demands that its exact reviewed HEAD was merged **into main**, and verifies its merge commit is an ancestor of the **current** main. Retargeting a child alone is not sufficient. #91 remains **hard BLOCKED** pending independent live same-Run physical and signed source evidence.

**Important limits:** Unit tests can validate reject/accept logic but do **not** prove that the public repository's branch rules are active. REST observations are subject to change between check and merge; GitHub server-side Rulesets/required check contexts, legitimate CODEOWNERS and actual human decisions remain the enforcement and authorization mechanisms. This script does **not** ascertain reviewer expertise or the correctness of their diff review, only GitHub identity/permission and exact reviewed source. Never treat an `ELIGIBLE_AT_PINNED_SHA_ONLY` string as license to merge, alter Guard/AgentD permissions, or release production. It is intentionally not an auto-merge gate and requires a separate admin-configured protected workflow before mandatory-enforcement claims.

## Reviewer ledger — must be populated by real GitHub actors

| Required field | Current value |
|---|---|
| Main branch protection/ruleset verified | **NO — open #107** |
| Independent PG/Sandbox reviewer GitHub login | **UNASSIGNED** |
| Independent ACP/Runtime/Guard reviewer GitHub login | **UNASSIGNED** |
| Current-head human approvals | **NONE for #81/#83/#84/#102; owner comments only for #91** |
| Exact current-main merge candidate CI | **NOT YET PERFORMED; #81 and #91 have divergent main ancestry** |
| Real same-Run cross-authority G01–G05 evidence | **BLOCKED** |
| Final go/no-go | **NO-GO** |

If source HEAD, main, reviewer, requested checks or evidence changes, create a **new dated snapshot**. Do not silently edit a previous approval record and present it as current.
