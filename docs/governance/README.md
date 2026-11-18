# Platform governance v0.3 — historical, unratified proposal

This directory contains a **proposal and a dated observation**, not the current
approved cross-service contract. It must not be used to authorize a Runtime
cutover, protected action, provider mutation, or a production deployment.

- `governance/contract-registry.v0.3.json` has `state: proposed`, and
  `runtime_migration.cutover_authorized: false`. The documented G01–G05
  readiness claims are historical and must be checked against current
  service-owned evidence before changing any release gate.
- `governance/pr-topology.v0.3.json` records an **2026-11-04** observation
  of 38 then-open PRs. It is **not** a live list or proof of contemporary
  ancestry. Some PRs in that snapshot have since been merged or closed.
- `scripts/audit_pr_topology.py --live` intentionally fails closed on
  changed PR identities/HEADs/base branches. Do not bypass this by weakening
  verification; regenerate a complete, source-pinned, dated observation
  across all six listed repositories before using a new snapshot for decisions.
- `scripts/check_governance.py` validates local manifest consistency,
  not remote GitHub facts, branch protections, owner ratification or E2E.
- The canonical PR template remains the newer version already on
  `main`. The historical template from PR #4 was **not** installed because
  it lacks exact BASE/HEAD and Main PR Evidence declaration fields.

**Promotion decision:** No governance/CI outcome from these historical
documents is a substitute for independent reviews, exact integrated-head
tests, required branch Rulesets or signed source-of-truth contracts.
