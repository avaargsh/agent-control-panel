# Main protection audit (read-only; #107)

This audit observes GitHub configuration; it **does not** create protection,
approve a PR, merge code, or authorize production. A passing result only means
selected effective-rule prerequisites were observed at a pinned main SHA.

**Repository administrator action required:** configure effective main
protection that requires pull requests, disallows force push/deletion, and
requires strict status checks. Verify the actual **job** names from passing
GitHub Actions: `verify`, `actual-broker`, `local-repro`, `contracts`,
`evidence` are the five observed on #168. Apply any other independent
Sandbox/security requirements appropriate to the changed paths.

The checker reads `GET /branches/main` and
`GET /rules/branches/main` (effective server rules).
It fails closed on missing, inaccessible, inconsistent, or ambiguous responses.

Run with a separately authorized read-only token supplied through a
secrets manager, pinned to the currently observed main SHA:

```sh
python3 scripts/audit_main_protection.py \
  --repository avaargsh/agent-control-panel \
  --expected-main CURRENT_40_CHARACTER_SHA
```

Set `ACP_GOVERNANCE_READ_TOKEN` in the process environment, not in
command arguments or shared logs. Unit tests need no GitHub credentials:

```sh
python3 -m unittest discover -s tests -p test_main_protection_audit.py -v
```

The on-demand `Main protection read-only audit` GitHub workflow accepts a
pinned SHA and uses read-only GitHub credentials. A 401/403, stale SHA or
unknown effective rule is **BLOCKED**, not a pass.

**Important limits:** Effective rules do not attest that ruleset bypass
actors are absent, that administrators cannot override every rule, or that
a human approved the target change. Verify exceptions and actual
bypass permissions in the GitHub admin UI and exercise a disposable
negative test PR to confirm server-enforced rejection. Classic branch
protection configuration must also be checked in the authoritative
branch protection API/UI. #107 remains open until those independent
checks pass. <Technical GREEN> is not production authorization.
