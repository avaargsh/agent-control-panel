# Main protection audit (read-only; #107)

This audit observes GitHub configuration; it **does not** create protection,
approve a PR, merge code, or authorize production. A passing result only means
selected effective-rule prerequisites were observed at a pinned main SHA.

**Repository administrator action required:** configure effective main
protection that requires pull requests, disallows force push/deletion, and
requires strict status checks. Verify the actual **job** names, not workflow display names.
For all main-targeted PRs, the existing unconditional jobs are `verify`,
`contracts`, and `evidence`. The `actual-broker` and `local-repro` POC jobs
use `pull_request.paths` filters; **do not set them as global required
checks**, since unrelated PRs would be blocked by skipped workflows.
Require POC/security checks only after providing an always-reporting wrapper
check or otherwise enforcing appropriate path-aware requirements.

The checker reads `GET /branches/main` and
`GET /rules/branches/main` (effective server rules).
It fails closed on missing, inaccessible, inconsistent, or ambiguous responses.
It requires the effective `pull_request` rule to enable
`required_review_thread_resolution`, and reads **all pages** of effective
rules with a bounded `per_page=100&page=N` pagination loop. A malformed
page or an exhausted page bound is BLOCKED rather than a partial pass.

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
