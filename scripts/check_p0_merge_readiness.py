#!/usr/bin/env python3
"""Read-only P0 PR merge preflight; never issues APPROVE, merge or a provider action.

An ALLOW means *only* that queried GitHub metadata meets these stricter
preconditions at the specified source/target SHA. Server branch Ruleset and
human operational authorization remain separate authorities. Failure to read
any required live fact MUST produce a nonzero exit.
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

SHA = re.compile(r"^[0-9a-f]{40}$")
REPO = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
SCOPED_SANDBOX = frozenset((81, 83, 84, 102))
PRODUCTION_GATE = 91


def evaluate(state, *, expected_head, expected_main=None):
    """Return concrete NO-GO reasons from a source-typed GitHub API snapshot.

    This pure function is deterministic for tests; caller-supplied snapshots
    are NOT trusted release attestations. Only the live REST collector can
    supply operational inputs, and even then no release action is taken.
    """
    errors = []
    if not isinstance(state, dict):
        return ["missing authenticated GitHub state"]
    if not isinstance(expected_head, str) or not SHA.fullmatch(expected_head):
        errors.append("invalid expected source HEAD")
    pr = state.get("pr") or {}
    branch = state.get("branch") or {}
    protection = state.get("protection") or {}
    reviews = state.get("reviews")
    checks = state.get("checks")
    number = pr.get("number")
    source_head = (pr.get("head") or {}).get("sha")
    base = pr.get("base") or {}
    main_sha = (branch.get("commit") or {}).get("sha")

    if number == PRODUCTION_GATE:
        errors.append("PR #91 real same-Run four-authority postfault/physical evidence remains independently BLOCKED")
    elif number not in SCOPED_SANDBOX:
        errors.append("PR is outside the pinned non-dispatch Sandbox review scope")
    if pr.get("state") != "open" or pr.get("merged") is not False:
        errors.append("PR is not verified open and unmerged")
    if pr.get("draft") is not False:
        errors.append("draft PR is not promotion-ready")
    if source_head != expected_head or not isinstance(source_head, str) or not SHA.fullmatch(source_head):
        errors.append("source HEAD differs from expected exact review commit")
    if base.get("ref") != "main" or branch.get("name") != "main":
        errors.append("PR must target main, never a stacked feature parent")
    if not isinstance(main_sha, str) or not SHA.fullmatch(main_sha) or base.get("sha") != main_sha:
        errors.append("PR base SHA does not equal current main")
    if expected_main is not None and main_sha != expected_main:
        errors.append("current main advanced from the reviewed target SHA")
    if branch.get("protected") is not True:
        errors.append("main is not verified protected")

    # Absence/403 of the server-side protection source is a hard failure.
    required = protection.get("required_pull_request_reviews") or {}
    statuses = protection.get("required_status_checks") or {}
    resolution = protection.get("required_conversation_resolution") or {}
    if not required or not statuses:
        errors.append("missing authoritative main protection API / review and status requirements")
    if required.get("required_approving_review_count", 0) < 2:
        errors.append("main protection requires fewer than two human approvals")
    if required.get("dismiss_stale_reviews") is not True:
        errors.append("main protection does not dismiss stale reviews")
    if required.get("require_last_push_approval") is not True:
        errors.append("main protection does not require last push approval")
    if (protection.get("enforce_admins") or {}).get("enabled") is not True:
        errors.append("main protection allows administrator bypass")
    if resolution.get("enabled") is not True:
        errors.append("main protection does not require conversation resolution")
    if statuses.get("strict") is not True:
        errors.append("main protected checks are not strict on current base")

    contexts = [c.get("context") for c in statuses.get("checks", [])
                if isinstance(c, dict) and c.get("context")]
    if not contexts:
        contexts = [c for c in statuses.get("contexts", []) if isinstance(c, str) and c]
    if not contexts or len(set(contexts)) != len(contexts):
        errors.append("no unambiguous required job check contexts are configured")

    # Reviews are chronologically returned by GitHub's paginated API. For
    # any reviewer, only the most recent decisive review applies. Approvals
    # on a different commit, by the author, a Bot or without a verified
    # collaborator permission cannot count as independent human sign-off.
    latest = {}
    if not isinstance(reviews, list):
        errors.append("missing complete independent review history")
        reviews = []
    for r in reviews:
        if not isinstance(r, dict):
            continue
        user = r.get("user") or {}
        login = user.get("login")
        if isinstance(login, str) and login:
            latest[login.lower()] = r
    author = ((pr.get("user") or {}).get("login") or "").lower()
    permissions = state.get("reviewer_permissions") or {}
    approved = 0
    for login, record in latest.items():
        user = record.get("user") or {}
        if record.get("state") == "CHANGES_REQUESTED":
            errors.append("unresolved review requests changes from " + login)
        if (login != author and login and user.get("type") != "Bot" and
                not login.endswith("[bot]") and record.get("state") == "APPROVED" and
                record.get("commit_id") == source_head and
                permissions.get(login) in ("write", "maintain", "admin")):
            approved += 1
    if approved < 2:
        errors.append("fewer than two current-HEAD independent eligible human approvals")

    by_name = {}
    if not isinstance(checks, list):
        errors.append("missing complete exact-HEAD check runs")
        checks = []
    for c in checks:
        if not isinstance(c, dict) or not isinstance(c.get("name"), str):
            continue
        name = c["name"]
        old = by_name.get(name)
        if old is None or int(c.get("id") or 0) >= int(old.get("id") or 0):
            by_name[name] = c
    for context in contexts:
        check = by_name.get(context)
        if (check is None or check.get("head_sha") != source_head or
                check.get("status") != "completed" or check.get("conclusion") != "success"):
            errors.append("missing, stale, skipped or failing required check: " + context)
    return errors


def _get_json(repo, path, token):
    url = "https://api.github.com/repos/" + repo + path
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "Authorization": "Bearer " + token,
        "User-Agent": "acp-p0-readonly-merge-preflight",
    })
    with urllib.request.urlopen(request, timeout=15) as resp:
        return json.load(resp)


def _all_pages(repo, path, token, key=None):
    found = []
    for page in range(1, 21):
        sep = "&" if "?" in path else "?"
        data = _get_json(repo, f"{path}{sep}per_page=100&page={page}", token)
        chunk = data.get(key) if key else data
        if not isinstance(chunk, list):
            raise ValueError("unexpected paginated GitHub response")
        found.extend(chunk)
        if len(chunk) < 100:
            return found
    raise ValueError("GitHub pagination exceeded bound; no partial approval")


def collect_live(repo, number, token):
    """Fetch independent REST authorities; no user-supplied JSON fallback."""
    pr = _get_json(repo, f"/pulls/{number}", token)
    branch = _get_json(repo, "/branches/main", token)
    protection = _get_json(repo, "/branches/main/protection", token)
    reviews = _all_pages(repo, f"/pulls/{number}/reviews", token)
    checks = _all_pages(repo, f"/commits/{pr['head']['sha']}/check-runs", token, key="check_runs")
    permissions = {}
    for review in reviews:
        login = (review.get("user") or {}).get("login", "")
        if login and login.lower() != ((pr.get("user") or {}).get("login") or "").lower():
            perms = _get_json(repo, f"/collaborators/{login}/permission", token)
            permissions[login.lower()] = perms.get("permission")
    return {
        "pr": pr, "branch": branch, "protection": protection,
        "reviews": reviews, "checks": checks, "reviewer_permissions": permissions,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only strict P0 merge preflight; no merge API")
    parser.add_argument("--repository", required=True, help="owner/repository")
    parser.add_argument("--pr", required=True, type=int)
    parser.add_argument("--expected-head", required=True, help="full reviewed feature SHA")
    parser.add_argument("--expected-main", required=True, help="full reviewed main SHA")
    args = parser.parse_args(argv)
    if (not REPO.fullmatch(args.repository) or args.pr < 1 or
            not SHA.fullmatch(args.expected_head) or not SHA.fullmatch(args.expected_main)):
        print("P0_MERGE_READINESS=BLOCKED: invalid pinned live request", file=sys.stderr)
        return 2
    token = os.environ.get("ACP_GOVERNANCE_READ_TOKEN")
    if not token:
        print("P0_MERGE_READINESS=BLOCKED: no separately authorized read-only governance token", file=sys.stderr)
        return 2
    try:
        state = collect_live(args.repository, args.pr, token)
        reasons = evaluate(state, expected_head=args.expected_head, expected_main=args.expected_main)
    except (OSError, ValueError, KeyError, TypeError, urllib.error.HTTPError) as err:
        # 401/403/404/rate limit or malformed API is never an empty review
        # list and never a PASS. Never print response bodies or bearer tokens.
        print("P0_MERGE_READINESS=BLOCKED: live GitHub governance authority inaccessible or incomplete", file=sys.stderr)
        return 2
    if reasons:
        for reason in reasons:
            print("BLOCKED: " + reason, file=sys.stderr)
        print("P0_MERGE_READINESS=BLOCKED", file=sys.stderr)
        return 1
    print("P0_MERGE_PREFLIGHT=ELIGIBLE_AT_PINNED_SHA_ONLY; NO_MERGE_OR_PRODUCTION_AUTHORIZATION")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
