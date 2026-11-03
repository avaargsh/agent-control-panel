#!/usr/bin/env python3
"""Audit an observed GitHub PR dependency snapshot; optional live drift check.

Default checks the stored observation and its declared gates. With --live,
fetches open PR heads through GitHub REST API (read-only), requiring a token
for private repositories. It neither approves PRs nor changes any branch.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r"^[a-f0-9]{40}$")
EXPECTED_REPOS = frozenset({
    "avaargsh/agent-control-panel",
    "avaargsh/agent-runtime",
    "avaargsh/agent-decision",
    "avaargsh/EngageGuard",
    "avaargsh/compute-control-panel",
})


def validate_snapshot(snapshot: dict, registry: dict) -> bool:
    if (snapshot.get("schema_version") != "pr-topology/v0.3" or
            snapshot.get("state") != "observed-not-approved" or
            snapshot.get("root_issue") != registry.get("root_issue") or
            not re.fullmatch(r"20\d{2}-\d{2}-\d{2}", snapshot.get("observed_date", ""))):
        raise ValueError("PR topology must be a dated, non-approving observation")
    known_gates = {g["id"] for g in registry["merge_gates"]}
    repos = snapshot.get("repositories")
    if not isinstance(repos, list):
        raise ValueError("invalid repositories array")
    seen_repo = set()
    all_prs = {}
    for entry in repos:
        repo = entry["repo"]
        if repo in seen_repo:
            raise ValueError("duplicate repository")
        seen_repo.add(repo)
        if not isinstance(entry.get("pull_requests"), list):
            raise ValueError("PR entries must be a list")
        seen_pr, branches = set(), {}
        for pr in entry["pull_requests"]:
            number = pr["number"]
            if not isinstance(number, int) or isinstance(number, bool) or number <= 0 or number in seen_pr:
                raise ValueError("duplicate PR or invalid PR number")
            seen_pr.add(number)
            if not SHA.fullmatch(pr["head_sha"]):
                raise ValueError("invalid PR head SHA")
            if not pr.get("head_branch") or not pr.get("base_branch"):
                raise ValueError("missing PR branch lineage")
            if pr["head_branch"] in branches:
                raise ValueError("two PRs share a head branch without explicit resolution")
            branches[pr["head_branch"]] = number
            if not isinstance(pr.get("draft"), bool) or pr.get("disposition") != "blocked":
                raise ValueError("snapshot cannot approve an open implementation PR")
            gates = pr.get("gate_ids")
            if (not isinstance(gates, list) or not gates or
                    len(gates) != len(set(gates)) or
                    any(gate not in known_gates for gate in gates)):
                raise ValueError("unknown governance gate or missing gate mapping")
            if pr.get("head_tracking") is not None and (
                    repo != "avaargsh/agent-control-panel" or number != 4 or
                    pr["head_tracking"] != "exists-only"):
                raise ValueError("only the self-editing governance PR may ignore its own head SHA")
        by_number = {p["number"]: p for p in entry["pull_requests"]}
        for pr in entry["pull_requests"]:
            parent_branch = pr["base_branch"]
            parent_number = branches.get(parent_branch) if parent_branch != "main" else None
            lineage = pr.get("lineage_state")
            explicit = pr.get("legacy_parent")
            if lineage not in (None, "retired-parent-blocked"):
                raise ValueError("unrecognized PR lineage state")
            if parent_branch == "main":
                if lineage is not None or explicit is not None:
                    raise ValueError("main-based PR cannot claim retired parent")
                continue
            if parent_number is None or parent_number == pr["number"]:
                # No live parent: only an explicitly identified, unmerged,
                # closed PR can explain this legacy branch. It stays BLOCKED.
                if (lineage != "retired-parent-blocked" or
                        not isinstance(explicit, dict) or
                        type(explicit.get("pr_number")) is not int or
                        explicit["pr_number"] <= 0 or
                        explicit["pr_number"] in by_number or
                        explicit.get("head_branch") != parent_branch or
                        not isinstance(explicit.get("head_sha"), str) or
                        not SHA.fullmatch(explicit["head_sha"]) or
                        explicit.get("state") != "closed" or
                        explicit.get("merged") is not False):
                    raise ValueError("missing active parent PR for stacked branch")
            else:
                if explicit is not None:
                    raise ValueError("active parent cannot also be a legacy parent")
                parent = by_number[parent_number]
                inherited_retired = parent.get("lineage_state") == "retired-parent-blocked"
                if inherited_retired != (lineage == "retired-parent-blocked"):
                    raise ValueError("retired parent lineage must propagate to children")
        all_prs[repo] = by_number
    if seen_repo != EXPECTED_REPOS:
        raise ValueError("missing or unexpected core repository")
    groups = snapshot.get("parallel_conflicts", [])
    seen_groups = set()
    for group in groups:
        repo = group["repo"]
        pair = group["pull_requests"]
        group_key = (repo, tuple(sorted(pair)))
        if group_key in seen_groups:
            raise ValueError("duplicate parallel PR conflict")
        seen_groups.add(group_key)
        if (len(pair) < 2 or len(pair) != len(set(pair)) or
                any(pr not in all_prs.get(repo, {}) for pr in pair)):
            raise ValueError("invalid parallel conflict PR references")
        if group["candidate_pr"] not in pair:
            raise ValueError("invalid parallel conflict candidate")
        if group.get("issue") not in {g["issue"] for g in registry["merge_gates"]}:
            raise ValueError("parallel conflict missing governance gate issue")
        if not group.get("reason"):
            raise ValueError("parallel conflict requires rationale")
    if 4 in all_prs["avaargsh/EngageGuard"] and 5 in all_prs["avaargsh/EngageGuard"]:
        if ("avaargsh/EngageGuard", (4, 5)) not in seen_groups:
            raise ValueError("unresolved parallel EngageGuard PRs 4 and 5")
    return True


def snapshot_heads(snapshot: dict) -> dict[str, dict[int, str | None]]:
    return {
        group["repo"]: {
            p["number"]: None if p.get("head_tracking") == "exists-only" else p["head_sha"]
            for p in group["pull_requests"]
        }
        for group in snapshot["repositories"]
    }


def compare_live(expected: dict, actual: dict) -> bool:
    for repo in sorted(set(expected) | set(actual)):
        old = expected.get(repo, {})
        new = actual.get(repo, {})
        if set(old) != set(new):
            raise ValueError(
                f"PR drift: {repo} open PR identities changed "
                f"(added={sorted(set(new) - set(old))}, closed={sorted(set(old) - set(new))})"
            )
        for number, sha in old.items():
            if sha is not None and new[number] != sha:
                raise ValueError(
                    f"PR drift: {repo} #{number} expected {sha}, observed {new[number]}"
                )
    return True


def fetch_live_pr_heads(repos: set[str], token: str | None = None) -> dict:
    """Read all open PR heads; API errors are fatal, not treated as empty lists."""
    result = {}
    for repo in sorted(repos):
        heads = {}
        for page in range(1, 11):
            request = Request(
                f"https://api.github.com/repos/{repo}/pulls?state=open&per_page=100&page={page}",
                headers={
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "open-agent-governance-audit/0.3",
                    **({"Authorization": f"Bearer {token}"} if token else {}),
                },
            )
            try:
                with urlopen(request, timeout=15) as response:
                    entries = json.load(response)
            except (HTTPError, URLError, TimeoutError, ValueError) as exc:
                raise RuntimeError(f"cannot verify {repo} live PRs: {exc}") from exc
            if not isinstance(entries, list):
                raise RuntimeError(f"unexpected GitHub response for {repo}")
            for item in entries:
                heads[item["number"]] = item["head"]["sha"]
            if len(entries) < 100:
                break
        else:
            raise RuntimeError(f"PR pagination limit reached for {repo}")
        result[repo] = heads
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--live", action="store_true", help="compare open PRs against GitHub REST")
    args = parser.parse_args()
    snapshot = json.loads((ROOT / "governance" / "pr-topology.v0.3.json").read_text())
    registry = json.loads((ROOT / "governance" / "contract-registry.v0.3.json").read_text())
    validate_snapshot(snapshot, registry)
    print("Observed PR topology and blocked gate mapping are internally consistent")
    if args.live:
        expected = snapshot_heads(snapshot)
        live = fetch_live_pr_heads(set(expected), os.getenv("GH_GOVERNANCE_READ_TOKEN"))
        compare_live(expected, live)
        print("All observed open PR identities and pinned heads match live GitHub")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(1)
