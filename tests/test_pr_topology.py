"""Independent cross-repository PR topology governance regression tests."""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from audit_pr_topology import validate_snapshot, compare_live

REGISTRY = json.loads((ROOT / "governance" / "contract-registry.v0.3.json").read_text())
SNAPSHOT = json.loads((ROOT / "governance" / "pr-topology.v0.3.json").read_text())


class PRTopologyTests(unittest.TestCase):
    def test_observed_snapshot_is_not_merge_approval(self):
        self.assertTrue(validate_snapshot(SNAPSHOT, REGISTRY))

    def test_open_pr_snapshot_covers_all_six_active_repositories(self):
        groups = {r["repo"]: r["pull_requests"] for r in SNAPSHOT["repositories"]}
        self.assertEqual(set(groups), {
            "avaargsh/agent-infra", "avaargsh/agent-control-panel",
            "avaargsh/compute-control-panel", "avaargsh/agent-runtime",
            "avaargsh/agent-decision", "avaargsh/EngageGuard",
        })
        self.assertEqual(sum(len(prs) for prs in groups.values()), 40)
        rust_numbers = {p["number"] for p in groups["avaargsh/agent-infra"]}
        self.assertEqual(rust_numbers, {15, 16})
        runtime_numbers = {p["number"] for p in groups["avaargsh/agent-runtime"]}
        self.assertEqual(runtime_numbers, {1, 2, 3, 8, 9, 11, 12, 14, 16, 18, 19, 21})
        compute_numbers = {p["number"] for p in groups["avaargsh/compute-control-panel"]}
        self.assertNotIn(11, compute_numbers)
        self.assertNotIn(28, compute_numbers)
        self.assertEqual(SNAPSHOT["observed_date"], "2026-11-04")

    def test_snapshot_records_full_base_and_head_commits(self):
        for group in SNAPSHOT["repositories"]:
            for pr in group["pull_requests"]:
                with self.subTest(repo=group["repo"], number=pr["number"]):
                    self.assertEqual(len(pr["head_sha"]), 40)
                    self.assertEqual(len(pr["base_sha"]), 40)

    def test_untracked_gate_rejected(self):
        changed = copy.deepcopy(SNAPSHOT)
        changed["repositories"][0]["pull_requests"][0]["gate_ids"] = ["G99"]
        with self.assertRaisesRegex(ValueError, "unknown governance gate"):
            validate_snapshot(changed, REGISTRY)

    def test_open_pr_cannot_be_mislabeled_approved(self):
        changed = copy.deepcopy(SNAPSHOT)
        changed["repositories"][0]["pull_requests"][0]["disposition"] = "approved"
        with self.assertRaisesRegex(ValueError, "cannot approve"):
            validate_snapshot(changed, REGISTRY)

    def test_cross_repo_duplicate_pr_identity_rejected(self):
        changed = copy.deepcopy(SNAPSHOT)
        changed["repositories"][0]["pull_requests"].append(
            copy.deepcopy(changed["repositories"][0]["pull_requests"][0])
        )
        with self.assertRaisesRegex(ValueError, "duplicate PR"):
            validate_snapshot(changed, REGISTRY)

    def test_stacked_parent_must_be_active(self):
        changed = copy.deepcopy(SNAPSHOT)
        runtime = next(r for r in changed["repositories"] if r["repo"] == "avaargsh/agent-runtime")
        parent = next(p for p in runtime["pull_requests"] if p["number"] == 2)
        parent["head_branch"] = "renamed-branch"
        with self.assertRaisesRegex(ValueError, "missing active parent"):
            validate_snapshot(changed, REGISTRY)

    def test_closed_guard_competing_pr_is_removed_from_open_snapshot(self):
        guard = next(r for r in SNAPSHOT["repositories"] if r["repo"] == "avaargsh/EngageGuard")
        self.assertNotIn(4, {p["number"] for p in guard["pull_requests"]})
        conflicts = {tuple(sorted(group["pull_requests"])) for group in SNAPSHOT["parallel_conflicts"]}
        self.assertEqual(conflicts, {(9, 17), (12, 18)})
        self.assertTrue(validate_snapshot(SNAPSHOT, REGISTRY))

    def test_non_draft_open_pr_remains_blocked_until_gate_passes(self):
        changed = copy.deepcopy(SNAPSHOT)
        compute = next(r for r in changed["repositories"] if r["repo"] == "avaargsh/compute-control-panel")
        ready = compute["pull_requests"][0]  # any currently open PR may lose Draft without passing G04
        ready["draft"] = False
        self.assertIs(ready["draft"], False)
        self.assertEqual(ready["disposition"], "blocked")
        self.assertTrue(validate_snapshot(changed, REGISTRY))

    def test_base_sha_must_be_full_commit(self):
        changed = copy.deepcopy(SNAPSHOT)
        changed["repositories"][0]["pull_requests"][0]["base_sha"] = "main"
        with self.assertRaisesRegex(ValueError, "invalid PR base"):
            validate_snapshot(changed, REGISTRY)

    def test_head_sha_must_be_full_commit(self):
        changed = copy.deepcopy(SNAPSHOT)
        changed["repositories"][0]["pull_requests"][0]["head_sha"] = "main"
        with self.assertRaisesRegex(ValueError, "invalid PR head"):
            validate_snapshot(changed, REGISTRY)

    def test_live_pr_drift_is_detected_without_auto_refresh(self):
        expected = {"avaargsh/agent-decision": {8: "a" * 40}}
        actual = {"avaargsh/agent-decision": {8: "b" * 40}}
        with self.assertRaisesRegex(ValueError, "PR drift"):
            compare_live(expected, actual)

    def test_live_closed_or_new_pr_is_drift(self):
        expected = {"avaargsh/EngageGuard": {4: "a" * 40}}
        with self.assertRaisesRegex(ValueError, "PR drift"):
            compare_live(expected, {"avaargsh/EngageGuard": {}})
        with self.assertRaisesRegex(ValueError, "PR drift"):
            compare_live(expected, {"avaargsh/EngageGuard": {4: "a" * 40, 5: "b" * 40}})


if __name__ == "__main__":
    unittest.main()
