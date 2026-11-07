"""Fail-closed regression tests for retired-parent, still-open PR branches."""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from audit_pr_topology import validate_snapshot

REGISTRY = json.loads((ROOT / "governance" / "contract-registry.v0.3.json").read_text())
SNAPSHOT = json.loads((ROOT / "governance" / "pr-topology.v0.3.json").read_text())

def guard(snapshot):
    return next(group for group in snapshot["repositories"] if group["repo"] == "avaargsh/EngageGuard")

class ClosedParentTests(unittest.TestCase):
    def test_old_guard_branch_requires_explicit_retired_parent(self):
        changed = copy.deepcopy(SNAPSHOT)
        g = guard(changed)
        legacy = next(p for p in g["pull_requests"] if p["number"] == 9)
        legacy["lineage_state"] = "retired-parent-blocked"
        self.assertIs(legacy["legacy_parent"]["merged"], False)
        self.assertTrue(validate_snapshot(changed, REGISTRY))

    def test_unqualified_missing_parent_rejected(self):
        changed = copy.deepcopy(SNAPSHOT)
        g = guard(changed)
        g["pull_requests"] = [p for p in g["pull_requests"] if p["number"] != 8]
        next(p for p in g["pull_requests"] if p["number"] == 9).pop("legacy_parent")
        with self.assertRaisesRegex(ValueError, "missing active parent"):
            validate_snapshot(changed, REGISTRY)

    def test_retired_parent_cannot_claim_merged_or_approved(self):
        changed = copy.deepcopy(SNAPSHOT)
        g = guard(changed)
        g["pull_requests"] = [p for p in g["pull_requests"] if p["number"] != 8]
        legacy = next(p for p in g["pull_requests"] if p["number"] == 9)
        legacy["lineage_state"] = "retired-parent-blocked"
        legacy["legacy_parent"]["merged"] = True
        with self.assertRaises(ValueError):
            validate_snapshot(changed, REGISTRY)

if __name__ == "__main__":
    unittest.main()
