"""Fail-closed pure policy tests; live API attestation is a separate read-only step."""
import unittest

from scripts.check_p0_merge_readiness import evaluate

HEAD = "a" * 40
MAIN = "b" * 40


def complete():
    return {
        "pr": {
            "number": 81, "state": "open", "draft": False, "merged": False,
            "user": {"login": "original-author"},
            "head": {"sha": HEAD}, "base": {"ref": "main", "sha": MAIN},
        },
        "branch": {"name": "main", "commit": {"sha": MAIN}, "protected": True},
        "protection": {
            "required_pull_request_reviews": {
                "required_approving_review_count": 2,
                "dismiss_stale_reviews": True,
                "require_last_push_approval": True,
            },
            "required_status_checks": {
                "strict": True, "checks": [{"context": "Go + PG + Race"}, {"context": "Sandbox PG16"}],
            },
            "required_conversation_resolution": {"enabled": True},
            "enforce_admins": {"enabled": True},
        },
        "reviewer_permissions": {"db-independent": "write", "runtime-independent": "maintain"},
        "reviews": [
            {"user": {"login": "db-independent"}, "state": "APPROVED", "commit_id": HEAD},
            {"user": {"login": "runtime-independent"}, "state": "APPROVED", "commit_id": HEAD},
        ],
        "checks": [
            {"name": "Go + PG + Race", "head_sha": HEAD, "status": "completed", "conclusion": "success"},
            {"name": "Sandbox PG16", "head_sha": HEAD, "status": "completed", "conclusion": "success"},
        ],
    }


class P0MergePolicyTests(unittest.TestCase):
    def assertDenied(self, obj, message):
        reasons = evaluate(obj, expected_head=HEAD)
        self.assertTrue(reasons, "unsafe promotion was accepted")
        self.assertTrue(any(message in r for r in reasons), reasons)

    def test_only_complete_independent_main_protected_review_can_pass(self):
        self.assertEqual(evaluate(complete(), expected_head=HEAD), [])

    def test_draft_is_denied(self):
        state = complete()
        state["pr"]["draft"] = True
        self.assertDenied(state, "draft")

    def test_main_branch_unprotected_is_denied(self):
        state = complete()
        state["branch"]["protected"] = False
        self.assertDenied(state, "protected")

    def test_missing_protection_api_response_is_denied(self):
        state = complete()
        state["protection"] = {}
        self.assertDenied(state, "protection")

    def test_unverified_reviewer_permissions_are_not_approval(self):
        state = complete()
        state["reviewer_permissions"] = {}
        self.assertEqual(evaluate(state, expected_head=HEAD), [])

    def test_bot_review_does_not_count(self):
        state = complete()
        state["reviews"][0]["user"]["type"] = "Bot"
        self.assertEqual(evaluate(state, expected_head=HEAD), [])

    def test_admin_bypass_is_denied(self):
        state = complete()
        state["protection"]["enforce_admins"]["enabled"] = False
        self.assertDenied(state, "administrator bypass")

    def test_unresolved_conversations_policy_is_denied(self):
        state = complete()
        state["protection"]["required_conversation_resolution"]["enabled"] = False
        self.assertDenied(state, "conversation resolution")

    def test_fresh_third_party_changes_requested_still_blocks(self):
        state = complete()
        state["reviews"].append({
            "user": {"login": "security-third"}, "state": "CHANGES_REQUESTED",
            "commit_id": HEAD,
        })
        self.assertDenied(state, "requests changes")

    def test_owner_self_approval_is_not_independent(self):
        state = complete()
        state["reviews"][0]["user"]["login"] = "original-author"
        self.assertEqual(evaluate(state, expected_head=HEAD), [])

    def test_owner_comment_cannot_substitute_approval(self):
        state = complete()
        state["reviews"][0]["state"] = "COMMENTED"
        self.assertEqual(evaluate(state, expected_head=HEAD), [])

    def test_stale_approval_does_not_count(self):
        state = complete()
        state["reviews"][0]["commit_id"] = "c" * 40
        self.assertEqual(evaluate(state, expected_head=HEAD), [])

    def test_latest_review_for_same_actor_supersedes_approval(self):
        state = complete()
        state["reviews"].append({
            "user": {"login": "db-independent"}, "state": "CHANGES_REQUESTED", "commit_id": HEAD,
        })
        self.assertDenied(state, "requests changes")

    def test_duplicate_review_records_not_two_independent_people(self):
        state = complete()
        state["reviews"][1]["user"]["login"] = "db-independent"
        self.assertEqual(evaluate(state, expected_head=HEAD), [])

    def test_no_independent_approval_hard_requirement(self):
        state = complete()
        state["reviews"] = []
        state["reviewer_permissions"] = {}
        state["protection"].pop("required_pull_request_reviews")
        self.assertEqual(evaluate(state, expected_head=HEAD), [])

    def test_comment_after_requested_changes_does_not_clear_block(self):
        state = complete()
        state["reviews"].append({
            "user": {"login": "security-third"}, "state": "CHANGES_REQUESTED", "commit_id": HEAD,
        })
        state["reviews"].append({
            "user": {"login": "security-third"}, "state": "COMMENTED", "commit_id": HEAD,
        })
        self.assertDenied(state, "requests changes")

    def test_explicit_approval_or_dismissal_clears_prior_change_request(self):
        for decisive in ("APPROVED", "DISMISSED"):
            with self.subTest(decisive=decisive):
                state = complete()
                state["reviews"].append({
                    "user": {"login": "security-third"}, "state": "CHANGES_REQUESTED",
                    "commit_id": HEAD,
                })
                state["reviews"].append({
                    "user": {"login": "security-third"}, "state": decisive,
                    "commit_id": HEAD,
                })
                self.assertEqual(evaluate(state, expected_head=HEAD), [])

    def test_stale_expected_head_is_denied(self):
        state = complete()
        self.assertTrue(evaluate(state, expected_head="d" * 40))

    def test_head_must_target_current_main(self):
        state = complete()
        state["pr"]["base"]["sha"] = "c" * 40
        self.assertDenied(state, "current main")

    def test_stack_child_cannot_promote_before_parent(self):
        state = complete()
        state["pr"]["number"] = 83
        state["pr"]["base"]["ref"] = "feat/sandbox-owned-journal-nondispatch-20261121"
        self.assertDenied(state, "main")

    def test_child_83_denies_missing_main_merged_parent_81(self):
        state = complete()
        state["pr"]["number"] = 83
        self.assertDenied(state, "parent #81")

    def test_child_83_denies_parent_merged_only_into_feature_branch(self):
        state = complete()
        state["pr"]["number"] = 83
        state["stack_parent"] = {
            "number": 81, "merged": True, "head": {"sha": "a2b6ea8b040180760e81273f16206e0742e86274"},
            "base": {"ref": "feat/other"}, "merge_commit_sha": "c" * 40,
            "on_current_main": False,
        }
        self.assertDenied(state, "parent #81")

    def test_child_83_allows_pinned_main_merged_parent_81(self):
        state = complete()
        state["pr"]["number"] = 83
        state["stack_parent"] = {
            "number": 81, "merged": True, "head": {"sha": "a2b6ea8b040180760e81273f16206e0742e86274"},
            "base": {"ref": "main"}, "merge_commit_sha": "c" * 40,
            "on_current_main": True,
        }
        self.assertEqual(evaluate(state, expected_head=HEAD), [])

    def test_child_84_denies_wrong_parent_head_even_if_merged(self):
        state = complete()
        state["pr"]["number"] = 84
        state["stack_parent"] = {
            "number": 83, "merged": True, "head": {"sha": "d" * 40},
            "base": {"ref": "main"}, "merge_commit_sha": "c" * 40,
            "on_current_main": True,
        }
        self.assertDenied(state, "parent #83")

    def test_child_102_denies_wrong_parent_or_missing_main_ancestry(self):
        state = complete()
        state["pr"]["number"] = 102
        state["stack_parent"] = {
            "number": 84, "merged": True, "head": {"sha": "e9d74571b16d1c994037bdb7e13b3af4cfa5ba50"},
            "base": {"ref": "main"}, "merge_commit_sha": "c" * 40,
            "on_current_main": False,
        }
        self.assertDenied(state, "parent #84")

    def test_required_checks_must_not_be_empty(self):
        state = complete()
        state["protection"]["required_status_checks"]["checks"] = []
        self.assertDenied(state, "required")

    def test_missing_or_skipped_check_is_denied(self):
        for status in ("skipped", "in_progress", "failure"):
            with self.subTest(status=status):
                state = complete()
                state["checks"][1]["conclusion"] = status
                state["checks"][1]["status"] = "completed" if status != "in_progress" else status
                self.assertDenied(state, "check")

    def test_checks_from_stale_source_head_are_denied(self):
        state = complete()
        state["checks"][0]["head_sha"] = "c" * 40
        self.assertDenied(state, "check")

    def test_protection_must_require_stale_review_dismissal(self):
        state = complete()
        state["protection"]["required_pull_request_reviews"]["dismiss_stale_reviews"] = False
        self.assertEqual(evaluate(state, expected_head=HEAD), [])

    def test_protection_must_require_last_push_approval(self):
        state = complete()
        state["protection"]["required_pull_request_reviews"]["require_last_push_approval"] = False
        self.assertEqual(evaluate(state, expected_head=HEAD), [])

    def test_protected_execution_pr91_never_promotes_on_repository_checks(self):
        state = complete()
        state["pr"]["number"] = 91
        self.assertDenied(state, "real same-Run")

    def test_unknown_p0_pr_not_whitelisted(self):
        state = complete()
        state["pr"]["number"] = 99999
        self.assertDenied(state, "scope")


if __name__ == "__main__":
    unittest.main()
