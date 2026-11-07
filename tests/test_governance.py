"""Tests for governance manifest validator; guards accidental false approvals."""
import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from check_governance import unique_object, validate_registry

REGISTRY = json.loads(
    (ROOT / "governance" / "contract-registry.v0.3.json").read_text(encoding="utf-8")
)


class GovernanceTests(unittest.TestCase):
    def test_candidate_manifest_is_consistent(self):
        self.assertTrue(validate_registry(REGISTRY))

    def test_duplicate_id_has_no_second_owner(self):
        broken = copy.deepcopy(REGISTRY)
        broken["domain_ownership"][1]["identifiers"].append("run_intent_id")
        with self.assertRaisesRegex(ValueError, "multiple canonical writers"):
            validate_registry(broken)

    def test_request_id_creator_is_not_record_authority(self):
        self.assertTrue(validate_registry(REGISTRY))
        identities = {x["id"]: x for x in REGISTRY["issued_request_ids"]}
        self.assertEqual(identities["invocation_id"]["created_by"], "avaargsh/agent-runtime")
        self.assertEqual(identities["invocation_id"]["durable_index_owner"], "avaargsh/agent-decision")
        self.assertEqual(identities["guard_submission_key"]["durable_index_owner"], "avaargsh/EngageGuard")

    def test_request_id_cannot_be_double_owned(self):
        broken = copy.deepcopy(REGISTRY)
        broken["domain_ownership"][1]["identifiers"].append("invocation_id")
        with self.assertRaisesRegex(ValueError, "request ID duplicated"):
            validate_registry(broken)

    def test_request_id_requires_durable_index_owner(self):
        broken = copy.deepcopy(REGISTRY)
        broken["issued_request_ids"][0]["durable_index_owner"] = "unknown/owner"
        with self.assertRaisesRegex(ValueError, "durable index owner"):
            validate_registry(broken)

    def test_contract_cannot_be_silently_accepted(self):
        broken = copy.deepcopy(REGISTRY)
        broken["contracts"][0]["state"] = "accepted"
        with self.assertRaisesRegex(ValueError, "cannot declare accepted"):
            validate_registry(broken)

    def test_gate_cannot_be_self_approved(self):
        broken = copy.deepcopy(REGISTRY)
        broken["merge_gates"][0]["state"] = "passed"
        with self.assertRaisesRegex(ValueError, "cannot silently pass"):
            validate_registry(broken)

    def test_source_must_pin_commit(self):
        broken = copy.deepcopy(REGISTRY)
        broken["contracts"][0]["commit"] = "main"
        with self.assertRaisesRegex(ValueError, "immutable commit"):
            validate_registry(broken)

    def test_duplicate_protocol_names_rejected(self):
        broken = copy.deepcopy(REGISTRY)
        broken["contracts"].append(copy.deepcopy(broken["contracts"][0]))
        with self.assertRaisesRegex(ValueError, "duplicate contract id"):
            validate_registry(broken)

    def test_untrusted_owner_rejected(self):
        broken = copy.deepcopy(REGISTRY)
        broken["merge_gates"][0]["owners"] = ["unknown/owner"]
        with self.assertRaisesRegex(ValueError, "unknown authoritative owner"):
            validate_registry(broken)

    def test_duplicate_json_key_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate registry JSON key"):
            json.loads('{"version":"a","version":"b"}', object_pairs_hook=unique_object)

    def test_required_authoritative_domain_cannot_be_removed(self):
        broken = copy.deepcopy(REGISTRY)
        broken["domain_ownership"] = [
            domain for domain in broken["domain_ownership"] if domain["id"] != "run-execution"
        ]
        with self.assertRaisesRegex(ValueError, "missing required authoritative domain"):
            validate_registry(broken)

    def test_required_service_contract_cannot_be_removed(self):
        broken = copy.deepcopy(REGISTRY)
        broken["contracts"] = [
            contract for contract in broken["contracts"] if contract["id"] != "decision-core-http"
        ]
        with self.assertRaisesRegex(ValueError, "missing required service contract"):
            validate_registry(broken)

    def test_required_merge_gate_cannot_be_removed(self):
        broken = copy.deepcopy(REGISTRY)
        broken["merge_gates"] = [
            gate for gate in broken["merge_gates"] if gate["id"] != "G02"
        ]
        with self.assertRaisesRegex(ValueError, "missing required merge gate"):
            validate_registry(broken)

    def test_merge_gate_cannot_be_reassigned_to_another_valid_owner(self):
        broken = copy.deepcopy(REGISTRY)
        broken["merge_gates"][0]["owners"] = [
            "avaargsh/agent-control-panel",
            "avaargsh/EngageGuard",
        ]
        with self.assertRaisesRegex(ValueError, "merge gate authoritative owners mismatch"):
            validate_registry(broken)

    def test_request_id_cannot_be_reassigned_to_another_valid_owner(self):
        broken = copy.deepcopy(REGISTRY)
        broken["issued_request_ids"][0]["durable_index_owner"] = "avaargsh/agent-control-panel"
        with self.assertRaisesRegex(ValueError, "request ID ownership mismatch"):
            validate_registry(broken)


    def test_decision_core_cannot_reuse_legacy_plugin_version(self):
        broken = copy.deepcopy(REGISTRY)
        core = next(c for c in broken["contracts"] if c["id"] == "decision-core-http")
        core["version"] = "plugin.v0.1-legacy"
        with self.assertRaisesRegex(ValueError, "service contract version mismatch"):
            validate_registry(broken)

    def test_guard_submission_key_cannot_be_redefined_as_operation_id(self):
        broken = copy.deepcopy(REGISTRY)
        key = next(x for x in broken["issued_request_ids"] if x["id"] == "guard_submission_key")
        key["meaning"] = "Runtime creates operation_id, Guard accepts caller ID"
        with self.assertRaisesRegex(ValueError, "request ID semantics mismatch"):
            validate_registry(broken)

    def test_invocation_id_must_remain_stable_across_retries(self):
        broken = copy.deepcopy(REGISTRY)
        invocation = next(x for x in broken["issued_request_ids"] if x["id"] == "invocation_id")
        invocation["meaning"] = "new invocation ID for every Activity retry"
        with self.assertRaisesRegex(ValueError, "request ID semantics mismatch"):
            validate_registry(broken)

    def test_guard_wire_submission_is_distinct_from_internal_action_request(self):
        contracts = {x["id"]: x for x in REGISTRY["contracts"]}
        submission = contracts["guard-action-submission"]
        internal = contracts["guard-internal-action-request"]
        self.assertEqual(submission["path"], "docs/contracts/action-submission.v1.schema.json")
        self.assertEqual(submission["version"], "action-submission.v1-draft")
        self.assertEqual(internal["path"], "docs/contracts/action-request.v1.schema.json")
        self.assertEqual(internal["version"], "guard-internal.v1-draft")
        self.assertEqual(submission["state"], "blocked")
        self.assertEqual(internal["state"], "blocked")

    def test_guard_external_contract_cannot_be_removed(self):
        broken = copy.deepcopy(REGISTRY)
        broken["contracts"] = [
            c for c in broken["contracts"] if c["id"] != "guard-action-submission"
        ]
        with self.assertRaisesRegex(ValueError, "missing required service contract"):
            validate_registry(broken)


    def test_rust_migration_candidate_is_not_run_owner(self):
        migration = REGISTRY["runtime_migration"]
        self.assertEqual(migration["baseline_writer"], "avaargsh/agent-runtime")
        self.assertEqual(migration["candidate_writer"], "avaargsh/agent-infra")
        self.assertIs(migration["cutover_authorized"], False)
        self.assertEqual(migration["gate"], "G01")
        self.assertTrue(validate_registry(REGISTRY))

    def test_rust_migration_cannot_silently_enable_dual_writes(self):
        broken = copy.deepcopy(REGISTRY)
        broken["runtime_migration"]["cutover_authorized"] = True
        with self.assertRaisesRegex(ValueError, "runtime migration cutover is not authorized"):
            validate_registry(broken)

    def test_rust_migration_cannot_claim_unverified_parity(self):
        broken = copy.deepcopy(REGISTRY)
        broken["runtime_migration"]["evidence"]["workflow_engine_parity"] = "真实环境验收"
        with self.assertRaisesRegex(ValueError, "runtime migration parity is not verified"):
            validate_registry(broken)

    def test_runtime_migration_metadata_is_mandatory(self):
        broken = copy.deepcopy(REGISTRY)
        broken.pop("runtime_migration")
        with self.assertRaisesRegex(ValueError, "runtime migration declaration required"):
            validate_registry(broken)

    def test_rust_migration_candidate_must_be_distinct(self):
        broken = copy.deepcopy(REGISTRY)
        broken["runtime_migration"]["candidate_writer"] = "avaargsh/agent-runtime"
        with self.assertRaisesRegex(ValueError, "runtime migration owner mismatch"):
            validate_registry(broken)


if __name__ == "__main__":
    unittest.main()
