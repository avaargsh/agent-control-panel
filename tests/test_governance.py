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


if __name__ == "__main__":
    unittest.main()
