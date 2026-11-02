#!/usr/bin/env python3
"""Validate canonical Decision schemas and cross-language ActionHash vectors."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parent
DECISION = ROOT / "agent-decision" / "v0.1"
ACTION_HASH = ROOT / "engageguard" / "action-hash" / "v0.1"


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def expect_valid(validator, payload, label: str) -> None:
    errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.path))
    if errors:
        details = "; ".join(error.message for error in errors)
        raise SystemExit(f"{label}: expected valid payload: {details}")


def expect_invalid(validator, payload, label: str) -> None:
    if validator.is_valid(payload):
        raise SystemExit(f"{label}: invalid payload was accepted")


def main() -> None:
    request_schema = load_json(DECISION / "decision-turn.schema.json")
    result_schema = load_json(DECISION / "decision-result.schema.json")
    Draft202012Validator.check_schema(request_schema)
    Draft202012Validator.check_schema(result_schema)

    request_validator = Draft202012Validator(request_schema, format_checker=FormatChecker())
    result_validator = Draft202012Validator(result_schema, format_checker=FormatChecker())

    request = load_json(DECISION / "examples" / "decision-turn.valid.json")
    final_response = load_json(DECISION / "examples" / "final-response.valid.json")
    proposals = load_json(DECISION / "examples" / "action-proposals.valid.json")

    expect_valid(request_validator, request, "DecisionTurn")
    expect_valid(result_validator, final_response, "FinalResponse")
    expect_valid(result_validator, proposals, "ActionProposals")

    invalid_kind = dict(final_response, kind="needs_input")
    expect_invalid(result_validator, invalid_kind, "unknown response discriminator")
    missing_evidence = dict(final_response)
    missing_evidence.pop("evidence_refs")
    expect_invalid(result_validator, missing_evidence, "missing evidence_refs")
    extra_field = dict(request, provider_token="must-not-be-accepted")
    expect_invalid(request_validator, extra_field, "unexpected request field")

    vectors = load_json(ACTION_HASH / "workspace-write-vectors.json")
    if vectors.get("canonicalization") != "RFC 8785 JCS" or vectors.get("algorithm") != "SHA-256":
        raise SystemExit("ActionHash vector metadata mismatch")
    if vectors.get("domain_separator") != "engageguard/action-hash/v1\x00":
        raise SystemExit("ActionHash domain separator mismatch")
    domain = vectors["domain_separator"].encode("utf-8")
    for vector in vectors["vectors"]:
        # Use an RFC 8785 implementation rather than approximating JCS with
        # json.dumps (notably, string escaping must match ECMAScript exactly).
        import rfc8785

        canonical_bytes = rfc8785.dumps(vector["action"])
        # The explanatory canonical_json fixture must describe the same
        # action; the hash is always computed from independently generated JCS.
        if json.loads(vector["canonical_json"]) != vector["action"]:
            raise SystemExit(f"{vector['name']}: canonical JSON describes a different action")
        digest = hashlib.sha256(domain + canonical_bytes).hexdigest()
        if digest != vector["action_hash"]:
            raise SystemExit(f"{vector['name']}: ActionHash mismatch")

    print("Decision JSON Schemas and ActionHash v0.1 vectors: PASS")


if __name__ == "__main__":
    main()
