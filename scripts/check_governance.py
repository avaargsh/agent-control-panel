#!/usr/bin/env python3
"""Check governance registry for internally consistent, non-ambiguous ownership.

This verifies the proposed manifest ONLY. It does not verify remote commits or
approve protocols, configure branch protection, or exercise cross-repo CI.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = re.compile(r"^avaargsh/[A-Za-z0-9_.-]+$")
SHA = re.compile(r"^[a-f0-9]{40}$")
ISSUE = re.compile(r"^https://github\.com/avaargsh/[A-Za-z0-9_.-]+/issues/[1-9][0-9]*$")
ROOT_ISSUE = "https://github.com/avaargsh/agent-control-panel/issues/3"

# These are the v0.3 proposal's non-optional authority boundaries. Additive
# domains are allowed, but a required domain or identifier cannot disappear.
REQUIRED_DOMAINS = {
    "agent-definition": (
        "avaargsh/agent-control-panel",
        frozenset({
            "tenant_id", "project_id", "agent_id", "bundle_digest",
            "release_id", "session_id", "run_intent_id",
        }),
    ),
    "run-execution": (
        "avaargsh/agent-runtime",
        frozenset({"run_id", "workflow_id", "run_attempt_id"}),
    ),
    "decision-record": (
        "avaargsh/agent-decision",
        frozenset({"decision_id", "proposal_id"}),
    ),
    "protected-action": (
        "avaargsh/EngageGuard",
        frozenset({"operation_id", "action_hash", "permit_id", "executor_attempt_id"}),
    ),
    "compute": (
        "avaargsh/compute-control-panel",
        frozenset({"workload_id", "allocation_id", "compute_operation_id"}),
    ),
    "workflow-history": (
        "external:Temporal",
        frozenset({"temporal_activity_attempt"}),
    ),
    "provider-facts": (
        "external:Kubernetes/Kueue/Provider",
        frozenset({"provider_resource_id"}),
    ),
}

# Protocol pointers must remain service-owned and source-pinned. The two
# incompatible legacy/draft protocols are deliberately required to stay blocked.
REQUIRED_CONTRACTS = {
    "agent-control-run-intent": (
        "avaargsh/agent-control-panel",
        "docs/architecture/ADR-003-IDENTITY-AND-RETRY-OWNERSHIP.md",
        "v0.2-draft",
        "candidate",
    ),
    "runtime-run-and-workflow": (
        "avaargsh/agent-runtime",
        "docs/architecture/DECISION-INTEGRATION-CONTRACT.md",
        "v0.1-draft",
        "candidate",
    ),
    "decision-core-http": (
        "avaargsh/agent-decision",
        "api/openapi.yaml",
        "core.v1-draft",
        "candidate",
    ),
    "framework-plugin-decision-turn": (
        "avaargsh/agent-decision",
        "protocol/v0.1/manifest.json",
        "plugin.v0.1-legacy",
        "blocked",
    ),
    "guard-action-submission": (
        "avaargsh/EngageGuard",
        "docs/contracts/action-submission.v1.schema.json",
        "action-submission.v1-draft",
        "blocked",
    ),
    "guard-internal-action-request": (
        "avaargsh/EngageGuard",
        "docs/contracts/action-request.v1.schema.json",
        "guard-internal.v1-draft",
        "blocked",
    ),
    "compute-workload-http": (
        "avaargsh/compute-control-panel",
        "docs/contracts/COMPUTE-WORKLOAD-V1.md",
        "compute.v1-draft",
        "candidate",
    ),
}

REQUIRED_REQUEST_IDS = {
    "invocation_id": ("avaargsh/agent-runtime", "avaargsh/agent-decision",
                      "stable Decision/adapter invocation across Runtime Activity retry"),
    "guard_submission_key": ("avaargsh/agent-runtime", "avaargsh/EngageGuard",
                             "stable HTTP Guard Idempotency-Key; Guard creates operation_id"),
}

REQUIRED_GATES = {
    "G01": (
        frozenset({"avaargsh/agent-control-panel", "avaargsh/agent-runtime"}),
        "https://github.com/avaargsh/agent-control-panel/issues/3",
    ),
    "G02": (
        frozenset({"avaargsh/agent-decision", "avaargsh/agent-runtime"}),
        "https://github.com/avaargsh/agent-decision/issues/9",
    ),
    "G03": (
        frozenset({"avaargsh/EngageGuard", "avaargsh/agent-runtime"}),
        "https://github.com/avaargsh/EngageGuard/issues/3",
    ),
    "G04": (
        frozenset({"avaargsh/compute-control-panel", "avaargsh/EngageGuard"}),
        "https://github.com/avaargsh/compute-control-panel/issues/3",
    ),
    "G05": (
        frozenset({"avaargsh/agent-runtime", "avaargsh/agent-decision"}),
        "https://github.com/avaargsh/agent-runtime/issues/5",
    ),
}


def unique_object(pairs):
    output = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate registry JSON key: " + key)
        output[key] = value
    return output


def validate_registry(registry):
    if registry.get("version") != "platform-governance/v0.3" or registry.get("state") != "proposed":
        raise ValueError("governance v0.3 must explicitly be a proposed candidate")
    if registry.get("root_issue") != ROOT_ISSUE or not ISSUE.fullmatch(registry.get("root_issue", "")):
        raise ValueError("governance tracking issue must remain anchored to ACP issue #3")

    domains, contracts, gates = (registry.get(n) for n in ("domain_ownership", "contracts", "merge_gates"))
    if not all(isinstance(v, list) and v for v in (domains, contracts, gates)):
        raise ValueError("domains, contracts and gates must be nonempty")

    owners, domain_ids, identifiers = set(), set(), set()
    domain_by_id = {}
    for domain in domains:
        owner = domain["writer"]
        if not (REPO.fullmatch(owner) or owner.startswith("external:")):
            raise ValueError("unknown domain writer namespace")
        if domain["id"] in domain_ids:
            raise ValueError("duplicate domain ID")
        domain_ids.add(domain["id"])
        domain_by_id[domain["id"]] = domain
        owners.add(owner)
        for identifier in domain["identifiers"]:
            if identifier in identifiers:
                raise ValueError("identifier has multiple canonical writers: " + identifier)
            identifiers.add(identifier)

    for domain_id, (expected_owner, required_identifiers) in REQUIRED_DOMAINS.items():
        domain = domain_by_id.get(domain_id)
        if domain is None:
            raise ValueError("missing required authoritative domain: " + domain_id)
        if domain["writer"] != expected_owner:
            raise ValueError("authoritative domain owner mismatch: " + domain_id)
        missing_identifiers = required_identifiers.difference(domain["identifiers"])
        if missing_identifiers:
            raise ValueError(
                "missing required canonical identifiers for " + domain_id + ": "
                + ", ".join(sorted(missing_identifiers))
            )

    requests = registry.get("issued_request_ids")
    if not isinstance(requests, list) or not requests:
        raise ValueError("request ID issuance matrix is required")
    request_ids = set()
    request_by_id = {}
    for request_id in requests:
        name = request_id["id"]
        if name in identifiers or name in request_ids:
            raise ValueError("request ID duplicated as authority-owned identifier")
        request_ids.add(name)
        request_by_id[name] = request_id
        if (request_id["created_by"] not in owners or
                request_id["durable_index_owner"] not in owners or
                not request_id.get("meaning")):
            raise ValueError("request ID creator and durable index owner must be declared")

    for request_id, (creator, index_owner, meaning) in REQUIRED_REQUEST_IDS.items():
        actual = request_by_id.get(request_id)
        if actual is None:
            raise ValueError("missing required request ID: " + request_id)
        if actual["created_by"] != creator or actual["durable_index_owner"] != index_owner:
            raise ValueError("request ID ownership mismatch: " + request_id)
        if actual["meaning"] != meaning:
            raise ValueError("request ID semantics mismatch: " + request_id)

    contract_ids = set()
    contract_by_id = {}
    for contract in contracts:
        if contract["id"] in contract_ids:
            raise ValueError("duplicate contract id")
        contract_ids.add(contract["id"])
        contract_by_id[contract["id"]] = contract
        if contract["repo"] not in owners or not REPO.fullmatch(contract["repo"]):
            raise ValueError("contract references a non-owner repository")
        if not SHA.fullmatch(contract["commit"]) or not contract["path"] or contract["path"].startswith("/"):
            raise ValueError("contract source must pin an immutable commit and relative path")
        if ".." in Path(contract["path"]).parts:
            raise ValueError("contract path escapes source repository")
        if contract["state"] not in ("candidate", "blocked"):
            raise ValueError("unapproved registry cannot declare accepted contracts")
        if not ISSUE.fullmatch(contract["issue"]):
            raise ValueError("contract missing linked blocker issue")
        if not contract["version"]:
            raise ValueError("contract version cannot be blank")

    for contract_id, (expected_repo, expected_path, expected_version, expected_state) in REQUIRED_CONTRACTS.items():
        contract = contract_by_id.get(contract_id)
        if contract is None:
            raise ValueError("missing required service contract: " + contract_id)
        if (contract["repo"] != expected_repo or contract["path"] != expected_path or
                contract["state"] != expected_state):
            raise ValueError("service contract authority or state mismatch: " + contract_id)
        if contract["version"] != expected_version:
            raise ValueError("service contract version mismatch: " + contract_id)

    gate_ids = set()
    gate_by_id = {}
    for gate in gates:
        if gate["id"] in gate_ids:
            raise ValueError("duplicate merge gate")
        gate_ids.add(gate["id"])
        gate_by_id[gate["id"]] = gate
        if gate["state"] != "blocked":
            raise ValueError("a proposed registry cannot silently pass a merge gate")
        if not ISSUE.fullmatch(gate["issue"]):
            raise ValueError("merge gate missing issue")
        if not gate["owners"] or len(gate["owners"]) != len(set(gate["owners"])):
            raise ValueError("merge gate owners invalid")
        if any(owner not in owners for owner in gate["owners"]):
            raise ValueError("merge gate has an unknown authoritative owner")

    for gate_id, (expected_owners, expected_issue) in REQUIRED_GATES.items():
        gate = gate_by_id.get(gate_id)
        if gate is None:
            raise ValueError("missing required merge gate: " + gate_id)
        if set(gate["owners"]) != expected_owners or gate["issue"] != expected_issue:
            raise ValueError("merge gate authoritative owners mismatch: " + gate_id)

    # Rust is an execution-core migration candidate, not a second Run writer.
    # Only a separately ratified governance version may authorize the cutover.
    migration = registry.get("runtime_migration")
    if not isinstance(migration, dict):
        raise ValueError("runtime migration declaration required")
    if (migration.get("baseline_writer") != domain_by_id["run-execution"]["writer"] or
            migration.get("candidate_writer") != "avaargsh/agent-infra" or
            migration.get("candidate_writer") == migration.get("baseline_writer")):
        raise ValueError("runtime migration owner mismatch")
    if (migration.get("strategy") != "single-writer-cutover" or
            migration.get("status") != "candidate" or
            migration.get("gate") != "G01" or
            gate_by_id["G01"]["state"] != "blocked"):
        raise ValueError("runtime migration requires blocked G01 single-writer gate")
    if migration.get("cutover_authorized") is not False:
        raise ValueError("runtime migration cutover is not authorized")
    evidence = migration.get("evidence")
    required_evidence = {
        "rust_sqlx_store", "trusted_acp_transport", "workflow_engine_parity",
        "restart_recovery", "cross_service_golden_path",
    }
    allowed_levels = {"已实现", "测试通过", "真实环境验收", "当前未知"}
    if (not isinstance(evidence, dict) or set(evidence) != required_evidence or
            any(v not in allowed_levels for v in evidence.values())):
        raise ValueError("runtime migration evidence invalid")
    if any(evidence[k] != "当前未知" for k in required_evidence - {"rust_sqlx_store"}):
        raise ValueError("runtime migration parity is not verified")
    source = migration.get("source")
    if (not isinstance(source, dict) or
            source.get("pr_url") != "https://github.com/avaargsh/agent-infra/pull/9" or
            not isinstance(source.get("head_sha"), str) or
            not SHA.fullmatch(source["head_sha"]) or
            not isinstance(source.get("ci_url"), str) or
            not re.fullmatch(r"https://github\\.com/avaargsh/agent-infra/actions/runs/[0-9]+", source["ci_url"])):
        raise ValueError("runtime migration evidence source invalid")

    return True


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "governance" / "contract-registry.v0.3.json"
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    validate_registry(value)
    print(f"Validated proposed platform governance registry: {len(value['domain_ownership'])} domains, "
          f"{len(value['contracts'])} pinned candidate contracts, {len(value['merge_gates'])} blocked gates")


if __name__ == "__main__":
    main()
