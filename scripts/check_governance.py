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
    if not ISSUE.fullmatch(registry.get("root_issue", "")):
        raise ValueError("missing real governance tracking issue")
    domains, contracts, gates = (registry.get(n) for n in ("domain_ownership", "contracts", "merge_gates"))
    if not all(isinstance(v, list) and v for v in (domains, contracts, gates)):
        raise ValueError("domains, contracts and gates must be nonempty")
    owners, domain_ids, identifiers = set(), set(), set()
    for domain in domains:
        owner = domain["writer"]
        if not (REPO.fullmatch(owner) or owner.startswith("external:")):
            raise ValueError("unknown domain writer namespace")
        if domain["id"] in domain_ids:
            raise ValueError("duplicate domain ID")
        domain_ids.add(domain["id"])
        owners.add(owner)
        for identifier in domain["identifiers"]:
            if identifier in identifiers:
                raise ValueError("identifier has multiple canonical writers: " + identifier)
            identifiers.add(identifier)
    requests = registry.get("issued_request_ids")
    if not isinstance(requests, list) or not requests:
        raise ValueError("request ID issuance matrix is required")
    request_ids = set()
    for request_id in requests:
        name = request_id["id"]
        if name in identifiers or name in request_ids:
            raise ValueError("request ID duplicated as authority-owned identifier")
        request_ids.add(name)
        if (request_id["created_by"] not in owners or
                request_id["durable_index_owner"] not in owners or
                not request_id.get("meaning")):
            raise ValueError("request ID creator and durable index owner must be declared")
    contract_ids = set()
    for contract in contracts:
        if contract["id"] in contract_ids:
            raise ValueError("duplicate contract id")
        contract_ids.add(contract["id"])
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
    gate_ids = set()
    for gate in gates:
        if gate["id"] in gate_ids:
            raise ValueError("duplicate merge gate")
        gate_ids.add(gate["id"])
        if gate["state"] != "blocked":
            raise ValueError("a proposed registry cannot silently pass a merge gate")
        if not ISSUE.fullmatch(gate["issue"]):
            raise ValueError("merge gate missing issue")
        if not gate["owners"] or len(gate["owners"]) != len(set(gate["owners"])):
            raise ValueError("merge gate owners invalid")
        if any(owner not in owners for owner in gate["owners"]):
            raise ValueError("merge gate has an unknown authoritative owner")
    return True


def main():
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "governance" / "contract-registry.v0.3.json"
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_object)
    validate_registry(value)
    print(f"Validated proposed platform governance registry: {len(value['domain_ownership'])} domains, "
          f"{len(value['contracts'])} pinned candidate contracts, {len(value['merge_gates'])} blocked gates")


if __name__ == "__main__":
    main()
