# G01–G05 same-Run Evidence Package v1 (Draft)

**Status:** local, read-only consistency validator; **NOT** a production gate acceptance. This is an additive verifier on ACP Draft #91, not a new Run, Decision, Guard, Sandbox or Compute authority.

## What is checked

The verifier accepts one original ACP/Runtime subject, one real Worker SIGKILL fault and one independently supplied original provider allocation binding. It requires exactly **seven source-signed lifecycle statements** in addition to the **eight original signed before/after observations** already required by `internal/postfault`. Each signed exported observation and its native source receipt are included as separate base64 byte strings and checked against an externally trusted Ed25519 owner key, using the exact domain `acp.evidence-observation/v1\x00`. No source may share a signing key with another authority.

| Gate | Signed stages | Consistency checked | Still required for actual gate PASS |
| --- | --- | --- | --- |
| G01 | ACP `run` + postfault Runtime | original tenant/Run/Session/Workflow/RunIntent and RequestDigest binding, `ACCEPTED` | separately asserted original Runtime acceptance, lost-ACK/idempotency and exact-head live test |
| G02 | Decision `decision` + Guard `permit` | signed Decision ID/digest matches downstream Permit | independent Runtime DecisionRecord wire-version parity and accepted Decision transition |
| G03 | Guard `permit`, Runtime `recovery`, Guard `guard_release`, postfault Guard and Runtime | exact Permit/ActionDigest and Guard epoch preserved; separately pinned CLOSED Runtime breaker epoch | real Permit issuer, PEP, re-read under live authority and operation receipt/UNKNOWN reconciliation |
| G04 | Guard settlement, Sandbox `sandbox_release`, Compute `compute_release` | signed `RELEASED` with `provider_absent=true`, original sandbox UID, exact externally expected AllocationID/provider UID/generation | real independent Sandbox and Compute provider Inspect after deletion; actual physical resource/credential release and cost FINAL |
| G05 | Runtime `recovery`, postfault Runtime/AgentD/Sandbox/Guard | same checkpoint, command ID, breaker epoch, resolved UNKNOWN and workspace readback | real same-Run worker SIGKILL plus independently captured persistence and signed owner evidence |

**Important:** the signed export schema checks compatibility of claims, not their physical truth. A producer must obtain the source facts from its own authoritative storage and authenticated provider API, with a source-pinned exporter and independent review. Merely signing hard-coded JSON cannot meet any live gate.

## Inputs and contract

- `package.json` has schema `acp.evidence-package/v1`: original `subject`, `run_intent_id`, `request_digest`, `fault`, `postfault_b64` (exact signed postfault bundle bytes), and seven `receipts` with `stage`, `authority`, `payload_b64` (the signed export), `original_b64` (opaque unmodified native receipt bytes), `signature_b64`. The signed export contains `original_digest` equal to SHA256 of `original_b64`. The verifier rejects a missing or altered native receipt, even if the export signature remains valid.
- Each signed source export JSON has schema `acp.evidence-observation/v1`; it binds the same subject, RunIntent, request digest, source/stage, raw source receipt hash and observation timestamp. Stage-specific fields must match the issuing authority and other receipts. The original opaque receipt is retained byte-for-byte; a separate owner-owned exporter must demonstrate its actual provenance and schema. This checker does not attempt to infer that opaque bytes prove a real provider operation.
- `expected.json` has schema `acp.evidence-expected/v1`: the same independently accepted subject, RunIntent, request digest, actual fault ID/kind/time and original `allocation_id`, `provider_uid`, `provider_generation`. **It must not be copied from package.json**, the model, an untrusted task payload, or the receipt under verification.
- `trust/` contains seven independent, pinned, hex-encoded Ed25519 **public** keys: `acp.pub`, `decision.pub`, `guard.pub`, `runtime.pub`, `sandbox.pub`, `agentd.pub`, `compute.pub`. Private keys never enter ACP, its CLI, this package or CI logs.
- The postfault bundle remains bound to the same Run and fault and is verified with the existing `postfault.Verify`. Missing or unresolved UNKNOWN, stale/rotated Permit, changed checkpoint, changed sandbox UID, a different provider generation, absent trust root or incomplete release makes the verdict **BLOCKED**.

Run against independently provisioned artifacts:

```sh
go test -race -count=1 ./internal/evidencepackage ./cmd/acp-evidence-verify
go run ./cmd/acp-evidence-verify \
  --package "$RUNNER_TEMP/acp-evidence/package.json" \
  --expected "$RUNNER_TEMP/acp-evidence/expected.json" \
  --trust-dir "$RUNNER_TEMP/acp-evidence/trust"
```

A local test creates **ephemeral test keys and invented provider facts** solely for the parser's positive and negative assertions. It is not live evidence. The live CI gate MUST require real independently signed records; never add fixture generators, skip flags, cached green receipts or `continue-on-error` to make it pass.

## Limitations and next real integration

1. **Sandbox/AgentD:** Issue #70 must supply a real mTLS SandboxService and AgentD, a durable Journal with exact command/generation and terminal inspect/exit proof; only permit-bound PEP may execute commands. PR #92's local OS SIGKILL readback remains a separate, narrower result.
2. **G01/G02/G03:** source owners must export real accepted Runtime/Decision/Guard records and prove revoked/expired authorization cannot be replayed. Wire compatibility and actual effect authority cannot be inferred from this parser.
3. **G04:** after the authoritative command is reconciled, capture *separate* Sandbox and Compute signed inspect/readback observations for absence, credential revocation and cost reconciliation. If Inspect returns UNKNOWN, preserve UNKNOWN; do not mark release FINAL.
4. **Time/replay:** this v1 uses postfault's short live freshness gate (fault no older than 30 minutes, post-recovery observations no older than five minutes). **It is not yet a durable archival timestamp validator.** Long-term offline re-verification requires a separately trusted, immutable capture-time seal; never change local clock to make historical evidence pass.
5. **Independent review:** a Green CLI result means signatures and cross-links are consistent; complete G01–G05 requires service-owner exact-head experiments, physical checks and an independent security review. Keep #91 and #92 Draft and do not merge or deploy protected writes on this evidence alone.
