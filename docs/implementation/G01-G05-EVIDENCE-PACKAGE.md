# G01–G05 same-Run Evidence Package v2 (Draft)

**Status:** local, read-only consistency validator; **NOT** a production gate acceptance. This is an additive verifier on ACP Draft #91, not a new Run, Decision, Guard, Sandbox or Compute authority.

## What is checked

The verifier accepts one original ACP/Runtime subject, one real Worker SIGKILL fault and one independently supplied original provider allocation binding. It requires exactly **seven source-signed lifecycle statements** in addition to the **eight original signed before/after observations** already required by `internal/postfault`. Each signed exported observation and its native source receipt are included as separate base64 byte strings and checked against an externally trusted Ed25519 owner key, using the exact domain `acp.evidence-observation/v2\x00`. No source may share a signing key with another authority.

| Gate | Signed stages | Consistency checked | Still required for actual gate PASS |
| --- | --- | --- | --- |
| G01 | ACP `run` + postfault Runtime | original tenant/Run/Session/Workflow/RunIntent and RequestDigest binding, `ACCEPTED` | separately asserted original Runtime acceptance, lost-ACK/idempotency and exact-head live test |
| G02 | Decision `decision` + Guard `permit` | signed Decision ID/digest matches downstream Permit | independent Runtime DecisionRecord wire-version parity and accepted Decision transition |
| G03 | Guard `permit`, Runtime `recovery`, Guard `guard_release`, postfault Guard and Runtime | exact Permit/ActionDigest and Guard epoch preserved; separately pinned CLOSED Runtime breaker epoch | real Permit issuer, PEP, re-read under live authority and operation receipt/UNKNOWN reconciliation |
| G04 | Guard settlement, Sandbox `sandbox_release`, Compute `compute_release` | signed `RELEASED` with `provider_absent=true`, original sandbox UID, exact externally expected AllocationID/provider UID/generation | real independent Sandbox and Compute provider Inspect after deletion; actual physical resource/credential release and cost FINAL |
| G05 | Runtime `recovery`, postfault Runtime/AgentD/Sandbox/Guard | same checkpoint, command ID, breaker epoch, resolved UNKNOWN and workspace readback | real same-Run worker SIGKILL plus independently captured persistence and signed owner evidence |

**Important:** the signed export schema checks compatibility of claims, not their physical truth. A producer must obtain the source facts from its own authoritative storage and authenticated provider API, with a source-pinned exporter and independent review. Merely signing hard-coded JSON cannot meet any live gate.

## Inputs and contract

- `package.json` has schema `acp.evidence-package/v2`: original `subject`, `run_intent_id`, `request_digest`, `fault`, `postfault_b64` (exact signed postfault bundle bytes), and seven `receipts` with `stage`, `authority`, `payload_b64` (the signed export), `original_b64` (opaque unmodified native receipt bytes), `signature_b64`. The signed export contains `original_digest` equal to SHA256 of `original_b64`. The verifier rejects a missing or altered native receipt, even if the export signature remains valid.
- Each signed source export JSON has schema `acp.evidence-observation/v2`; it binds the same subject, RunIntent, request digest, source/stage, raw source receipt hash and observation timestamp. Stage-specific fields must match the issuing authority and other receipts. The original opaque receipt is retained byte-for-byte; a separate owner-owned exporter must demonstrate its actual provenance and schema. This checker does not attempt to infer that opaque bytes prove a real provider operation.
- `expected.json` has schema `acp.evidence-expected/v2`: the same independently accepted subject, RunIntent, request digest, actual fault ID/kind/time and original `allocation_id`, `provider_uid`, `provider_generation`. **It must not be copied from package.json**, the model, an untrusted task payload, or the receipt under verification.
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

## Receipt head version fencing (candidate, not an authoritative writer)

- Each owner-signed exported statement now includes a positive `source_revision`. The **independently obtained** `expected.json` must contain exactly seven `source_revisions` keyed by lifecycle stage (`run`, `decision`, `permit`, `recovery`, `guard_release`, `sandbox_release`, `compute_release`). The checker rejects missing, older or unexpected future revisions even with a valid owner signature. The v2 package/observation/expected schema and signature domain intentionally reject v1 artifacts; no deployed producer migration is claimed.
- `CompareReceiptHead(current, incoming)` classifies **INSERT / IDEMPOTENT_REPLAY / ADVANCE** and rejects older revision, same-revision/different-byte digests and tenant/Run/stage/authority rebinding. It is read-only. To actually prevent stale overwrites or double records, the **source-owned writer** must apply this under an atomic database CAS/row lock with a unique identity and append-only original bytes. This ACP library neither writes a record nor proves that a remote writer did so.
- An expected head snapshot constructed from the submitted package is untrusted and invalid by contract. Valid signatures or transport acknowledgement do not imply a passing business verdict or permission to publish a PR. Receipt provenance, source-owned atomic persistence, external PR-to-original-receipt correlation and independent live verification are still blocking.

## Historical, offline re-verification (candidate)

Default `acp-evidence-verify` remains **LIVE ONLY**: it evaluates fresh Permit state, fault age and after-recovery observations against the current clock. Supplying an old `package.json` without an additional trusted archival attestation still fails closed. Do not set the verifier's clock backwards.

`internal/evidencepackage.VerifyArchive` adds an **opt-in, read-only** historical consistency check. A separate archival authority signs the exact original `package.json` and independently sourced `expected.json` bytes by their SHA256 hashes, plus `archive_id`, `captured_at` and `sealed_at`, under the distinct Ed25519 domain `acp.evidence-archive-seal/v1\\x00`. The archive issuer's public key MUST be provisioned outside the package, distinct from all seven service authorities; the signed statement must assert `captured_at ≤ sealed_at ≤ current time`, with at most two minutes between capture and sealing. The verifier then re-applies ALL existing signed lifecycle and postfault continuity checks **at the attested original capture instant**. It never converts a historical Permit into current authorization.

CLI usage with an independently issued `seal.json` (containing base64 `payload_b64`, `signature_b64`) and trusted `archiver.pub`:

```sh
go run ./cmd/acp-evidence-verify \
  --package "$ARCHIVE/package.json" \
  --expected "$ARCHIVE/expected.json" \
  --trust-dir "$ARCHIVE/owner-public-keys" \
  --archive-seal "$ARCHIVE/seal.json" \
  --archive-pub "$ARCHIVE/archiver.pub"
```

**Crucial time-trust boundary:** an Ed25519 signature can attest what an archival issuer claims but cannot prove when the issuer actually signed. Independent time-source policy and an append-only transparency log or trusted timestamp/notarization are still needed before making an evidentiary retention or non-backdating claim. Ephemeral test keys validate parser behavior only. **No real archival authority, immutable log, or production G01–G05 evidence is claimed.** This feature is never enabled in the live Golden Path CI gate.

## Limitations and next real integration

1. **Sandbox/AgentD:** Issue #70 must supply a real mTLS SandboxService and AgentD, a durable Journal with exact command/generation and terminal inspect/exit proof; only permit-bound PEP may execute commands. PR #92's local OS SIGKILL readback remains a separate, narrower result.
2. **G01/G02/G03:** source owners must export real accepted Runtime/Decision/Guard records and prove revoked/expired authorization cannot be replayed. Wire compatibility and actual effect authority cannot be inferred from this parser.
3. **G04:** after the authoritative command is reconciled, capture *separate* Sandbox and Compute signed inspect/readback observations for absence, credential revocation and cost reconciliation. If Inspect returns UNKNOWN, preserve UNKNOWN; do not mark release FINAL.
4. **Time/replay:** the live gate retains postfault's 30-minute fault and five-minute post-recovery freshness bounds. Offline archive verification is a separately signed candidate; without independent trusted timestamp anchoring, a signed archive assertion is not proof against backdating. Never change local clock to make live evidence pass.
5. **Independent review:** a Green CLI result means signatures and cross-links are consistent; complete G01–G05 requires service-owner exact-head experiments, physical checks and an independent security review. The read-only verifier and negative tests may merge into open development after scoped technical review and exact-source CI; never deploy protected writes or treat the resulting main branch as production G01–G05 acceptance on this evidence alone.
