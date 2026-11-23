# Signed receipt export links (Draft, optional, read-only)

**Status:** Source contract candidate in ACP Draft PR #106, stacked on #105/#91. No real Sandbox/AgentD/Guard/Compute signed source exporters, actual PEP, command dispatch, physical release, or audited service clock is proven.

## Why

The G01–G05 v2 verifier already checks seven independent source signatures, source-native receipt hash bindings, the original tenant/Run/fault, expected source revisions, and timestamps. A re-signed downstream stage can nevertheless assert a different upstream stage **without committing to the exact upstream signed export bytes**. Timestamps alone are not an immutable provenance link. `VerifyLinked` is a separate, stricter **opt-in** check; existing `Verify` and `VerifyArchive` remain unchanged.

## Required signed graph

| Stage | Owner | Signed parent export |
| --- | --- | --- |
| `run` | ACP | none (root) |
| `decision` | Decision | `run` |
| `permit` | Guard | `decision` |
| `recovery` | Runtime | `permit` |
| `guard_release` | Guard | `recovery` |
| `sandbox_release` | Sandbox | `guard_release` |
| `compute_release` | Compute | `guard_release` |

Each **owner-signed** statement optionally includes `parent_export_digest`, a SHA256 digest of its predecessor's exact original **signed export payload bytes** (`payload_b64` decoded). The root **must have no parent**. The link is signed as part of the child source's existing Ed25519 domain-separated payload. No verifier-generated or model-derived parent field is trusted. Sandbox and Compute release are siblings, because their provider inspections can run independently after Guard settlement; Compute must not silently claim to depend on Sandbox release.

`VerifyLinked` first runs the entire existing `Verify` gate with independently provisioned keys and `expected.json`. It then checks **all** links, rejecting missing, stale, sibling-swapped, or recomputed/re-encoded parent payload references. The legacy v2 verifier intentionally ignores this optional field, so callers **must deliberately invoke** the linked gate rather than interpreting a legacy GREEN as linked proof.

## Usage (candidate)

```sh
go run ./cmd/acp-evidence-verify \
  --package "$RUNNER_TEMP/acp-evidence/package.json" \
  --expected "$RUNNER_TEMP/acp-evidence/expected.json" \
  --trust-dir "$RUNNER_TEMP/acp-evidence/trust" \
  --require-linked
```

`--require-linked` is **live-only**; combining it with `--archive-seal` is explicitly rejected because historical linked verification has not been implemented. Do not weaken freshness checks or use a synthetic fixture in the mandatory Golden Path.

## Threat boundary and blockers

- The hash link proves **cryptographic commitment to particular bytes** by each trusted source. It does not prove when the source learned that predecessor, whether the source truly operated its provider, or whether a Guard Permit was enforced.
- Independent signing keys and authentic `expected.json` heads remain mandatory; compromised signers, hostile administrators, copied synthetic source reports and post-hoc collusion are not solved by hashes.
- Future production causality requires append-only source-owned journal sequence numbers, stable revision/commit identities, actual signed provider Inspect and trustworthy clock/skew policy. An authoritative post-commit journal event should persist the predecessor receipt reference **before** downstream effects.
- This code is offline/parser-only. No real owner exporters, mTLS, AgentD, SandboxLease, dispatch, credential broker, independent physical absence evidence or Compute cost FINAL exists by virtue of this PR.
- Even a linked consistency PASS must **not** authorize production release, resource cleanup or protected effects. This read-only verifier can merge in the open-development phase after exact-head regression checks and technical review; ACP Issues #70–#72 remain prerequisites for live protected execution.
