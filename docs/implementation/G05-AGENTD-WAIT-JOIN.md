# G05: original AgentD OS Wait receipt join (read-only candidate)

**Status:** Draft PR #110 stacked on ACP Evidence #106/#105/#91. The authority that performs the actual process Wait and stores the immutable source receipt is **Sandbox/AgentD**, not ACP. It is implemented as a separate standalone module in Draft [#108](https://github.com/avaargsh/agent-control-panel/pull/108) (real Linux process / PostgreSQL tests). ACP only verifies externally supplied, already committed source bytes.

## Source and expected binding

The source `acp.agentd-wait-terminal/v1` includes:
- `source=agentd.os.wait`, `observed_at`, `journal_revision=2`, `status=EXITED|FAILED_CONFIRMED`, `exit_code`, `signal`.
- Immutable original `tenant_id, run_id, runtime_attempt_id, sandbox_uid, command_id, attempt_id, provider_command_uid, request_digest, guard_permit_id, permit_epoch, process_pid, process_start_ticks, host_boot_id`.
- Original canonical JSON payload, Ed25519 signature on `acp.agentd-wait-terminal/v1\x00 || payload`, SHA256 of exact payload bytes. The source writer commits the signed bytes to independent Sandbox PostgreSQL and only then returns an ACK; an ACK timeout does not make an effect retriable.

`postfault.VerifyWithAgentDWait` requires the existing eight independently signed `before_fault/after_recovery` observations to pass first. It then validates original Wait payload size/strict parsing/canonical encoding, domain-separated signature with the independently configured AgentD public key (same authenticated owner), and the exact expected ACP accepted Run + separate Guard Permit/epoch. It compares the source receipt's SHA256 to the independently signed AgentD post-recovery `exit_receipt_digest`, plus `CommandID/AttemptID/ProviderUID/State` and post-fault timestamp order.

**Critically**, `ExpectedAgentDWait` must be built by a trusted orchestration/verifier process from ACP's accepted Run + Runtime's original attempt + Guard's authenticated Permit response. Do **not** populate it by copying the candidate AgentD receipt or LLM output. A mutable client-provided expected tuple provides no independent guarantee.

## Fallbacks / release gating

- Missing, uncommitted, unsigned, wrong-key, swapped, cross-tenant or wrong-Attempt receipt: **BLOCKED**. PID absence or lost ACK is **UNKNOWN/HOLD**, not `FAILED_CONFIRMED`.
- A valid source Wait proves a *local process terminal observation*. It does not prove that a networked/external effect was undone, that a Guard Permit was valid at execution time, that the workspace persisted, or that the Sandbox/Compute allocation was physically released.
- The existing `postfault.Verify` also requires a **fresh source-owned, journal-persisted `agentd.inspect` event with incrementing `InspectCount` and `JournalVersion`**. Draft #108 presently persists the terminal but not that separate fresh inspection event. An invented count is NOT acceptable.
- Even after the new join accepts a complete synthetic fixture, **live G01–G05 remains BLOCKED** until Guard issuer/PEP, authenticated source mTLS and independent key lifecycle, original Run/Attempt/Permit journal references, real Sandbox/Sentinel readback, source postfault inspection counts, provider UID absence and cost FINAL are proven.
- CLI and production runtime are NOT yet wired to call this extra source gate; the helper is an independent read-only opt-in verification primitive for future trusted integration. No protected command execution, PR merge or resource release is granted by it.

## CI and evidence standard

The isolated `G05 original AgentD Wait source join (non-production)` workflow runs exact HEAD, pinned Go version, formatting/module verification and `go test -race -count=1 -run '^TestG05' ./internal/postfault`. Tests use independently signed fixtures (not deployed AgentD), including re-signed foreign Run/tenant/Attempt/Permit/process, missing/mismatched digest and invalid source time. True OS process and PostgreSQL crash tests are run separately under #108; do not combine synthetic fixture PASS with OS tests from another commit and call that a full same-Run end-to-end success.

See ACP Issues [#70](https://github.com/avaargsh/agent-control-panel/issues/70), [#71](https://github.com/avaargsh/agent-control-panel/issues/71), [#72](https://github.com/avaargsh/agent-control-panel/issues/72).
