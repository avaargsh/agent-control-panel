# AgentD original command Inspect — source-owned candidate

**Status:** Draft #108 on the independent Sandbox PostgreSQL module. Tests use actual Linux processes, `os.Process.Wait`, PostgreSQL 16, Ed25519 signatures, worker `SIGKILL` and a fresh inspector connection. **This does not enable command dispatch in production.** Parent PRs #81/#83/#84/#102 are also still Draft.

## Authority / storage

`migrations/0013_agentd_attempt_terminal.sql` creates TWO new append-only, owner-only tables in the **independent Sandbox Service database**, never ACP's RunIntent database:

1. `sandbox_agentd_attempts`: original immutable `tenant_id / run_id / runtime_attempt_id / sandbox_uid / command_id / attempt_id / provider_command_uid / request_digest / guard_permit_id / permit_epoch / process_pid / process_start_ticks / host_boot_id`. `dispatch_count = 1`, original state `UNKNOWN`. Unique tenant+Sandbox+Command forbids a silently substituted attempt.
2. `sandbox_agentd_terminal_receipts`: exactly one terminal fact per original attempt; source-owned raw Ed25519 signed `agentd.os.wait` payload + detached signature + raw SHA256 digest, atomically committed. Ordinary row UPDATE/DELETE are prohibited. The privileged database owner can still bypass triggers: migration ownership and production signer custody require independent review.

The existing `PERMIT_UNAVAILABLE`/pre-Permit tables remain completely separate and **cannot** be interpreted as a dispatched command. Migration 0013 grants no new runtime roles and has default-deny RLS with no non-owner policy. The test harness uses an isolated owner to inject a command identity only after it has launched a disposable OS process. This is not a supported, externally authenticated registration API.

## Authoritative operation

`CaptureLinuxProcessIdentity(pid)` captures the Linux kernel Boot ID and `/proc/<pid>/stat` start-time tick from the originally launched process. `InspectCommand(ctx, db, expectedRef, trustedAgentDPublicKey)` compares all original columns in a repeatable-read transaction, probes the exact live process without trusting PID alone, and reads the **original committed Wait receipt**:

- If no source terminal exists: `UNKNOWN/HOLD`, no `ExitReceiptDigest`, `CanRetry=false`, `CanDeclareReleased=false`. **No inference from missing PID, timeout, lost ACK, SIGKILL or reused PID.**
- If a real `os.ProcessState` from `Wait` was durably recorded by the source supervisor: `EXITED` for exit 0 or `FAILED_CONFIRMED` for nonzero exit/signal. It returns the stored signature, raw payload and digest, with `HOLD` for any resource release and no automatic command retry.
- If signer, hash, original Run/Attempt/UID/Permit binding or original record is invalid: fail closed. The trust key MUST be configured independently of the database or untrusted request.
- `RecordWaitOutcome` accepts only an actual `*os.ProcessState` from the original PID, rechecks original journal identity under the source transaction, and INSERTs one terminal receipt. Lost ACK after COMMIT is replay-safe: new inspector reads the first immutable receipt; the effect is not repeated.

## What the real CI proves

`AgentD original-command Inspect (non-production)` runs exact candidate HEAD, Go 1.27.4, PostgreSQL 16 and `go test -p 1 -race -count=1 -v ./agentd`. It starts genuine disposable shell/sleep commands under OS test control, captures `/proc` identity, persists original attempts, and tests:

- OS Wait committed → ACK lost → *new* DB pool retrieves the signed original terminal and does not re-dispatch.
- Worker process SIGKILL **before** source terminal commit → fresh process returns `UNKNOWN/HOLD`, even when the command process eventually disappears.
- Worker process SIGKILL **after** source terminal commit → fresh process returns the same signed `FAILED_CONFIRMED` with dispatch count fixed at one.
- Wrong tenant, Run, attempt, process start tick, Permit epoch, missing attempt, untrusted key, immutable-row UPDATE and repeat receipt / inspection fail-closed.
- Process-liveness observation is diagnostic only, not authority to declare completion.

The source private key in CI is **ephemeral test data**, transferred to a disposable child process only to sign real test Wait results. It is NOT a deployed secret, production signing flow or proof of Guard approval.

## Same-Run G05 cross-service gate — required contract, NOT yet complete

The next real authenticated service path must be:

```
ACP accepted Run / RuntimeAttempt / original request hash
   -> Guard issuer + executor PEP validates PermitID/Epoch and command action digest
   -> Sandbox/AgentD source registers exactly ONE allowed attempt and original PID identity
   -> AgentD source Wait -> signed immutable terminal commit (or UNKNOWN/HOLD)
   -> AgentD InspectCommand(original RunID+CommandID+AttemptID) -> original terminal digest
   -> AgentD source persists and signs an Inspect *journal event* (source revision and inspect count)
   -> ACP G05 verifier receives the original source bytes via authenticated transport
      and compares same Tenant/Run/Attempt/Provider UID/Permit epoch/CommandID and SHA256
   -> Runtime/Guard/Sandbox independent signed postfault inspections
   -> only then Guard settlement -> Sandbox/Compute physical absence -> cost FINAL
```

**Unimplemented on this Draft**: a trusted Guard issuer / executor PEP; authenticated AgentD attempt registration; a source-owned durable `InspectCount`/inspection event chain; production mTLS transport and independent trust anchor; same-Run postfault bundle wire adapter; live SandboxLease continuity; actual Guard authorization revalidation, physical Sandbox/Compute release, cost FINAL. The root ACP `postfault.Verify` requires increasing `InspectCount` and source `agentd.inspect`, so a terminal receipt alone MUST NOT be passed off as that independently journaled inspection. The G01–G05 release gate MUST remain **BLOCKED** until all requirements are demonstrated against one actual original Run.

See ACP Issues [#70](https://github.com/avaargsh/agent-control-panel/issues/70)–[#72](https://github.com/avaargsh/agent-control-panel/issues/72), Draft [#91](https://github.com/avaargsh/agent-control-panel/pull/91), [#105](https://github.com/avaargsh/agent-control-panel/pull/105) and [#106](https://github.com/avaargsh/agent-control-panel/pull/106).
