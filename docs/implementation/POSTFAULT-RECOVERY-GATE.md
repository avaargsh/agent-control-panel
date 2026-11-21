# Post-fault Golden Path: complete recovery acceptance gate

**Status: contract verifier implemented as a candidate; real Sandbox/AgentD/Guard evidence production is BLOCKED.**

The existing Golden Path proves same-Run OAuth, Runtime/Temporal Worker SIGKILL/Decision continuation and source-pinned Guard mTLS read-only behavior. It does **not** yet prove real Sandbox directory persistence, protected external command resolution, Guard Permit issuance or postfault authorization epochs. This page specifies the extra mandatory gate; historical Workflow GREEN is not full Agent recovery GREEN.

## Single-Run scenario

1. ACP accepts an immutable tenant-bound RunIntent. Runtime assigns the canonical Run/Workflow identity. Each independently trusted service owns its own authoritative records.
2. Allocate an isolated SandboxLease and workspace. AgentD writes and actually re-reads a known sentinel file. Before the fault, record the Sandbox UID, lease ID/generation, workspace ID/root/path and SHA256 of actual sentinel bytes.
3. An approved Guard Permit and trusted executor PEP must bind the command and Guard operation. Start a command with one durable CommandID/AttemptID and record one dispatch. Lose its ACK and persist UNKNOWN in the authoritative Command Journal. Do **not** invoke StartCommand again.
4. Inject real Worker SIGKILL after a durable checkpoint, preserving the original provider and database. Restart a new Worker and recover the **same** Run/Workflow/checkpoint.
5. Inspect SandboxService and AgentD through real authenticated APIs. Reopen the original workspace, re-read identical sentinel bytes, and reconcile UNKNOWN by the **original** CommandID. Require an authoritative terminal exit receipt and a strictly newer journal revision; unresolved UNKNOWN must block.
6. Re-read Runtime's RUN breaker state/epoch/version and Guard's Permit authorization/epoch under **separate** identities after fault. A CLOSED breaker does not grant Permit. An OPEN breaker, rotated/stale epoch, revoked/expired Permit or mismatched action digest blocks new protected execution.
7. Release and provider-UID absence, credential revocation and cost FINAL require a later **separate** cleanup gate; the current version does not verify those effects.

## Evidence ownership and negative tests

| Independent signer | Before-fault signed facts | Required fresh after-recovery facts |
|---|---|---|
| Runtime | Tenant/Run/Session/Workflow/GuardOperation binding; history and checkpoint digests; CLOSED breaker epoch/version | Same binding and checkpoint, Workflow recovered, CLOSED breaker under same epoch, updated valid version |
| SandboxService | Lease ID, Sandbox UID, workspace ID/root, generation, sentinel path/hash, actual byte readback, ACTIVE state | Exact lease, UID, generation, root and SHA256 preserved after actual readback; replacement/missing bytes/mount block |
| AgentD | CommandID, AttemptID, journal version, one dispatch, durable UNKNOWN | Same command, no new dispatch, strictly later journal version, InspectCommand evidence and EXITED or FAILED_CONFIRMED with SHA256 receipt |
| EngageGuard | Operation-bound PermitID, authorization epoch, ActionHash and VALID status | Separately refreshed VALID Permit with identical epoch/action binding, never a cached pre-fault approval |

Eight owner-signed before/after observations are required. Each contains the same fault ID and exact Run binding. The postfault verifier rejects missing/duplicate source, bad signature, one signer shared by multiple authorities, cross-Run claim, pre-fault replay, stale timestamp, changed directory bytes, uninspected UNKNOWN, double dispatch, OPEN/stale breaker or invalid Guard Permit.

**Authority distinction:** Runtime breaker epoch/version is a Run safety fence, not the Guard Permit authorization epoch. Both must be checked independently; changed Epoch with the old Permit must fail closed.

## Binary and trust inputs

The verifier executable is built from cmd/acp-postfault-verify. It only reads a bounded JSON bundle and externally supplied Ed25519 public keys; it has no runtime/tool/provider write capability.

Run (only after the trusted producers have created actual observations):

    go run ./cmd/acp-postfault-verify --bundle "$RUNNER_TEMP/acp-postfault/proof.json" --expected "$RUNNER_TEMP/acp-postfault/expected.json" --trust-dir "$RUNNER_TEMP/acp-postfault/trust"

The trust directory must contain four distinct, independently provisioned **hex-encoded Ed25519 public keys**, named runtime.pub, sandbox.pub, agentd.pub and guard.pub. These keys must NOT be taken from the user-supplied bundle, the ACP Goal Manifest or untrusted PR code.

The separate expected.json file must be created by the trusted ACP/Runtime acceptance test and actual fault injector, **not** copied from the bundle. It uses schema acp.postfault-expected/v1 and contains subject (original tenant/run/session/workflow/guard_operation) plus fault_id and fault_at. All values must match the signed receipts and recorded injection time exactly; evidence for a different Run cannot pass.

The bundle has schema acp.postfault-bundle/v1, the original Subject and Fault, plus eight receipt objects with authority, phase, payload_b64 and signature_b64. The exact decoded observation JSON bytes are signed with Ed25519 using domain prefix acp.postfault-observation/v1 followed by a NUL byte. The strict schema acp.postfault-observation/v1 requires one owner-specific observation, original fault ID, matching Run, signed timestamp and owner phase.

Bundle times are constrained to a fault within 30 minutes and signed postfault observations no older than five minutes. This is a reproducibility and replay guard, not by itself proof that a service observed a real provider.

Contract-only checks can run:

    go test -race -count=1 ./internal/postfault ./cmd/acp-postfault-verify

These generate **test-only signing keys** and validate signature/tamper/identity/workspace/journal/epoch rejection. They are NOT evidence of live Sandbox or Guard behavior. Never promote a fixture signature or success message into a cross-service claim.

## Mandatory CI fail-closed behavior

The existing acp-temporal-golden-path.yml now builds the verifier **after** the existing real Worker/Decision recovery stage. Its final required step reads the same-job RUNNER_TEMP independently accepted expected Run/fault binding, signed postfault proof and external trust directory. If no real producers have supplied both, the workflow **fails with an explicit BLOCKED error**. There is no continue-on-error and no synthetic artifact generator.

At the time of this change the pinned workflow does not build SandboxService/AgentD nor an issuing Guard Permit/PEP, so the expanded full Golden Path **cannot pass**. The legacy Workflow/Decision step may still pass on its own; that is not full business recovery acceptance.

**Security constraint:** Do not expose real signing keys as generic pull_request secrets, especially to forked or unreviewed code. Use independently authenticated and approved service identities with source-pinned code and protected execution environments when wiring producers. Do not substitute green static tests for physical workspace readback or provider command inspection.

## Prerequisites / tracked work

- ACP Issue #70: implement real isolated SandboxService and AgentD CommandJournal; UID/generation fencing, actual reattach/readback, CommandID inspect, same Run.
- ACP Issue #71: scoped Credential Broker and default-deny egress; no token in workspace, stdout or Temporal history.
- ACP Issue #72: independent Verifier/evidence signatures and authorized resource release, provider UID absence; human control for GitHub write effects.
- EngageGuard owner: actual Scoped Permit, issuer and executor PEP with fresh postfault authorization and revocation checks. A read-only Guard mTLS client is not enough.
- All external repositories and images must be pinned to exact SHA/digest, and a separate reviewer must validate the trust roots, fault transcript and complete negative matrix before any main or production promotion.

**Claim boundary:** A Green contract unit suite means the *checker* works. Only externally signed real Sandbox/AgentD/Guard evidence for the same Run can turn the **full** Golden Path GREEN.


## Local physical workspace crash precursor (PR #92)

Draft [#92](https://github.com/avaargsh/agent-control-panel/pull/92) adds a **real Linux OS-process SIGKILL experiment** inside the disposable Go test binary. It is a necessary lower-level storage/process continuity check, **not** the full SandboxService integration required above.

The first fresh process opens an owner-private workspace directory using Linux `openat` and `O_NOFOLLOW`, creates a sentinel file and a durable workspace-binding JSON record with exclusive creation, flushes file contents and directory metadata to disk, then emits its observation. The parent process sends actual SIGKILL and verifies the OS termination signal. A second independent process opens the same directory, verifies the original device/inode, re-reads the durable metadata and physical sentinel bytes, and compares SHA256 plus Tenant/Run/Lease/SandboxUID/Workspace/generation bindings against the original observation.

The negative matrix deliberately modifies the real filesystem or expected authority binding between processes: changed sentinel bytes, replacing the directory while copying identical files, replacing a sentinel with a symlink, wrong RunID, stale generation and wrong SandboxUID must all fail. No mock provider response or in-memory replay can satisfy these assertions.

Reproduce this **local-only** precursor using:

```sh
go test -race -count=1 -v -run '^TestPhysicalWorkspace(SurvivesWorkerSIGKILL|RecoveryRejectsCorruptionAndStaleBinding)$' ./internal/postfault
```

The existing ACP Temporal Golden Path CI now also invokes this specific test explicitly **before** the mandatory source-signed full recovery gate. A local PASS does **not** create Sandbox/AgentD/Guard authority receipts, attest a KVM/Pod mount, prove UID lease renewal, reconcile a real externally executed command, or revalidate a genuine Guard Permit. The final step must still report **BLOCKED** until #70/#71/#72 deliver those real producers.
