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

**AgentD fresh inspect counter fence:** `agentd/after_recovery.inspect_count` must be **strictly greater** than `agentd/before_fault.inspect_count` for the same CommandID, AttemptID and ProviderCommandUID. Merely reporting `inspect_count > 0`, a later journal revision, `source=agentd.inspect` and a terminal receipt is insufficient: an already-inspected pre-fault UNKNOWN might carry a stale positive count while an unrelated journal event advances revision. Signed test fixtures reproduce that false positive (RED) and verify a later distinct count is accepted after repair (GREEN). The dedicated local-postfault CI requires both tests, but it does **not** produce externally authenticated AgentD inspection receipts or authorize retry. Failure to increment stays UNKNOWN/HOLD, never terminal success.

**Signed workspace and pre-fault UNKNOWN consistency:** The Sandbox root path in signed before/after evidence must be an absolute, lexically canonical Linux pathname **other than `/`**, without `..`, `.` aliases, duplicate separators, trailing separators, backslashes or embedded control bytes. Otherwise equality of signed path strings could misrepresent the directory being claimed. A canonical pathname is only a *statement-format prerequisite*; it is **not proof of real inode/mount identity, symlink freedom or byte persistence**, which require independent Sandbox/AgentD readback. Separately, an AgentD command in pre-fault `UNKNOWN` must have **no terminal exit-receipt digest**. A contradictory pre-fault record cannot be repaired merely by signing a new post-fault journal revision or increasing InspectCount. Both invariants have signed-fixture RED tests, minimal checker fixes, and mandatory explicit coverage in the local postfault CI; these tests remain non-production contract evidence.

Eight owner-signed before/after observations are required. Each contains the same fault ID and exact Run binding. The postfault verifier rejects missing/duplicate source, bad signature, one signer shared by multiple authorities, cross-Run claim, pre-fault replay, stale timestamp, changed directory bytes, uninspected UNKNOWN, double dispatch, OPEN/stale breaker or invalid Guard Permit.

**Authority distinction:** Runtime breaker epoch/version is a Run safety fence, not the Guard Permit authorization epoch. Both must be checked independently; changed Epoch with the old Permit must fail closed.

## Binary and trust inputs

The verifier reads local evidence and makes a read-only AgentD request over
mutual TLS. It does not write to Runtime, tools, or providers. Install Go as
declared in `go.mod` and run from the repository root.

Only run the check after trusted producers have created the actual observations.
Set `POSTFAULT_DIR` to a secure directory holding those inputs and
`AGENTD_EVIDENCE_ENDPOINT` and `AGENTD_SERVER_NAME` to the approved AgentD HTTPS
origin and expected certificate DNS name, respectively:

```sh
go run ./cmd/acp-postfault-verify \
  --bundle "${POSTFAULT_DIR:?}/proof.json" \
  --expected "$POSTFAULT_DIR/expected.json" \
  --head-acceptance "$POSTFAULT_DIR/head-acceptance.json" \
  --trust-dir "$POSTFAULT_DIR/trust" \
  --agentd-evidence-endpoint "${AGENTD_EVIDENCE_ENDPOINT:?}" \
  --agentd-client-cert "$POSTFAULT_DIR/agentd-client.pem" \
  --agentd-client-key "$POSTFAULT_DIR/agentd-client.key" \
  --agentd-server-ca "$POSTFAULT_DIR/agentd-ca.pem" \
  --agentd-server-name "${AGENTD_SERVER_NAME:?}"
```

The trust directory contains independently provisioned hex Ed25519 public keys
`runtime.pub`, `sandbox.pub`, `agentd.pub`, and `guard.pub`, plus a distinct
`head-acceptor.pub`. Do not source any of these keys from the supplied bundle,
Goal Manifest, or untrusted PR code. Keep the scoped mTLS client key file at mode
0600; never add it to the repository or upload it as a review artifact.

The separate `expected.json` uses `acp.postfault-expected/v2`. It binds the
original Run, fault, Guard operation, AgentD reference and exact Inspect Head.
Source it from trusted acceptance and the real fault injector, not the bundle
or AgentD's response. `head-acceptance.json` signs the complete expected binding
and must come from a separate Head acceptor. See [Head acceptance and AgentD
mTLS](G05-AGENTD-MTLS-CLIENT.md#signed-head-acceptance-preflight-consumer-only-candidate)
for the precise wire format and remaining publisher requirements. Missing
inputs leave G01–G05 on HOLD; the command cannot mint the acceptance or
authorize retry or release.

The bundle has schema acp.postfault-bundle/v1, the original Subject and Fault, plus eight receipt objects with authority, phase, payload_b64 and signature_b64. The exact decoded observation JSON bytes are signed with Ed25519 using domain prefix acp.postfault-observation/v1 followed by a NUL byte. The strict schema acp.postfault-observation/v1 requires one owner-specific observation, original fault ID, matching Run, signed timestamp and owner phase.

Bundle times are constrained to a fault within 30 minutes and signed postfault observations no older than five minutes. This is a reproducibility and replay guard, not by itself proof that a service observed a real provider.

Contract-only checks can run:

    go test -race -count=1 ./internal/postfault ./cmd/acp-postfault-verify

These generate **test-only signing keys** and validate signature/tamper/identity/workspace/journal/epoch rejection. They are NOT evidence of live Sandbox or Guard behavior. Never promote a fixture signature or success message into a cross-service claim.

## Mandatory CI fail-closed behavior

During open-development pull requests, `acp-temporal-golden-path.yml` runs the actual same-Run Worker/Decision/Guard read-only checks, local SIGKILL negative tests and compiles independent verifiers. It prints `EXTENDED_POSTFAULT_GATE=NOT_RUN`; a green PR job is **development contract coverage only**, never full G01–G05 acceptance. The complete signed postfault and lifecycle checks are invoked on `workflow_dispatch` and still **fail CLOSED** with BLOCKED if real owner-issued same-Run proof, independent expected binding or trust anchors are missing. They are not `continue-on-error`, and no synthetic artifact generator is supplied. Production promotion MUST require explicit success of those independent full checks, not inference from green development CI.

At the time of this change the pinned workflow does not build SandboxService/AgentD nor an issuing Guard Permit/PEP, so the expanded full Golden Path **cannot pass**. The legacy Workflow/Decision step may still pass on its own; that is not full business recovery acceptance.

**Security constraint:** Do not expose real signing keys as generic pull_request secrets, especially to forked or unreviewed code. Use independently authenticated and approved service identities with source-pinned code and protected execution environments when wiring producers. Do not substitute green static tests for physical workspace readback or provider command inspection.

## Prerequisites / tracked work

- ACP Issue #70: implement real isolated SandboxService and AgentD CommandJournal; UID/generation fencing, actual reattach/readback, CommandID inspect, same Run.
- ACP Issue #71: scoped Credential Broker and default-deny egress; no token in workspace, stdout or Temporal history.
- ACP Issue #72: independent Verifier/evidence signatures and authorized resource release, provider UID absence; human control for GitHub write effects.
- EngageGuard owner: actual Scoped Permit, issuer and executor PEP with fresh postfault authorization and revocation checks. A read-only Guard mTLS client is not enough.
- All external repositories and images must be pinned to exact SHA/digest, and a separate reviewer must validate the trust roots, fault transcript and complete negative matrix before protected-effect enablement or production promotion.

**Claim boundary:** A Green contract unit suite means the *checker* works. Only externally signed real Sandbox/AgentD/Guard evidence for the same Run can turn the **full** Golden Path GREEN.


## Pinned Sandbox PostgreSQL source boundary (PR #91 ↔ Draft #102)

The `sandbox-db-boundary` job in [the local postfault CI](../../.github/workflows/postfault-local-precursor.yml) checks out **two distinct exact source commits**: its own current #91 HEAD and the standalone Sandbox Journal from Draft #102 at `7abe480007692e370c790957baf12acf923b36c6`. The checkout action is also SHA-pinned. It verifies both source HEADs and Go module checksums, runs #102's real disposable **PostgreSQL 16** migrations/least-privileged `sandboxctl inspect` demo, and securely tears down the one-off Docker database. This is **cross-source execution with actual SQL and authenticated reader**, not an in-memory or source-signature fixture.

The test parses the read-only JSON from PostgreSQL and asserts that the Lease and Command have exactly the same fixture Tenant, Run and Runtime Attempt, the lease state is `WAITING_FOR_PERMIT`, the command is `PERMIT_UNAVAILABLE`, the source label is `UNATTESTED_DB_SNAPSHOT` and all dispatch, retry, success and release authority fields remain false. It then passes the actual raw snapshot to `acp-postfault-verify` as a proposed signed bundle and **requires explicit rejection** as an invalid recovery bundle. This prevents a successful local database inspection from being silently promoted into an AgentD exit or workspace persistence receipt. CI prints `SANDBOX_SOURCE_BOUNDARY=PASS; REAL_SIGNED_RUNTIME_SANDBOX_AGENTD_GUARD_PROOF=NOT_VERIFIED` only when the negative boundary holds.

**Critical scope limits:** This exercises a *separate synthetic pre-Permit Run* from #102, not the canonical live Run in the Temporal Golden Path. It creates no SandboxLease, Guard Permit, AgentD side effect, live `UNKNOWN` inspection, terminal receipt or physical release. Source pinning fixes the repository tree but the demo's `postgres:16-alpine` image is still tag-based, so exact image digest provenance must be established before treating the experiment as fully reproducible production evidence. The current #102 branch is Draft. **The full Golden Path's missing independently signed, same-Run Sandbox/AgentD/Guard/Runtime producers remains mandatory BLOCKED.**

The next authority-producing integration must use owner-controlled service credentials and an independently provisioned trust root to bind an actual Sandbox UID/generation/workspace readback and an **original, durable `UNKNOWN` CommandID/AttemptID** to a new authenticated `InspectCommand` result without repeating dispatch. AgentD must durably own the terminal receipt/journal revision; no ACP test fixture, `sandboxctl` snapshot, model decision or client-provided signature may substitute.

## Local physical workspace crash precursor (PR #92)

Draft [#92](https://github.com/avaargsh/agent-control-panel/pull/92) adds a **real Linux OS-process SIGKILL experiment** inside the disposable Go test binary. It is a necessary lower-level storage/process continuity check, **not** the full SandboxService integration required above.

The first fresh process opens an owner-private workspace directory using Linux `openat` and `O_NOFOLLOW`, creates a sentinel file and a durable workspace-binding JSON record with exclusive creation, flushes file contents and directory metadata to disk, then emits its observation. The parent process sends actual SIGKILL and verifies the OS termination signal. A second independent process opens the same directory, verifies the original device/inode, re-reads the durable metadata and physical sentinel bytes, and compares SHA256 plus Tenant/Run/Lease/SandboxUID/Workspace/generation bindings against the original observation.

The negative matrix deliberately modifies the real filesystem or expected authority binding between processes: changed sentinel bytes, replacing the directory while copying identical files, replacing a sentinel with a symlink, wrong RunID, stale generation and wrong SandboxUID must all fail. No mock provider response or in-memory replay can satisfy these assertions.

Reproduce this **local-only** precursor using:

```sh
go test -race -count=1 -v -run '^TestPhysicalWorkspace(SurvivesWorkerSIGKILL|RecoveryRejectsCorruptionAndStaleBinding)$' ./internal/postfault
```

The existing ACP Temporal Golden Path CI now also invokes this specific test explicitly **before** the mandatory source-signed full recovery gate. A local PASS does **not** create Sandbox/AgentD/Guard authority receipts, attest a KVM/Pod mount, prove UID lease renewal, reconcile a real externally executed command, or revalidate a genuine Guard Permit. The separate full-evidence dispatch must still report **BLOCKED** until #70/#71/#72 deliver those real producers.


### Disposable local filesystem boundary regressions (2026-11-22)

The **test-only** Linux workspace inspector now resolves the absolute root one directory component at a time via directory handles and `O_NOFOLLOW`, rejecting parent symlinks and non-canonical `..` components. Its child-file read only accepts a single relative filename, denying absolute paths, `../`, embedded separators and symlink substitution. An additional concurrent symlink-swap test asserts that a successful read never returns bytes from an external file. The readback also rejects multi-link regular files (`st_nlink != 1`): a sibling tenant's hard-linked inode must not be read merely because `O_NOFOLLOW` accepts it. These checks exercise a local disposable helper, **not** a deployed AgentD filesystem API, a mount-namespace sandbox or a source-signed producer. The real SandboxService/AgentD egress, filesystem traversal and execution permissions remain a separate blocked acceptance gate.


## Disposable external OS-command lost-ACK precursor (PR #92)

This **Linux test-only** experiment extends the physical workspace SIGKILL probe without creating or forging an AgentD authority. A fresh child of the Go test binary first persists an explicit `UNKNOWN`, `dispatch_count=1` local record (with Tenant/Run/SandboxUID/CommandID/AttemptID, original workspace device/inode and expected SHA256), fsyncs it, and invokes a real disposable `/bin/sh -c 'printf ...'` process. The command's actual stdout is written once into an owner-private workspace file, then file and directory are fsynced. A harness readiness line is **not a trusted command terminal ACK**. The outer test sends SIGKILL to the actual child process and verifies the kernel-reported termination signal.

A newly launched, separate OS inspector process opens the original workspace through the existing `openat`/`O_NOFOLLOW` path, re-reads both the durable local journal and actual command side-effect bytes, verifies the exact original identities/digest, and **continues to return UNKNOWN, no terminal receipt, can_retry=false, can_declare_success=false**. It does not launch a second command or advance a source-owned journal. Negative cases reject a missing or duplicated side effect, forged terminal receipt, forged second dispatch, wrong Run/Attempt/CommandID, swapped directory with identical file bytes and symlinked effect. The acceptance requires both positive and negative assertions, in addition to prior workspace-only checks.

Reproduce:
```sh
go test -race -count=1 -v -run '^(TestLocalUnknownCommandAfterSIGKILLRemainsBlocked|TestLocalUnknownCommandRejectsForgedReconciliation)$' ./internal/postfault
```

**Do not promote this precursor as a full recovery proof.** The local file named journal is test-generated and unauthenticated; actual external process exit may have occurred, but no independent AgentD/Guard signed terminal receipt exists. It proves the conservative rule: visible side effects following a lost ACK do **not** authorize blind retry or success declaration. Production requires a real SandboxService-owned journal and separately authenticated AgentD InspectCommand response for the same Run, fresh Guard epoch/Permit and independent evidence authority. The full-evidence dispatch remains **BLOCKED** until these are available; PR contract checks explicitly report **NOT_RUN**.
