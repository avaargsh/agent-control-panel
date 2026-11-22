# G05 original AgentD source InspectCount/JournalVersion join

**Draft #112** (stacked on #110). This is read-only verification in ACP. It does not own or generate inspection events, OS Wait terminal records, Guard Permits, process execution or source database transactions. The separately scoped Sandbox AgentD source Draft [#111](https://github.com/avaargsh/agent-control-panel/pull/111) implements owner-only append-only inspection events over Draft [#108](https://github.com/avaargsh/agent-control-panel/pull/108)'s real OS Wait journal.

## Required unbroken evidence

1. Original ACP accepted Tenant / Run / RuntimeAttempt / SandboxUID / CommandID / AttemptID / Provider UID / request digest, and Guard PermitID/Epoch are pinned **independently of the submitted source evidence**.
2. Existing `VerifyWithAgentDWait` must verify the original source-signed OS Wait and all eight independent Runtime/Sandbox/AgentD/Guard pre/postfault observations. No fallback to the legacy-only verifier is allowed by the new API.
3. The original source signs each canonical `acp.agentd-inspect-event/v1` using a distinct domain, original immutable Ref, `InspectCount`, `JournalVersion`, source state `UNKNOWN|EXITED|FAILED_CONFIRMED`, terminal digest (empty when UNKNOWN), `NextAction=HOLD`, `DispatchCount=1`, `Replayed=false`, and previous original signed payload SHA256.
4. `VerifyWithAgentDSourceJournal` checks the **complete source chain beginning at count 1**, not just two selected observations: every source signature, original Ref and timestamp, incrementing count/version, prior hash and exit digest. It then compares the last before-fault source event to the independently signed AgentD pre-fault snapshot and the final post-fault source event to the postfault snapshot.
5. The final raw source Inspect payload SHA256, count and version must match a separately trusted **pinned Head**. A self-reported Head from the candidate bundle cannot rule out omission of the latest signed event.
6. The OS Wait terminal digest and status must match the fresh inspection source event; otherwise `UNKNOWN/HOLD` remains the only safe outcome. A signed `UNKNOWN` is an auditable unresolved state, **not** a G05 success.
7. Even when all local AgentD receipts are valid, the global G01–G05 path remains **BLOCKED** until source-owner authenticated Guard revalidation, Sandbox workspace continuity, Runtime checkpoint, physical release and cost FINAL evidence are present and checked for the very same Run.

## Limits

- This verifier currently consumes typed signed receipt bytes and independent expected values in tests; it is **not a production mTLS transport adapter** and does not consume authentic events from a live Sandbox service at runtime.
- Source #111 runs actual OS process SIGKILL / PostgreSQL tests, while #112's root tests use independent ephemeral test keys and signed synthetic evidence. These test suites must not be conflated into a single live same-Run end-to-end proof.
- The provider process may have produced external side effects even after a local terminal OS Wait; inspection does not authorize retry or resource release.
- Production still needs a dedicated authenticated AgentD inspect writer role with tenant-bound RLS, trustworthy source keys/key rotation, Guard issuer/PEP and authorization epoch fencing, consistent mTLS identity, trusted independent Head distribution, and verified Sandbox/Compute resource absence.
- Do not mark Draft #111/#112 READY or merge `main` solely because these isolated verifiers pass CI.

Related: [ACP G05 Wait join Draft #110](https://github.com/avaargsh/agent-control-panel/pull/110), [source-owned AgentD inspect Draft #111](https://github.com/avaargsh/agent-control-panel/pull/111), [original postfault gate Draft #91](https://github.com/avaargsh/agent-control-panel/pull/91).
