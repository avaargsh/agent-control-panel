# G05 AgentD authenticated mTLS evidence consumer — Draft #114

**Scope:** ACP read-only client and verifier, stacked on [#112](https://github.com/avaargsh/agent-control-panel/pull/112). The **source-owned** server contract and real source PostgreSQL/OS Wait tests live in [AgentD Draft #113](https://github.com/avaargsh/agent-control-panel/pull/113) (on #111/#108). Neither source nor consumer is a new control plane, a Guard Permit issuer, an executor, or an authority to release Sandbox/Compute.

## Caller input must be independent source truth

`postfault.FetchAndVerifyAgentDEvidence` accepts:
- `Bundle`: independently signed pre/postfault Runtime, Sandbox, AgentD, Guard observations with the **accepted** original ACP Run binding.
- `ExpectedAgentDWait`: exact original tenant, Run, RuntimeAttempt, SandboxUID, CommandID, AttemptID, provider command UID, request digest, original PID/start ticks/boot ID, and Guard PermitID/Epoch/Operation from accepted ACP/Guard state; **never copied from AgentD response**.
- `keys`: externally provisioned Ed25519 public keys for all four source authorities.
- `TrustedAgentDInspectHead`: exact source count, journal version and SHA256 head, pinned independently of the candidate source database, export response and the LLM.
- `endpoint` and `credentials`: an independently configured source URL and client TLS credentials with explicit server CA roots and one cert matching the original Tenant/Run evidence-reader URI.

If any of these are absent or untrusted, the operation **fails closed**.

## Wire read contract

`POST https://<trusted-agentd-host>/v1/agentd/evidence:read` sends canonical JSON with the full original `ref`. The client requires TLS 1.3, server certificate verification under an explicit independent root pool, exactly one evidence-reader client cert, original Tenant/Run URI SAN and a verified TLS peer chain. No HTTP, redirects, proxy fallback, caller-selected alternate path, query string or URL userinfo. Timeouts are bounded, keepalives disabled and source response size capped.

The response is the exact source-owned wire version `acp.agentd-evidence-export/v1`:
- Original exact immutable Ref (must equal the independently expected Ref).
- Full consecutive AgentD signed `agentd.inspect` chain (max 256 events per non-paginated response), with detached original Ed25519 signatures, canonical source payloads and raw SHA256 digest.
- The independently pinned exact trusted Head, **not a new source self-asserted Head**.
- A terminal `agentd.os.wait` signed source payload **only if** the final original Inspect is terminal. `UNKNOWN/HOLD` is an unresolved recovery condition and is never a successful G05 proof.
- `CanRetry=false`, `NextAction=HOLD`; any assertion of retry is rejected.

The reader rejects oversized or malformed/noncanonical/duplicate JSON, an untrusted response status/cache policy, missing Wait, mismatched original Run/Attempt/Guard Permit, altered signature/digest, stale Head, missing chain tail, wrong source state and invalid source clock order. Then, with **no legacy fallback**, it invokes `VerifyWithAgentDSourceJournal`, which independently verifies the eight source-signed G05 observations, true signed Wait, complete source Inspect chain and before/after accepted-Run continuity.

## Tests and what they do NOT prove

The dedicated root CI runs Go 1.27.4, exact candidate HEAD, strict gofmt/module checks, `go test -race -count=1 -run '^TestG05MTLSConsumer' ./internal/postfault` and vet. It starts a **real mutual TLS server and client** with ephemeral X.509/Ed25519 CA and authorized URI SANs, but that server is a **contract test fake responding with independently signed test fixtures**, not the deployed Sandbox/AgentD server. The producer's actual OS Wait, SIGKILL, PostgreSQL journal and real mTLS read handler are independently tested on Draft #113; these independent successes are **not equivalent** to a complete same-Run cross-service production test.

**Still blocking G01–G05 production readiness:** no real trusted client WorkloadIdentity provisioning, source signer/key rotation/Revocation, out-of-band Head store and ACP Run/Guard accepted identity adapters, authenticated Guard issuer/executor PEP, automatic source owner receipt aggregation from Runtime/Sandbox/Guard, real provider CommandUID settlement, physical Sandbox/Compute absence, cost FINAL, nor independent human security signoff. **Do not merge into main** from this read-only test gate. A verified source certificate and AgentD terminal receipt do not authorize command retries or resource release.
