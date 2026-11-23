# G05 AgentD authenticated mTLS evidence consumer — unified Draft #119

**Scope:** ACP read-only client and verifier, stacked on [#112](https://github.com/avaargsh/agent-control-panel/pull/112). The **source-owned** server contract and real source PostgreSQL/OS Wait tests live in [AgentD Draft #113](https://github.com/avaargsh/agent-control-panel/pull/113) (on #111/#108). Neither source nor consumer is a new control plane, a Guard Permit issuer, an executor, or an authority to release Sandbox/Compute.

## Caller input must be independent source truth

`postfault.FetchAndVerifyAgentDEvidence` is now a **thin TLS adapter** that delegates all JSON/source-signature/Head verification to the canonical `postfault.AgentDEvidenceClient.Read/Verify` from Draft #112. There must be no second independent wire parser. It accepts:
- `Bundle`: independently signed pre/postfault Runtime, Sandbox, AgentD, Guard observations with the **accepted** original ACP Run binding.
- `ExpectedAgentDWait`: exact original tenant, Run, RuntimeAttempt, SandboxUID, CommandID, AttemptID, provider command UID, request digest, original PID/start ticks/boot ID, and Guard PermitID/Epoch/Operation from accepted ACP/Guard state; **never copied from AgentD response**.
- `keys`: externally provisioned Ed25519 public keys for all four source authorities.
- `TrustedAgentDInspectHead`: exact source count, journal version and SHA256 head, pinned independently of the candidate source database, export response and the LLM.
- `endpoint` and `credentials`: an independently configured source URL and client TLS credentials with explicit server CA roots and one cert matching the original Tenant/Run evidence-reader URI.

If any of these are absent or untrusted, the operation **fails closed**.

## Wire read contract

`POST https://<trusted-agentd-host>/v1/agentd/evidence:read` sends canonical JSON with the full original `ref`. The client requires TLS 1.3, server certificate verification under an explicit independent root pool, exactly one evidence-reader client cert, original Tenant/Run URI SAN and a verified TLS peer chain. No HTTP, redirects, proxy fallback, caller-selected alternate path, query string or URL userinfo. Timeouts are bounded, keepalives disabled and source response size capped.

**Candidate server-workload identity pin (consumer-side):** the evidence reader now requires the HTTPS server certificate to contain **exactly one URI SAN** equal to `spiffe://<reader-trust-domain>/role/agentd-evidence-server`. The trust domain comes from the independently configured, original Tenant/Run-scoped client certificate, not the AgentD response or a model-generated argument. TLS 1.3, independently supplied CA roots, DNS hostname verification and the server-authenticated chain remain mandatory. This denies a different workload certificate signed by the same CA (including no URI, wrong service role or foreign trust domain) **during the handshake, before the immutable Run/Guard/Attempt evidence request is sent**. The Sandbox/AgentD server owner must provision this exact candidate URI in its leaf server certificate; the test-only CA and role path do **not** establish an actual SPIRE issuer or production identity lifecycle. Until the owner implements the matching server identity and independent Head distribution, G05 remains HOLD.

The response is the exact source-owned wire version `acp.agentd-evidence-export/v1`:
- Original exact immutable Ref (must equal the independently expected Ref).
- Full consecutive AgentD signed `agentd.inspect` chain (max 256 events per non-paginated response), with detached original Ed25519 signatures, canonical source payloads and raw SHA256 digest.
- The independently pinned exact trusted Head, **not a new source self-asserted Head**.
- A terminal `agentd.os.wait` signed source payload **only if** the final original Inspect is terminal. `UNKNOWN/HOLD` is an unresolved recovery condition and is never a successful G05 proof.
- `CanRetry=false`, `NextAction=HOLD`; any assertion of retry is rejected.

The single canonical reader rejects oversized or malformed/noncanonical/duplicate JSON, an untrusted response status/cache policy, missing Wait, mismatched original Run/Attempt/Guard Permit, altered signature/digest, stale Head, missing chain tail, wrong source state and invalid source clock order. Then, with **no legacy fallback**, it invokes `VerifyWithAgentDSourceJournal`, which independently verifies the eight source-signed G05 observations, true signed Wait, complete source Inspect chain and before/after accepted-Run continuity.

## Actual postfault CLI uses the same server identity gate

The `cmd/acp-postfault-verify` entrypoint now uses the existing
`postfault.FetchAndVerifyAgentDEvidence` mTLS adapter instead of constructing
a generic `http.Client` and calling the canonical parser directly.
`--agentd-evidence-endpoint` still accepts the configured HTTPS origin (or
the exact `/v1/agentd/evidence:read` route). The CLI derives that exact route
and rejects alternate paths, URL userinfo, queries and fragments before any
network access. The adapter checks the Tenant/Run-scoped client certificate,
explicit server CA/DNS name and sole AgentD **server** URI SAN during the TLS
handshake, so a same-CA certificate for another service cannot receive the
original Run/Guard/Attempt request. Signatures/Inspect chain remain verified
only by the single canonical reader.

**Head is still not a deployed trusted publisher.** The CLI's
`--expected` file is a user-provided local representation of a supposed
independently accepted Run/fault/AgentD Head. Strict JSON, a pinned digest
and full source signatures cannot authenticate the provenance of that file
or show that the claimed Head is the latest source commit. Production G05
requires an independently authorized, authenticated, anti-rollback
ACP/Guard-bound Head acceptance and publication path. An operator copying
the AgentD HTTP response Head into `--expected` is NOT an independent
trust anchor. Until that producer exists and its keys and ledger are
verified independently, the business Golden Path remains HOLD.

## Tests and what they do NOT prove

The dedicated root CI tests both the canonical verifier and scoped mTLS adapter using Go 1.27.4, exact candidate HEAD, strict gofmt/module checks, `go test -race -count=1 -v -run '^(TestG05MTLSConsumer|TestAgentDEvidenceClient)' ./internal/postfault` and vet. It starts a **real mutual TLS server and client** with ephemeral X.509/Ed25519 CA and authorized URI SANs, but that server is a **contract test fake responding with independently signed test fixtures**, not the deployed Sandbox/AgentD server. A separate exact-SHA-pinned PostgreSQL 16 / actual Linux OS Wait / scoped mTLS source Handler / ACP G05 cross-module integration from #115 is now included in this reconciliation PR. Even this independently verified non-production test is **not equivalent** to deployed same-Run Runtime/Sandbox/AgentD/Guard original postfault production proof.

**Still blocking G01–G05 production readiness:** no real trusted client WorkloadIdentity provisioning, source signer/key rotation/Revocation, out-of-band Head store and ACP Run/Guard accepted identity adapters, authenticated Guard issuer/executor PEP, automatic source owner receipt aggregation from Runtime/Sandbox/Guard, real provider CommandUID settlement, physical Sandbox/Compute absence, cost FINAL, nor independent human security signoff. **Do not merge into main** from this read-only test gate. A verified source certificate and AgentD terminal receipt do not authorize command retries or resource release.


## Canonical-client conflict resolution

This Draft copies the genuinely additional tests/CI/docs and the real source integration from #114/#115 onto the **latest #112** source tree. The two conflicting `internal/postfault/agentd_evidence_client*.go` files are NOT overwritten or concatenated. The only new production file is `agentd_evidence_mtls_client.go` implementing identity-checked, proxy-free TLS transport that delegates to existing canonical `AgentDEvidenceClient.Verify`, and the original #114 test suite now directly uses canonical source wire types and `inspectSourceDigest`. Old Draft #114 remains separate/unmerged until review resolution.

The parent #112's deliberately failing extended Guard Golden Path remains an independent **BLOCKED** production release gate; never weaken it to claim a successful integration. Main is not a merge target.
