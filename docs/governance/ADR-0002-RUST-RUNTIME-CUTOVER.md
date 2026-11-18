# ADR-0002: Single-writer Rust Runtime migration (proposal)

Status: **PROPOSED / NOT RATIFIED**. Date: 2026-11-03.
Tracking: https://github.com/avaargsh/agent-control-panel/issues/3
Rust implementation: https://github.com/avaargsh/agent-infra/pull/9
Go reference: https://github.com/avaargsh/agent-runtime/pull/6
Machine-readable status: `governance/contract-registry.v0.3.json` → `runtime_migration`.

## Context and authority

The Rust `agent-infra` project has merged its SQLx/PostgreSQL RunStore slice into `main` (PR #9). This is a **tested persistence component**, not a verified replacement for the Go Temporal Runtime. The platform v0.3 governance candidate continues to designate `agent-runtime` as the sole **proposed** Run/Task/Attempt writer. The governance registry does not attest an actual production route.

A migration must not introduce a second writer for the same RunIntent or Run. Neither successful PostgreSQL unit/integration tests nor a merged Rust PR is authorization to divert live RunIntent traffic. Both runtime repos retain their separate design authority during development, without a live dual-writer grant.

## Proposed cutover protocol

1. **Freeze the wire contract and caller identity.** ACP remains the RunIntent producer; the selected Runtime accepts immutable tenant/project/Agent/Release/Session/input bindings and assigns `run_id` and `agent-run/v1/<run_id>`. The source input must be retrievable by an immutable versioned reference and verified digest, not reconstructed from a hash.
2. **Pin a runtime route before the first dispatch.** The ACP dispatch record must durably bind `run_intent_id`, request digest, target Runtime endpoint, contract version and route epoch using CAS, before network I/O. A retry or a lost ACK must reuse the same target and immutable bindings. Do not fail over an unresolved RunIntent to the other Runtime.
3. **Keep each in-flight Run with its original authority.** During an epoch switch, route only **new, not-yet-dispatched** RunIntents to Rust. Go retains authority for previously accepted Go Runs until they terminate or undergo a separately proved migration. A shared database, simultaneous writes or simple load-balancer split without durable per-intent routing is prohibited.
4. **Make absence conservative.** A missing row is `ABSENT_UNCERTAIN` unless the selected Runtime supplies an authenticated durable idempotency barrier proving final absence. UNKNOWN response, network timeout or an in-flight transaction cannot trigger cross-Runtime re-acceptance.
5. **Preserve protected effect ownership.** Rust persists stable Decision invocation IDs and Guard submission keys before outbound calls. EngageGuard owns action approval, Permit, operation ID, journal and action UNKNOWN; Compute owns provider mutation UNKNOWN. Neither Runtime directly retries an uncertain protected side effect.
6. **Rollback by routing new work only.** Rollback stops routing new intents to Rust after a fence/epoch change, while Rust continues to resolve its already accepted Runs. Outstanding Rust unknowns stay pinned to Rust. Never replay them into Go to claim the same idempotency key.

## Promotion prerequisites (all required)

- Go and Rust consumer-driven protocol fixtures: tenant/project authorization, immutable digest and input_ref, stable Run ID/Workflow ID mapping, equivalent replay and conflict behavior.
- PostgreSQL concurrent acceptance, Outbox atomicity, schema upgrade/restore, deterministic transition replay and process SIGKILL/restart tests on both paths.
- Real authenticated ACP↔Rust and ACP↔Go network paths, revocation/rotation behavior, signed or otherwise authoritative receipt attribution, and lost network ACK after durable commit.
- Selected workflow-engine adapter: real worker restart, replay, cancellation, outbox redelivery, lease fencing, version rollout, and recovery without double execution.
- Decision Core/Framework Adapter split, Guard one-time Permit/Intent/Receipt/UNKNOWN and Compute inspect-only recovery validated at service boundaries.
- A recorded cutover rehearsal with route epoch persistence, ambiguous ACK, rollback while in-flight, audit correlation, operator signoff and explicit environment evidence.

## Evidence grading

`测试通过` applies to the Rust SQLx/PostgreSQL slice only: PR #9 source head `545269c6c1a9fa486e27286ddef85b1bceac4cc2`; CI https://github.com/avaargsh/agent-infra/actions/runs/41593065180.

`当前未知` remains the evidence status for trusted ACP transport, workflow-engine parity, full process restart recovery, six-service Golden Path and production cutover. No item has been shown to pass a real cross-service deployment test here.

## Adoption decision

Until a cross-repository ADR records approval, `cutover_authorized=false`, G01 stays blocked and the v0.3 registry must reject any implicit promotion to two active writers. Migration status updates must pin a source commit, CI run, tested environment and concrete behavior; historical README checkboxes or PR descriptions are not current-HEAD verification.
