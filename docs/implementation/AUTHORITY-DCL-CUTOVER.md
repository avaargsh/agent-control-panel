# Proposed ACP Authority DCL cutover contract (#98)

Status: PROPOSED, non-production design only. No new authorization or wire schema is ratified by this document.

## Existing behavior and evidence

The read-only handler in internal/authorityhttp/handler.go attests its reader role before and after catalog reads. #138 adds request cancellation checks; its exact-source Go/PG/race run 45310003768 is green. Issue #98 records an earlier real late-DCL experiment: a privileged grant after the final observation can still produce an authentic signed publication. An extra check cannot make HTTP delivery atomic with arbitrary DBA activity. Repeatable Read alone is not an ACL revocation guarantee.

## Cutover ledger role verification (experimental implementation)

The #151 implementation adds an explicit `VerifyPostgresRole` catalog probe and verified Store entry points. `ObserveVerified` and `ApplyVerified` acquire one pool backend, attest the expected independently authenticated Coordinator/Observer LOGIN on that backend, then perform the ledger operation through that same backend. This avoids accidentally checking one pool identity and executing the ledger operation on another.

This is a bounded defense-in-depth check, **not** a same-snapshot or atomic DCL fence: the role probe and ledger SQL are separate statements, and a privileged actor may commit DCL after the probe. It does not integrate the cutover ledger with the Run Authority or Decision Publication HTTP readers. Issue #98 remains open; no strict revocation-at-response guarantee is claimed. The verified methods must not be used as a substitute for the coordinated stop/drain/change/re-attest/open protocol below.
The catalog probe also rejects reachable privileges outside the three ledger tables: application-table/column reads and writes, sequence access, executable SECURITY DEFINER routines, and CREATE on any non-system schema. The PostgreSQL ACL regression introduces decoy objects and grants each privilege to PUBLIC, then proves fail-closed detection and recovery after revocation. This remains scoped to the Cutover database contract, not a complete arbitrary schema/trigger attestation.

## Scope and ownership

ACP owns catalog evidence and a proposed catalog authority generation. A dedicated operator/migrator identity owns coordinated DCL, not the read-only HTTP login. Guard remains the sole Permit and protected-action authorization owner; its epoch is distinct from the ACP generation and Runtime breaker epoch. No new dispatch, DB role mutation API, or production credentials.

## Alternatives

1. More per-request catalog checks or a single read-only transaction. Useful defense in depth; cannot guarantee a hard cutover against an uncoordinated privileged actor after the last check.
2. A coordinated stop/drain/change/re-attest/open barrier with durable generation. Chosen as the next experimental slice. It requires bounded in-flight work, independently authenticated participants and enforced administrative scope. External DBA bypass remains outside the hard-cutover guarantee and must trigger incident handling.

## Proposed contract

A cutover is keyed by immutable change ID, expected generation, exact role/ACL manifest digest and operator identity. The dedicated database's trusted coordinator owns its durable CAS record.

States: OPEN(g) -> DRAINING(g, change) -> CLOSED(g, change) -> VERIFYING(g+1, change) -> OPEN(g+1). Any unknown outcome stays CLOSED/HOLD; no automatic reopen or generation rollback. Initial missing/untrusted state denies serving. Generation is not a Permit.

Conceptual APIs (not existing endpoints):
- BeginChange(expectedGeneration, changeID, manifestDigest): close new admission and persist intent.
- Drain(changeID): prove every registered serving replica stopped admission and all old admitted requests finished or were cancelled and their serving connections fenced.
- ApplyAndObserve(changeID): operator commits scoped DCL only after drain proof; inspect actual catalog and record observed digest/outcome. Lost ACK requires readback, not blind DCL retry.
- Reopen(changeID, verifiedGeneration): only after fresh independently authenticated reader sessions and exact role attestation satisfy desired manifest, stale pools are closed, and every serving replica accepts the new generation.
- ObserveGeneration(): trusted read-only status; an unavailable coordinator cannot authorize new reads.

Replica admission must be fenced by authoritative state, not a cached heartbeat or best-effort broadcast. Registration, request admission and drain accounting need a common serialization point and generation-scoped identity. A crashed replica is not presumed drained solely because its lease expired: fence access/serving first or remain CLOSED. Bound request work and transport writes; a response already delivered before the barrier is not retractable. Old in-flight responses may already be in transit; consumers must reject stale generation under the agreed freshness contract. The first implementation must prove these semantics with real PG16 and two service processes before introducing wire changes.

Publication consumption: existing v1 signatures are historical source evidence, not revocable permits. Propose a versioned publication generation binding only after Guard contract review. Guard must independently obtain fresh ACP generation/status and validate its own current Permit/action scope at the protected-effect boundary. Do not treat a local ACP generation check as an atomic Guard/PEP effect fence. No cross-service shared database writes.

## Test-first slices

1. Two actual server replicas, separate reader LOGINs and privileged test operator. Positive authenticated Run/Publication controls; barrier after admission on A while B attempts another request. Observe no new success during DRAINING; DCL does not start before A drains. Show exact source and server-side request results, not client timeout alone.
2. Crash/lost ACK at each transition; persisted state and explicit readback must prevent reopen on uncertain DCL. Recreated coordinator and replica cannot reset generation. Reject stale CAS, changed duplicate command, unknown membership and unavailable state.
3. Real committed GRANT/REVOKE including extra table/column/function privilege and restoration, with new connections, actual role checks and fresh authorized positive controls. Show previous connection cannot serve after fence; failure of attestation keeps both replicas closed.
4. Independent consumer contract tests: old authentic signed publication cannot grant fresh authorization after cutover. Demonstrate Guard's independent ownership and deny on unavailable generation; no actual protected tool effect.
5. Measure baseline and added p50/p95/p99 latency, DB pool usage and drain time using documented test load. No unbounded lock or unmeasured production SLA.

## Gates

#98 remains OPEN. #107 server-side main protection remains a separate blocker. Exact-head Go/PG/race, deterministic cross-process fault tests and technical review required per implementation slice. Never claim atomic revocation against an uncontrolled superuser, production tenant isolation or G01–G05 completion from this proposal.


## Implemented experimental admission barrier (PR #151)

The opt-in `authoritycutover.PostgresBarrier` uses one stable, database-scoped PostgreSQL advisory-lock key on the same primary used by the authority catalog:

1. After mTLS and request syntax validation, each serving replica obtains a non-blocking shared session lock using its independently authenticated `acp_cutover_observer` LOGIN.
2. On that same backend it verifies the Observer role and reads the complete durable ledger. Only `OPEN` admits the request. The lease is retained through Run Authority lookup or Decision Publication signing and the final HTTP response flush.
3. The trusted coordinator commits `OPEN -> DRAINING` before requesting the exclusive session lock. New requests observe `DRAINING` and fail closed. The exclusive lock waits for every previously admitted shared lease to finish.
4. After exclusive acquisition, the coordinator records `CLOSED`, invokes scoped DCL using a separate operator identity, verifies the actual catalog with fresh independently authenticated Observer sessions, records `VERIFYING -> OPEN`, then releases the exclusive lock.
5. If the coordinator crashes or an ACK is uncertain, advisory lock release does not mutate the durable ledger. `DRAINING` / `CLOSED` / `VERIFYING` continue to deny new admissions; recovery requires authoritative readback and explicit state transitions. Never retry DCL blindly or auto-reopen.

The service opt-in requires both `ACP_AUTHORITY_CUTOVER_OBSERVER_DATABASE_URL` and `ACP_AUTHORITY_CUTOVER_OBSERVER_LOGIN`. Startup verifies the independent Observer role and confirms both pools reach the same PostgreSQL primary (database, server address/port, postmaster start time, and not in recovery). The option is disabled when both settings are absent; a partial pair is a startup configuration error. Existing `0001_state_ledger.sql` and `0002_table_acl.sql` remain explicit opt-in bootstrap steps. No production deployment or migration is enabled by this PR.

The real PostgreSQL 16 regression uses two independently authenticated replica LOGINs, a separate Coordinator LOGIN and a separate DCL owner. It verifies positive admission, durable DRAINING rejection, an exclusive lock that cannot pass an in-flight replica, coordinator-loss recovery without implicit reopen, DCL GRANT detection, role recovery after REVOKE, and explicit generation reopen. An mTLS handler regression verifies both Run Authority and Decision Publication acquire the lease only after mTLS/request validation and release it only after response flush.

**Guarantee boundary:** this is a cooperating-replica protocol, not protection against an uncoordinated superuser or a process that bypasses the gate. Every serving replica must use the same database primary and barrier. Already flushed bytes and historical signed publications cannot be recalled; Guard must independently enforce fresh authority generation and its own current Permit at protected-effect consumption. The barrier does not create a cross-service atomic Guard/PEP fence, production G01–G05 evidence, or tenant RLS proof. Keep #98 open pending full independent cross-process fault, lost-ACK, timeout/cancellation and latency acceptance.


The service performs a full ObserveVerified historical ledger audit on the independent Observer backend at startup. The per-request gate uses a bounded indexed admission-head query (singleton state, current claim, current transition and no newer revision), not the full transition-history scan. Trusted coordinator transitions and exclusive-lock recovery continue to use full history verification. This reduces request-path work but does not make historical tampering by an uncoordinated privileged DBA detectable on every request; that actor remains outside the cooperative protocol guarantee.


The exclusive coordinator path re-attests its LOGIN after the lock is granted, not only before waiting; this catches role-membership or ACL changes that occur while the coordinator is queued behind active requests. The PG16 test revokes the coordinator group while it is visibly waiting in pg_locks and requires post-lock attestation to fail closed. CI also logs a 100-sample database admission microbenchmark (baseline and gated p50/p95/p99 plus pool connection counts) and the observed drain wait. These are regression diagnostics, not production SLO evidence.


The request path uses two distinct advisory keys: shared admission leases conflict with the coordinator's exclusive drain lock; shared DDL leases conflict with the event trigger's transaction-exclusive DDL lock. Keeping these keys separate allows the independent DCL operator to execute local DDL while the coordinator holds admission CLOSED.
