# ACP Sandbox non-dispatch read projection (candidate)

**Status: internal candidate, non-production, no Sandbox Service wire contract.** This is a read-only, consumer-side safeguard for ACP issue #70, not a sandbox execution implementation.

## Authority boundary

The external Sandbox Provider owns actual SandboxLease, AgentD lifecycle, and CommandJournal state. Runtime owns canonical Run/Attempt, EngageGuard owns the operation, Permit, UNKNOWN and executor authorization, and Compute Control Plane owns capacity. ACP only displays or inspects status references. See ADR-004 and DOMAIN-OWNERSHIP.

The new internal/sandboxreadmodel package neither authenticates a remote observation nor persists a journal entry. It has no dispatch, retry, Permit-claim, provider-call, resource-release, or success-publishing interface. CandidateSchema is an internal test-fixture discriminator, **not** a normative source-service schema. No cross-service integration has been executed by this feature.

## Fail-closed user-facing behavior

| Observed Journal state | ACP read-only hint (CLAIMED lease) | Forbidden inference |
|---|---|---|
| PERMIT_UNAVAILABLE | HOLD | no effect without Guard Permit |
| PREPARED | HOLD | prepared is not dispatched |
| DISPATCHING | INSPECT_ONLY | missing ACK is not permission to retry |
| RUNNING | OBSERVE_ONLY | running is not business success |
| UNKNOWN | INSPECT_ONLY | never blindly replay |
| EXITED | VERIFY_ONLY | exit code is not independently attested result |
| FAILED_CONFIRMED | VERIFY_ONLY | failure observation is not permission to repeat effect |

Any lease state RELEASING or RELEASED returns INSPECT_ONLY because self-reported release does not prove the exact sandbox/provider UID is absent. Every assessment has CanDispatch=false, CanRetry=false, CanDeclareSuccess=false, CanDeclareReleased=false. Missing or mismatched tenant, Run, Runtime Attempt, Sandbox UID, Command ID, executor attempt, or stale generation fails closed. Unrecognized status/schema also fails.

## Reproduce

Run from repo root with repository-pinned Go 1.27.4:

    go test -race -count=1 ./internal/sandboxreadmodel
    go vet ./internal/sandboxreadmodel

RED was reproduced locally against a deliberately inert evaluator; GREEN and vet passed with the implementation. Local verification used GO111MODULE=off due to an older local Go compiler and does not establish full-repository compatibility. The hosted Go/PostgreSQL/Race CI on the PR supplies that evidence after completion.

## Blocking dependencies for actual execution

1. EngageGuard #34 trusted Scoped Permit issuer, atomic claim, live revocation, production PEP.
2. ACP #70 actual sandbox-service-owned durable Lease/CommandJournal with generation CAS, inspect/reconcile, lost ACK and SIGKILL testing.
3. ACP #71 short-lived scoped credentials and enforced egress deny-by-default.
4. ACP #72 independent verifier/evidence and confirmed provider UID absence before FINAL.
5. Owner-ratified cross-service source protocol and authenticated observer. Only then add an ACP adapter. This local code cannot certify ANY effect or release.
