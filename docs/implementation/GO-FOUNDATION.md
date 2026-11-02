# Go foundation — first implementation slice

Status: **non-production foundation; P0 golden path not yet complete**.

## Available

- Go 1.27 module, bounded HTTP process, health/readiness/metadata and graceful shutdown.
- Pure RunIntent state transitions with optimistic version checks.
- Dispatch leases with monotonically increasing fencing tokens.
- Typed Runtime dispatch/reconciliation outcomes; no caller-supplied boolean is accepted as proof.
- Runtime receipt checks bind tenant, RunIntent ID and canonical request digest.
- Accepted receipts must carry Runtime-generated `run_id` and the canonical Workflow ID mapping `agent-run/v1/{run_id}`.
- UNKNOWN can return to PENDING only after Runtime's authoritative idempotency registry reports final not-found for the same RunIntent ID and digest.
- Regression tests cover stale versions, lease expiry, fencing, mismatched receipts and no blind UNKNOWN retry.

## Boundaries and caveats

Agent Control Plane owns RunIntent and its dispatch projection. Agent Runtime owns `run_id`, `workflow_id`, `run_attempt_id` and the executed Run lifecycle. Temporal owns durable workflow history and native Activity attempts.

The current domain transitions are pure functions, **not durable compare-and-swap**. PostgreSQL must later atomically persist the version/fencing transition, idempotency record and Outbox row. Runtime receipts are accepted only after the adapter authenticates the Runtime workload identity; typed structs are not a substitute for transport authentication.

There are deliberately **no mutating HTTP endpoints** until persistent idempotency, authorization, transactional outbox and evidence acceptance are integrated. Readiness currently covers process admission only, not future database/Runtime health.

## Local

```sh
go test -race ./...
go run ./cmd/agent-control-panel
curl http://127.0.0.1:8080/api/v1/meta
```

`LISTEN_ADDR` defaults to loopback. For containers choose `LISTEN_ADDR=:8080` behind authenticated ingress/network policy.

## Next P0 slice

1. OpenAPI DTOs for Bundle/Release/Session/RunIntent and tenant scope.
2. Migration runner plus Go PostgreSQL repository: atomic idempotency claim, RunIntent + Outbox transaction, version/fence CAS.
3. Authenticated Runtime StartRun / InspectRunIntent client and durable dispatch leases.
4. Outbox publisher and Inbox consumer with duplicate/gap recovery.
5. Restart, lost-ACK, duplicate-start, tenant authorization and event-gap integration tests.

No production-readiness claim is made by this slice.
