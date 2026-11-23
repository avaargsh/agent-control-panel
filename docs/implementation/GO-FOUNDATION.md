# Go foundation

This guide covers the Go service and RunIntent persistence in this repository.

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

Domain transitions validate optimistic versions and fencing tokens. The PostgreSQL repository persists compare-and-swap transitions and Outbox events transactionally. Admission persists the RunIntent, execution input, principal snapshot, and Outbox event together. See [PostgreSQL persistence](PERSISTENCE-FOUNDATION.md) and [RunIntent admission](RUNINTENT-ADMISSION.md).

The operations HTTP service exposes read-only endpoints. Its readiness check covers process availability. Runtime receipt verification relies on the authenticated transport described in the [Runtime Inspect guide](RUNTIME-INSPECT-CLIENT.md).

## Local

```sh
go test -race ./...
go run ./cmd/agent-control-panel
curl http://127.0.0.1:8080/api/v1/meta
```

`LISTEN_ADDR` defaults to loopback. For containers choose `LISTEN_ADDR=:8080` behind authenticated ingress/network policy.
