# Go foundation — first implementation slice

Status: **non-production foundation; P0 golden path not yet complete**.

## Available

- Go 1.27 module, testable HTTP process, read-header/body timeouts and bounded header size.
- `GET /livez`, `GET /readyz`, `GET /api/v1/meta`.
- Readiness goes false when admission is being drained; SIGINT/SIGTERM triggers bounded graceful shutdown.
- Pure RunIntent status and optimistic version-transition checks.
- Regression tests for stale versions, no blind UNKNOWN retry, and isolation from Runtime-owned RUNNING state.
- CI with pinned GitHub Actions, Go vet and race-enabled tests.

## Boundaries and caveats

Agent Control Plane owns the RunIntent and identities. Agent Runtime owns
executed Run/Task/Attempt lifecycle and Temporal workflow history. This
package does not launch a workflow or enforce permissions.

`Advance` is a pure domain check, **not a durable CAS**. PostgreSQL will
need a versioned conditional update and an outbox insert in a single
transaction. A boolean `providerVerified` is temporary internal input:
before use by any API or reconciler, replace it with a typed observation
bound to the exact workflow ID, tenant, and operation ID. Never trust a
boolean supplied by a caller.

There are deliberately **no mutating endpoints** until persistent
idempotency, authorization and evidence acceptance are implemented. Readiness
currently covers process admission only, not future DB/Runtime health.

## Local

```sh
go test -race ./...
go run ./cmd/agent-control-panel
curl http://127.0.0.1:8080/api/v1/meta
```

`LISTEN_ADDR` defaults to loopback. For containers choose
`LISTEN_ADDR=:8080` behind authenticated ingress/network policy.

## Next P0 slice

1. OpenAPI DTOs for Bundle/Release/Session/RunIntent and tenant scope.
2. PostgreSQL migrations, idempotency and transactionally coupled outbox.
3. Typed WorkflowProvider start/inspect/reconcile contract.
4. Restart, lost-ACK, duplicate-start and authz integration tests.

No production-readiness claim is made by this slice.
