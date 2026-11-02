# HTTP API v1 — P0 Run Core

The first implementation exposes a deliberately small API for the durable Run identity and lifecycle slice.

## Tenant context

Every tenant-scoped request requires `X-Tenant-ID`. This header is a development-only stand-in for a tenant claim from authenticated OIDC/JWT middleware. The current binary therefore binds to `127.0.0.1` only. Do not expose it on a network interface or treat the header as authenticated identity.

## Create Run

`POST /api/v1/runs`

Headers:

- `X-Tenant-ID: <tenant>`
- `Idempotency-Key: <stable-client-generated-key>`

Body:

```json
{
  "agentId": "agent-123",
  "releaseId": "release-456",
  "sessionId": "optional-existing-session-id",
  "input": { "task": "summarize these documents" }
}
```

When `sessionId` is omitted, the service creates a Session identity. The key is scoped by tenant and operation. Reusing the same key and canonical request returns the original Run and Session (`200 OK`). Reusing it with a different request returns `409 Conflict`. First creation returns `201 Created`.

The database unique constraint is the concurrency arbiter. The service persists the idempotency record, Session (when new), Run and `RunCreated` outbox event in one transaction.

## Get Run

`GET /api/v1/runs/{id}`

The query is tenant-scoped. A missing Run and a Run owned by another tenant both return `404 Not Found`.

## Transition Run

`POST /api/v1/runs/{id}/transitions`

```json
{
  "expectedVersion": 1,
  "target": "RUNNING"
}
```

A stale version returns `409 Conflict`. The state machine rejects invalid transitions. `FAILED` requires a non-empty `reason`. Each accepted transition increments the version and appends a transactional outbox event.

## Error shape

```json
{
  "error": {
    "code": "CONFLICT",
    "message": "..."
  }
}
```

## Deliberate limitations in this slice

- Authentication and authorization middleware are not implemented; only loopback binding is allowed.
- `X-Tenant-ID` is not an identity proof.
- The outbox is persisted atomically, but publisher/consumer delivery is not implemented yet.
- Workflow and Sandbox Provider adapters are not implemented yet.
- Release and Agent references are opaque IDs; their resource APIs and existence checks are subsequent slices.
