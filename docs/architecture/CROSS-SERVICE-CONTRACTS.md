# Cross-Service Contracts — v0.1

## Event envelope

```json
{
  "event_id": "uuid",
  "event_type": "agent.run-intent.created",
  "schema_version": 1,
  "producer": "agent-control-panel",
  "tenant_id": "uuid",
  "aggregate_type": "run_intent",
  "aggregate_id": "uuid",
  "aggregate_version": 1,
  "occurred_at": "RFC3339 timestamp",
  "correlation_id": "uuid",
  "causation_id": "uuid",
  "data": {}
}
```

## Required cross-service identifiers

tenant_id, project_id, agent_id, bundle_digest, release_id, session_id, run_intent_id, run_id, attempt_id, operation_id, action_hash, provider_id, provider_resource_id, allocation_id, trace_id, evidence_digest.

IDs are opaque strings at service boundaries. Never derive authorization from caller-supplied tenant or actor fields; derive principal from authenticated workload/user identity and validate resource ownership.

## Delivery semantics

- Producer writes domain mutation and outbox row in one local transaction.
- Consumer inserts event_id into durable inbox with unique constraint before applying idempotent projection.
- Events are at-least-once and may be reordered. Consumers enforce aggregate_version.
- No distributed transaction across services.
- Remote timeout after a side-effect request is UNKNOWN until provider reconciliation.

## API conventions

- Versioned HTTP JSON APIs under /api/v1.
- OpenAPI is the source of truth for public HTTP contracts.
- Propagate request context, deadlines, trace context and authenticated principal.
- Stable error envelope: code, message, retryable, correlation_id, details (safe and bounded).
- Idempotency keys are scoped to tenant + principal + operation; same key/different canonical payload returns 409.
- Use explicit pagination and request/body limits.
