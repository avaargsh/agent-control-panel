# Cross-Service Contracts — v0.2

Status: Proposed; freeze before service-to-service implementation.

## Event envelope

Every event is a versioned fact, not a command with implicit exactly-once semantics.

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
  "traceparent": "00-...",
  "data": {}
}
```

Required fields are validated at the consumer boundary. `causation_id` may be omitted only for an originating event; trace context is propagated but is never an authorization input.

## Identifier ownership

- Agent Control Plane creates `run_intent_id`; it is the Runtime start-request idempotency identity.
- Agent Runtime creates canonical `run_id`, `workflow_id` and `attempt_id`. Control Plane stores these only as read-only references/projections.
- EngageGuard creates `action_hash`, Permit and protected-action `operation_id`.
- Compute Control Plane creates `workload_id`, `allocation_id` and provider-mutation `operation_id`.
- Provider-native resource IDs/UIDs remain external references.
- Do not put an unowned identifier into a service's aggregate key.

## Delivery, ordering and recovery

1. Producer commits domain mutation and Outbox row in the same local database transaction.
2. Publisher is at-least-once. A publish acknowledgement is not proof the consumer committed.
3. Consumer inserts `event_id` into a durable Inbox and applies its projection in the same local transaction.
4. Consumers enforce `aggregate_version`: ignore an already-applied version, apply the next expected version, and park/retry a version gap. Never silently drop a gap or apply an older event over newer state.
5. No distributed transaction and no claim of exactly-once external effects.
6. A timeout after a remote side-effect request is UNKNOWN until the owning service/provider is inspected and reconciled.

## Idempotency contract

- Every mutating API accepts an idempotency key. Scope uniqueness by `tenant_id + authenticated principal_id + operation`.
- Persist the canonical request digest with the idempotency key in the same transaction as the resource and Outbox row.
- Same key + same digest returns the original canonical resource/result.
- Same key + different digest returns HTTP 409 (`IDEMPOTENCY_KEY_REUSED`).
- A retry after timeout reuses the same key and digest. Never mint a new operation ID just because an acknowledgement was lost.
- Authentication principal and tenant membership come from verified identity context; caller JSON cannot choose them.

## Retry ownership

| Operation | Retry / reconciliation owner |
|---|---|
| RunIntent → Runtime StartRun request | Agent Control Plane dispatcher, same run_intent_id and digest; Runtime idempotency registry is authoritative |
| Temporal Workflow / Activity orchestration | Agent Runtime / Temporal |
| Model/framework invocation | Decision plugin invocation boundary; bounded by Runtime deadline and invocation_id |
| Protected action / external side effect | EngageGuard operation journal + trusted executor |
| Compute provider create/update/delete | Compute Control Plane operation journal + provider inspect/reconciliation |
| Kubernetes admission and scheduling | Kueue / Kubernetes; Compute observes and reconciles |

Temporal Activity retry must not create a second side-effect authority. Calls to EngageGuard or Compute must use their stable idempotency contracts.

## API conventions

- Versioned JSON APIs under `/api/v1`; OpenAPI is the public HTTP source of truth.
- Propagate request context, deadline, trace context and authenticated principal.
- Stable error envelope: `code`, `message`, `retryable`, `correlation_id`, bounded safe `details`.
- HTTP: 400 malformed request, 401 unauthenticated, 403 unauthorized, 404 absent resource, 409 idempotency/version conflict, 422 semantically invalid, 429 quota/rate limit, 503 unavailable, 500 internal.
- Explicit pagination, maximum page size, request/body limits and deadline budgets.
- Do not expose provider credentials, raw secrets, stack traces or unbounded provider payloads.
