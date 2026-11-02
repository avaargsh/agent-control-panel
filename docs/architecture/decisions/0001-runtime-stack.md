# ADR 0001: Initial Runtime and Persistence Stack

- Status: Accepted for the first implementation slice
- Date: 2026-11-02

## Context

The repository was initialized without source code or an existing build/test convention. The rewrite needs a small, Kubernetes-adjacent backend that can expose stable APIs and coordinate provider integrations without taking on Agent execution semantics.

## Decision

- Use Go for the Control Plane service and adapter interfaces.
- Use PostgreSQL as the authoritative store for domain state, idempotency records and transactional outbox events.
- Use `database/sql` at the repository boundary and pgx as the PostgreSQL driver.
- Use the Go standard library HTTP server for the initial API surface.
- Keep the first deliverable focused on Session/Run identity and lifecycle; do not introduce a workflow engine or Sandbox dependency before the provider contracts are ready.

## Consequences

- Domain and application packages remain independent of HTTP, PostgreSQL and Kubernetes SDK types.
- Database uniqueness and transactions arbitrate idempotency and state updates across service replicas.
- Outbox delivery is at-least-once once a publisher is added; consumers must be idempotent.
- The initial binary is loopback-only because authentication and authorization are not yet implemented.
- Kubernetes CRDs and UI are deferred until the API/domain contracts have executable tests.

## Revisit when

- The old `agent-control-plane` source is available for behavior/contract migration.
- Production authentication, authorization and multi-tenant identity mapping are implemented.
- The first workflow and Sandbox Provider adapters define their real operational requirements.
