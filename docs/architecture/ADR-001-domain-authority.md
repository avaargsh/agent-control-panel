# ADR-001: One Authority Per Domain Fact

## Status
Proposed

## Context
The platform spans Agent management, durable execution, decision plugins, action governance and compute. Reusing a shared database or allowing multiple services to own the same lifecycle creates conflicting writers and recovery ambiguity.

## Decision
Each domain has one authoritative writer. Agent Control Plane owns Agent and Session identity plus RunIntent. Runtime owns Run/Task execution lifecycle; Temporal owns durable workflow history. EngageGuard owns action authorization and operation journal. Compute Control Plane owns compute intent and allocation lifecycle; Kubernetes/Kueue own actual scheduling and provider state.

## Alternatives
- Shared database: rejected because service boundaries become unenforceable.
- Control Plane owns all Run state: rejected because it duplicates Temporal/Runtime execution semantics.
- Temporal owns all business entities: rejected because workflow history is not the platform's canonical resource registry.

## Consequences
Services communicate via versioned APIs and outbox/inbox events. Read models may be duplicated, but writes are not. Revisit only with evidence of a domain ownership failure.
