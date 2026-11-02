> **SUPERSEDED — HISTORICAL SNAPSHOT ONLY**
>
> This document records an earlier Agent Control Plane proposal. It is retained for decision history and must not be used to implement current service ownership, Run lifecycle, Workflow or Sandbox contracts.
>
> The normative architecture is now:
>
> - [Platform Baseline](PLATFORM-BASELINE.md)
> - [Domain Ownership](DOMAIN-OWNERSHIP.md)
> - [Cross-Service Contracts](CROSS-SERVICE-CONTRACTS.md)
> - [Identifier Lifecycle](IDENTIFIER-LIFECYCLE.md)
> - [ADR-002: Temporal and Agent Framework boundary](ADR-002-temporal-agent-framework.md)
> - [Current P0 Golden Path](../roadmap/P0-GOLDEN-PATH.md)
>
> **Known historical conflicts:** this snapshot assigns Run/Run state and portions of workflow dispatch to the Control Plane. Those responsibilities have moved to `agent-runtime`; Temporal owns durable workflow history. Compute resource intent and Allocation belong to `compute-control-panel`. The old component model and state descriptions below are non-normative.
>
> Do not copy code, state machines or API contracts from this historical snapshot into new implementations without an explicit ADR approved against the current baseline.

---

# Historical Architecture Baseline — Agent Control Plane Rewrite

Original status: proposal baseline for implementation  
Original date: 2026-11-02  
Target: `avaargsh/agent-control-panel`

The content below is preserved only to explain earlier design decisions. It is not current architecture authority.

## 1. Historical product shape

The product was described as a thin Agent Infrastructure Control Plane exposing a stable API and reconciling declared Agent intent into external execution systems.

The historical central contract described Control Plane authority as Agent identity, desired state, release intent, Session/Run identity, policy bindings, lifecycle coordination and evidence references; Runtime authority as execution plan semantics, workflow history, task/step scheduling, retry policy, wait/approval continuation and checkpoint details; Provider authority as external resource state and side effects.

## 2. Historical component model

The earlier component model included a Control Plane reconciler calling Workflow and Sandbox adapters directly. Current implementation must instead follow the Runtime and Compute service boundaries in the normative documents.

## 3. Historical domain model

The earlier proposal included Agent, AgentBundle, AgentRelease, Session, FederationBinding, CredentialBinding, ContextProjectionPolicy and Evidence. The current domain ownership and identifier documents supersede all historical ownership assumptions.

## 4. Historical reconciliation notes

The earlier proposal correctly distinguished desired from observed state, acknowledgement from verified outcome, and retryable from ambiguous outcomes. Those principles remain valid, but the owning services and operation identities are defined by the current contracts.

## 5. Historical external integrations

Temporal, Sandbox providers, Compute, OIDC and secret stores were identified as integrations. Their current contracts and authoritative boundaries are defined in [Platform Baseline](PLATFORM-BASELINE.md).

## 6. Historical open decisions

The old proposal listed language/framework, event model, Run idempotency, tenant authorization, evidence canonicalization and Kubernetes CRD decisions as open. These are superseded by the current Go service baseline and the current cross-service contracts; any remaining unresolved item must be recorded in the current roadmap or a new ADR.
