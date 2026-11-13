# ADR-004: Compute Allocation and Sandbox Lifecycle Are Separate Domains

Status: Proposed v0.2

## Context

A Kubernetes Sandbox may consume compute capacity, but treating SandboxProvider and ComputeProvider as the same authority creates duplicate create/delete operations and conflicting lifecycle records. Kueue admission, Kubernetes Pod placement and provider provisioning are different control points.

## Decision

- AgentBundle declares immutable compute requirements/profile references; RunIntent carries the resolved requirement reference, not a provider-native resource ID.
- Agent Runtime requests a Workload on behalf of a canonical Run when execution needs compute.
- Compute Control Plane owns ComputeProvider registration, ComputePool, ComputeProfile, Workload intent, Allocation, quota binding, provider operation journal and observation projections.
- Compute Control Plane chooses a compatible provider/pool and reconciles provider mutations. It does not implement another scheduler.
- Kueue owns queue admission and quota admission; Kubernetes scheduler owns Pod placement; device plugins/DRA and providers own device/resource realization.
- SandboxProvider owns sandbox identity, isolation and sandbox lifecycle. It may request compute capacity through Compute Control Plane, but it must not independently create a second Workload/Allocation for the same resource.
- Provider-native IDs and Sandbox IDs are references, never canonical Agent/Run IDs.

## Golden Path

`Run → Compute Workload Request → Allocation → Provider Operation → Kueue Admission → Kubernetes Scheduling → Provider Observation`

For sandbox execution:

`Runtime → SandboxProvider Claim → Compute Capacity Request (if needed) → SandboxProvider lifecycle`

The SandboxProvider remains the authority for the sandbox. Compute remains the authority for capacity allocation.

## Consequences

- Workload, Allocation, Provider Operation and Resource Observation are distinct records and state machines.
- Delete acknowledgement does not mean released; release requires inspection proving absence of the exact provider resource UID.
- UNKNOWN provider outcomes require operation lookup/inspect and reconciliation before retry.
- Kueue is not treated as a Pod scheduler; no parallel GPU scheduler is added.
