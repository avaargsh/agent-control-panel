# Domain and Identifier Ownership

Status: Proposed v0.2 — implementation gate; Decision and Guard wire contracts remain blocked (G02/G03).

## Authoritative writers

| Domain fact | Authoritative writer | Notes / read-only consumers |
|---|---|---|
| Tenant / Project | Agent Control Plane | Initial platform scope; services validate scoped references |
| Agent / AgentBundle / AgentRelease | Agent Control Plane | Bundle digest is immutable |
| AgentIdentity / SessionIdentity | Agent Control Plane | Session survives multiple Runs |
| RunIntent | Agent Control Plane | Idempotent request to start a Run; not an execution |
| Run / Task / RunAttempt / execution lifecycle | Agent Runtime | Agent Control Plane may keep a read-only projection |
| Temporal Workflow history / replay / native Activity attempts | Temporal | Runtime owns Workflow ID mapping and workflow code |
| DecisionRecord / invocation ledger and exact result | agent-decision Go Core | Runtime creates stable invocation_id; Decision owns the record |
| Bounded framework reasoning | separately versioned agent-decision adapter | Adapter has no second Decision ledger or protected-effect authority; wire contract pending agent-decision #9 |
| Action / ActionHash / risk / approval / Permit / Action Operation Journal / Receipt | EngageGuard | Trusted executor performs protected effects |
| ComputeProvider / ComputePool / ComputeProfile / Workload / Allocation / ComputeOperation | compute-control-panel | Compute domain only |
| Kueue queue and admission state | Kueue | Admission and quota enforcement, not Pod placement |
| Pod / Job / node placement / device allocation state | Kubernetes scheduler, device plugins / DRA, provider | Compute stores observations, not a second authority |
| Actual sandbox lifecycle and isolation | selected Sandbox Provider | Compute capacity is a separate allocation concern |

## Candidate identifier ownership

| Identifier | Created by | Authoritative owner | Meaning |
|---|---|---|---|
| `tenant_id`, `project_id` | Agent Control Plane | Agent Control Plane | Scope |
| `agent_id`, `bundle_digest`, `release_id` | Agent Control Plane | Agent Control Plane | Agent definition and release |
| `session_id` | Agent Control Plane | Agent Control Plane | Stable logical conversation/work identity |
| `run_intent_id` | Agent Control Plane | Agent Control Plane | Idempotent request to start a Run |
| `run_id`, `workflow_id`, `run_attempt_id` | Agent Runtime | Agent Runtime | Canonical execution identity and stable Temporal mapping |
| Temporal Activity attempt | Temporal | Temporal | Native retry metadata; not a Runtime Attempt ID |
| `invocation_id` | Agent Runtime | agent-decision | Runtime supplies stable ID; Decision Core owns ledger/result |
| `proposal_id` | agent-decision | agent-decision | Untrusted proposal identity |
| Action `operation_id` | EngageGuard (proposed; G03 blocked) | EngageGuard | EngageGuard owns Action Operation; current ActionRequest draft conflicts on whether this ID is caller-supplied or server-generated |
| `action_hash`, `permit_id`, `executor_attempt_id` | EngageGuard / trusted executor | EngageGuard | Canonical action, permit and concrete executor attempt |
| `workload_id`, `allocation_id`, `compute_operation_id` | Compute Control Plane | Compute Control Plane | Compute intent, allocation and provider mutation |
| `provider_id` | Compute Control Plane | Compute Control Plane | Registered provider identity |
| `provider_resource_id` / UID | Provider / Kubernetes | Provider / Kubernetes | Native reference, never platform ID |
| `event_id` | Event producer | Event producer | Immutable event envelope |
| `correlation_id` | Request origin / gateway | Request origin | End-to-end correlation, not authorization |
| `evidence_digest` | Evidence producer | Producing service | Content integrity reference |

Identifiers are opaque across service boundaries. A foreign ID is a reference, not permission and not ownership. Authorization is derived from verified identity context, never caller-supplied tenant, actor, project or workload fields.

## Cross-domain rules

- No cross-service direct database writes. Each service owns its PostgreSQL schema and migrations.
- Read models may be duplicated but must identify their source and observed version.
- RunIntent acceptance means Runtime accepted the request; it does not mean the Run is Running or Succeeded.
- Agent Runtime owns Run lifecycle; Temporal owns durable workflow history; neither moves Action/Permit/Action Operation authority out of EngageGuard.
- Runtime does not independently retry an external effect whose Action Operation is UNKNOWN in EngageGuard.
- Compute Control Plane owns provider mutation journal and Allocation reconciliation. It does not own Agent, Session or Run lifecycle.
- Sandbox Provider owns sandbox lifecycle; Compute Control Plane supplies capacity/workload allocation when requested. Do not create the same sandbox resource independently in both systems.
- Kubernetes/Kueue/provider state is observed through adapters; no second scheduler or provider authority is introduced.
- Evidence digest authority stays with the producing service; cross-service indexes are read-only references.
