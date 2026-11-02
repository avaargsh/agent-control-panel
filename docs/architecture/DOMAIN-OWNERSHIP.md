# Domain and Identifier Ownership

Status: Proposed v0.2 — implementation gate

## Authoritative writers

| Domain fact | Authoritative writer | Notes / read-only consumers |
|---|---|---|
| Tenant / Project | Agent Control Plane | Initial platform scope; services validate scoped references |
| Agent / AgentBundle / AgentRelease | Agent Control Plane | Bundle digest is immutable |
| AgentIdentity / SessionIdentity | Agent Control Plane | Session survives multiple Runs |
| RunIntent | Agent Control Plane | Request to start a Run; not an execution |
| Run / Task / Attempt / execution lifecycle | Agent Runtime | Agent Control Plane may keep a read-only projection |
| Temporal Workflow history / replay | Temporal | Runtime owns workflow mapping and code |
| DecisionRecord / framework invocation | agent-decision | Replaceable bounded plugin |
| Action / ActionHash / risk / approval / Permit / OperationJournal | EngageGuard | Trusted executor performs protected effects |
| ComputeProvider / ComputePool / ComputeProfile / Workload / Allocation / ComputeOperation | compute-control-panel | Compute domain only |
| Kueue queue and admission state | Kueue | Admission and quota enforcement, not Pod placement |
| Pod / Job / node placement / device allocation state | Kubernetes scheduler, device plugins / DRA, provider | Compute stores observations, not a second authority |
| Actual sandbox lifecycle and isolation | selected Sandbox Provider | Compute capacity is a separate allocation concern |

## Canonical identifier ownership

| Identifier | Created / owned by | Meaning |
|---|---|---|
| tenant_id, project_id | Agent Control Plane | Scope |
| agent_id, bundle_digest, release_id | Agent Control Plane | Agent definition and release |
| session_id | Agent Control Plane | Stable logical conversation/work identity |
| run_intent_id | Agent Control Plane | Idempotent request to start a Run |
| run_id | Agent Runtime | Canonical executed Run identity |
| workflow_id | Agent Runtime | Stable Temporal mapping derived from run_id |
| attempt_id | Agent Runtime | One execution attempt; never reused |
| invocation_id, turn_id | agent-decision / invocation contract | Bounded framework execution |
| action_hash, permit_id, action operation_id | EngageGuard | Protected action and its effect journal |
| workload_id, allocation_id, compute operation_id | compute-control-panel | Compute intent and provider operation |
| provider_id | compute-control-panel | Registered provider identity |
| provider_resource_id / UID | Provider / Kubernetes | Provider-native reference, never a platform ID |
| event_id | Event producer | One immutable event envelope |
| correlation_id | Originating request / gateway | End-to-end request correlation |
| evidence_digest | Evidence producer | Content integrity reference |

Identifiers are opaque across service boundaries. A foreign ID is a reference, not permission and not ownership. Authorization is derived from verified identity context, never caller-supplied tenant, actor, project or workload fields.

## Cross-domain rules

- No cross-service direct database writes. Each service owns its PostgreSQL schema and migrations.
- Read models may be duplicated but must identify their source and observed version.
- RunIntent acceptance means Runtime accepted the request; it does not mean the Run is Running or Succeeded.
- Agent Runtime owns Run lifecycle; Temporal owns durable workflow history; neither moves Action/Permit/OperationJournal authority out of EngageGuard.
- Runtime does not independently retry an external effect whose operation is owned by EngageGuard.
- Compute Control Plane owns provider mutation journal and allocation reconciliation. It does not own Agent, Session or Run lifecycle.
- Sandbox Provider owns sandbox lifecycle; Compute Control Plane supplies capacity/workload allocation when requested. Do not create the same sandbox resource independently in both systems.
- Kubernetes/Kueue/provider state is observed through adapters; no second scheduler or provider authority is introduced.
