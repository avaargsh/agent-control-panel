# Domain Ownership

A domain fact has exactly one authoritative writer. Consumers may keep projections, caches or references, but cannot mutate the producer's fact or claim ownership of its lifecycle.

| Domain fact | Authoritative writer | Read model consumers / notes |
|---|---|---|
| Tenant / Project (initial platform scope) | agent-control-panel | all services; authenticated principal and ownership are still verified at every boundary |
| Agent / AgentBundle / AgentRelease | agent-control-panel | runtime, decision, console |
| AgentIdentity / SessionIdentity | agent-control-panel | runtime, EngageGuard |
| RunIntent and client submission idempotency | agent-control-panel | runtime |
| Run / Task / RunAttempt / execution lifecycle projection | agent-runtime | agent-control-panel, console |
| Temporal Workflow history, timers and native Activity attempts | Temporal | runtime queries/projectors; Runtime defines stable Workflow ID mapping |
| DecisionRecord / invocation request digest and replay result / proposal | agent-decision | runtime, audit |
| Action / AuthorizationDecision / Risk / Approval / Permit / Action Operation Journal / Receipt | EngageGuard | runtime, audit, console |
| ComputeProvider / Pool / Workload / Allocation / Compute Operation Journal | compute-control-panel | runtime, console |
| Provider-native resource identity and actual state | selected provider / Kubernetes / Kueue | compute-control-panel observes and projects |
| Actual Sandbox lifecycle and isolation | selected Sandbox Provider | runtime observes through provider adapter |
| Context Projection policy | agent-control-panel | runtime enforces when constructing the bounded projection |
| Concrete Context Projection generated for one invocation | agent-runtime | decision consumes the supplied bounded projection; source references are provenance only |
| Workload identity issuance / signing keys | external OIDC or workload identity provider | each service verifies authenticated workload identity |
| Evidence payload and digest | service that produces the evidence | other services keep immutable references / indexes; Control Plane may index but is not a second writer |

## Canonical identifier ownership

- Control Plane creates `run_intent_id`.
- Runtime creates and owns `run_id`, `run_attempt_id`, and the deterministic `workflow_id` mapping.
- Decision owns `invocation_id` records and `proposal_id` values; Runtime supplies stable invocation identity across retries.
- Runtime assigns `action_operation_id` (wire field `operation_id`) once per accepted proposal; EngageGuard owns its immutable Action Operation record and computes `action_hash`.
- EngageGuard / trusted executor owns `executor_attempt_id` in the Receipt.
- Compute Control Plane creates and owns `compute_operation_id` and `allocation_id`.
- Each evidence producer calculates its own `evidence_digest`.

See [Identifier Lifecycle](IDENTIFIER-LIFECYCLE.md) for constraints and retry semantics.

## Rules

1. No cross-service direct database writes and no shared writable schema.
2. A read model is not a second authority; corrections are appended as new evidence rather than silently rewriting another service's history.
3. Runtime owns Run lifecycle but never independently retries a side effect whose Action Operation is UNKNOWN in EngageGuard.
4. EngageGuard owns the authorization/action journal; Compute owns provider resource operations and actual-state reconciliation. Their records are linked, not merged.
5. EngageGuard authorizes Agent-originated protected compute requests at the boundary. Compute controller maintenance uses its own service identity and policy.
6. Agent Control Plane stores logical Session identity, not MCP transport session state or framework memory.
7. Provider-native IDs are references, never canonical platform IDs.
8. No service trusts caller-supplied tenant, subject, actor or workload fields without binding them to authenticated identity and persisted ownership.
9. Evidence digest authority remains with the producer; a central index must not rewrite evidence or claim to verify content it has not independently checked.
