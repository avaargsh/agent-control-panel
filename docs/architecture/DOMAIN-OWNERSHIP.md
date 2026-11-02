# Domain Ownership

| Domain fact | Authoritative writer | Read model consumers |
|---|---|---|
| Tenant / Project (initial platform scope) | agent-control-panel | all services |
| Agent / AgentBundle / AgentRelease | agent-control-panel | runtime, decision, console |
| AgentIdentity / SessionIdentity | agent-control-panel | runtime, EngageGuard |
| RunIntent | agent-control-panel | runtime |
| Run / Task / Attempt / workflow projection | agent-runtime; workflow history is Temporal | agent-control-panel, console |
| DecisionRecord / framework invocation | agent-decision | runtime, audit |
| Action / AuthorizationDecision / Risk / Approval / Permit / OperationJournal | EngageGuard | runtime, console |
| Provider / ComputePool / Workload / Allocation | compute-control-panel | runtime, console |
| Actual Pod / Job / Kueue admission | Kubernetes / Kueue | compute-control-panel |
| Actual Sandbox lifecycle | selected Sandbox Provider | runtime |

## Rules

- No cross-service direct database writes.
- A read model is not a second authority.
- Runtime must not independently retry an external side effect recorded by EngageGuard.
- EngageGuard owns action execution ambiguity; Runtime owns business Run lifecycle ambiguity.
- Agent Control Plane stores Session identity, not MCP transport session state.
- Provider-native IDs are references, never canonical platform IDs.
