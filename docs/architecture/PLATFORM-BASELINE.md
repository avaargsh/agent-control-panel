# Open Agent Infrastructure — Platform Baseline

Status: Proposed v0.2 implementation baseline  
Date: 2026-11-02

## Product outcome

A self-hosted, Kubernetes-first platform to publish versioned Agents, execute durable Runs through managed framework plugins, govern protected actions and allocate heterogeneous compute. Reuse mature workflow, admission, scheduling, sandbox, IAM and policy systems.

## Capability and authority map

| Module | Repository / system | Sole authority |
|---|---|---|
| Agent Control Plane | agent-control-panel | Tenant/Project, Agent, Bundle, Release, SessionIdentity, RunIntent and desired state |
| Runtime | agent-runtime | Run, Task, RunAttempt, execution lifecycle and Runtime ↔ Temporal mapping |
| Durable orchestration | Temporal | Workflow history, replay, timers, durable waits and native Activity attempts |
| Decision plugin | agent-decision | DecisionRecord, invocation ledger/result, bounded model reasoning and proposals |
| Action governance | EngageGuard | Action, ActionHash, risk, approval, Permit, protected-action Operation Journal and Receipt |
| Compute | compute-control-panel | ComputeProvider, Pool, Profile, Workload, Allocation and Compute Operation Journal |
| Admission | Kueue | Queue and admission/quota state |
| Scheduling / resources | Kubernetes, scheduler, device plugins/DRA, provider | Actual Pod placement and provider resource state |
| Sandbox | selected Sandbox Provider | Sandbox identity, lifecycle and isolation |

A repository name ending in `panel` does not imply UI ownership. `agent-control-panel` is the Go Agent Control Plane API; a future console is only a client.

## Identifier ownership

- Agent Control Plane: tenant_id, project_id, agent_id, bundle_digest, release_id, session_id, run_intent_id.
- Agent Runtime: run_id, workflow_id, run_attempt_id; Runtime also assigns invocation_id and Action operation_id before dispatch.
- agent-decision: invocation ledger/result and proposal_id.
- EngageGuard: Action operation record, action_hash, permit_id, executor_attempt_id.
- Compute Control Plane: workload_id, allocation_id, compute_operation_id.
- Temporal: native Workflow/Activity attempt metadata.
- Provider / Kubernetes: provider_resource_id and UID.
- Event producers: event_id; request origin: correlation_id.
- Each evidence producer owns its own evidence_digest.

See [Identifier Lifecycle](IDENTIFIER-LIFECYCLE.md) for the complete creator/owner/retry matrix.

## Durable interaction contract

Each service owns its PostgreSQL database and schema. Domain mutation plus Outbox insert are one transaction. Inbox receipt is durable; projection update, cursor advance and APPLIED status are atomic. Delivery is at-least-once; aggregate versions detect duplicates and gaps. Same idempotency key plus same canonical digest returns the same resource; key reuse with another digest returns 409. No shared writable database and no exactly-once side-effect claim.

## Execution boundaries

Temporal Workflow code is deterministic orchestration only. Activities perform I/O. Runtime owns the Run lifecycle and invokes a bounded Decision plugin. The canonical Decision v0.1 schemas define a strict request and a two-outcome response union: FinalResponse or ActionProposals. The plugin has no privileged credentials. EngageGuard authorizes and journals each protected effect; the trusted executor performs it. Runtime/Temporal do not retry that effect independently.

## ActionHash

EngageGuard computes ActionHash only after trusted action normalization. It uses RFC 8785 JCS and the versioned domain separator `engageguard/action-hash/v1\\0`; SHA-256 output is 64 lowercase hexadecimal characters. Approval, Permit, executor claim and Receipt bind the same Action operation ID and hash. Cross-language vectors are stored at `contracts/engageguard/action-hash/v0.1/workspace-write-vectors.json`.

## Compute and sandbox boundaries

Runtime requests a Workload for a Run when required. Compute Control Plane chooses provider/pool and owns Allocation and provider operation reconciliation. Kueue performs queue/admission and quota admission; Kubernetes scheduler places Pods; device plugins/DRA/providers realize devices. SandboxProvider owns sandbox lifecycle and isolation; it can request compute capacity but does not create duplicate compute resources.

## Deployment shape

Begin with one API process and one reconciler/worker process per Go service, sharing only that service's database. Temporal is a separate durable execution service. Split deployables only when scaling or security isolation justifies it. Redis may cache, but is not authoritative.

## Build order

1. Freeze domain, identifier, event, Decision schema, ActionHash and idempotency contracts.
2. Go service bootstrap, config, health, telemetry, shutdown and PostgreSQL migrations.
3. Transactional idempotency + Outbox/Inbox with aggregate version recovery.
4. Agent RunIntent dispatch and Compute Workload vertical slices with lease/fencing.
5. Runtime Temporal adapter and Compute FakeProvider contract tests.
6. UNKNOWN recovery, restart/fault injection, AuthZ and evidence.
7. Kubernetes/Kueue and Sandbox adapters after fake contract suites pass.
8. Console and federation after APIs are stable.

## Deferred

Custom workflow engine, Agent framework, policy language, IAM, sandbox runtime, MCP/A2A gateway, GPU scheduler, Kafka before measured need, multi-region federation and generalized marketplace.

## Acceptance

A clean environment proves stable identity, duplicate request behavior, outbox/inbox recovery, stale-version rejection, lost-ACK reconciliation, tenant isolation, action-bound authorization, compute delete finality and restart recovery. Health endpoints and pure unit tests alone are not production acceptance.
