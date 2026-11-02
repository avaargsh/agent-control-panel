# Agent Control Panel

Agent Infrastructure Control Plane for self-hosted, Kubernetes-first agent workloads.

> **Product boundary:** Agent Control Plane owns desired state, identity, governance, federation and lifecycle. Agent Runtime owns execution semantics. Sandbox and compute providers own the execution substrate.

## Product intent

Build an API-first control plane to deploy, govern, observe and recover agent workloads across execution environments. The platform composes mature open-source systems instead of reimplementing workflow engines, sandbox runtimes, IAM, policy engines or GPU schedulers.

The initial Golden Path is:

`AgentBundle → AgentRelease → Agent Identity → Session → Run Intent → Workflow Adapter → Sandbox Provider → Execution → Evidence`

This path must demonstrate stable identity, recoverable Session/Run state, safe reconciliation, authorization, credential revocation and linked audit evidence.

## Core domain resources

| Resource | Authority |
|---|---|
| Agent | Logical agent identity and desired configuration |
| AgentBundle | Versioned declarative agent package and runtime requirements |
| AgentRelease | Release intent, rollout and release governance |
| Session | Canonical user/agent conversation-work identity across Runs |
| Run | One execution attempt with durable lifecycle identity |
| FederationBinding | Binding to a remote control plane/provider |
| CredentialBinding | References to external credential authorities; never raw secret material |
| ContextProjectionPolicy | Rules for selecting/projecting context into an execution |
| Evidence | Immutable references and attestations for lifecycle and execution outcomes |

The Control Plane owns logical Agent/Session/Run identity and desired state. It does not duplicate workflow history, worker scheduling, step retries, checkpoints or sandbox internals.

## Responsibility boundaries

- **Agent Control Plane:** domain resources, desired state, lifecycle coordination, authorization delegation, release governance, federation and evidence links.
- **Agent Runtime / workflow engine (Temporal or compatible):** durable execution, step semantics, retries, waits, checkpoints and worker orchestration.
- **Sandbox Provider (OpenKruise Agents, OpenSandbox, etc.):** isolated execution environment lifecycle, filesystem/runtime and sandbox-level network enforcement.
- **Compute Control Plane (`compute-control-panel` / `gpu-compute-platform`):** cluster/provider inventory, compute allocation and accelerator lifecycle.
- **Identity / secrets / policy:** integrate Keycloak or an OIDC provider, OpenBao/Kubernetes Secret, and mature policy systems (OPA/Casbin/Cedar) through adapters.
- **`agent-control-panel` UI:** operator and developer UX only; no separate authority or lifecycle source of truth.

## Architecture principles

1. API-first, Kubernetes-first, self-hosted.
2. Reconcile desired state; persist identity and lifecycle state independently from runtime processes.
3. Explicitly separate AgentIdentity, SessionIdentity and WorkloadIdentity.
4. Treat provider operations as asynchronous, idempotent and recoverable; unknown outcomes remain unknown until reconciled.
5. Evidence links outcomes to the exact release, run, provider operation and observation.
6. Reuse Temporal, OpenKruise Agents, Kueue/KAI/Volcano, Keycloak/OpenBao and existing gateways through narrow adapters.
7. Keep secrets out of Agent manifests, prompts, sandbox metadata and logs.
8. Keep UI, Runtime and Compute Control Plane separate deployable/repository boundaries.

## Initial implementation sequence

- **P0 — Contract and Golden Path:** resource/API contracts; AgentBundle → Release → Session → Run; persistence; Run state machine; workflow adapter contract; Sandbox Provider SPI; restart recovery and idempotent reconciliation.
- **P0 — Identity and authorization:** identity separation; scoped authorization; credential binding/revocation; audit correlation.
- **P0 — Evidence:** immutable references for release/run/provider operation and verification outcome.
- **P1 — OpenKruise Agents adapter:** SandboxClaim/Set lifecycle, warm pool, pause/resume, network policy and credential injection references.
- **P1 — Federation and multi-cluster:** explicit provider bindings and canonical IDs.
- **P1 — UI:** operate the API contracts, with no duplicate business authority.
- **P2 — GPU workloads:** integrate with Compute Control Plane and mature queue/scheduler providers.

## Non-goals

This project does not implement a new Agent framework, model serving stack, durable workflow engine, sandbox runtime, MCP gateway, enterprise IAM, policy language or GPU scheduler. It does not treat a model response or workflow history as authorization evidence.

## Development status

This repository is the rewrite target. The architecture contract and P0 Golden Path should be established before broad feature porting. Legacy functionality is not presumed to be part of the new public contract; migrate only after mapping ownership, invariants and acceptance evidence.

## Documentation

- [Architecture baseline](docs/architecture/BASELINE.md)
- [P0 Golden Path](docs/roadmap/P0-GOLDEN-PATH.md)
