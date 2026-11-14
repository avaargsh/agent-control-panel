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
| RunIntent | ACP-owned, durably accepted desired execution request; not a Run or execution receipt |
| Run | Runtime-owned execution record and lifecycle, exposed here only as a verified read-only projection |
| FederationBinding | Binding to a remote control plane/provider |
| CredentialBinding | References to external credential authorities; never raw secret material |
| ContextProjectionPolicy | Rules for selecting/projecting context into an execution |
| Evidence | Immutable references and attestations for lifecycle and execution outcomes |

The Control Plane owns logical Agent/Session identity, RunIntent and desired state. **Agent Runtime alone creates canonical `run_id`/`workflow_id` and owns Run/Task/Attempt state**; ACP may retain verified, access-controlled references to those records. It does not duplicate workflow history, worker scheduling, step retries, checkpoints or sandbox internals.

## Responsibility boundaries

- **Agent Control Plane:** domain resources, desired state, lifecycle coordination, authorization delegation, release governance, federation and evidence links.
- **Agent Runtime / workflow engine (Temporal or compatible):** durable execution, step semantics, retries, waits, checkpoints and worker orchestration.
- **Sandbox Provider (OpenKruise Agents, OpenSandbox, etc.):** isolated execution environment lifecycle, filesystem/runtime and sandbox-level network enforcement.
- **Compute Control Plane (`compute-control-panel`):** cluster/provider inventory, compute allocation and accelerator lifecycle.
- **Identity / secrets / policy:** integrate Keycloak or an OIDC provider, OpenBao/Kubernetes Secret, and mature policy systems (OPA/Casbin/Cedar) through adapters.
- **`agent-control-panel` UI:** operator and developer UX only; no separate authority or lifecycle source of truth.

`gpu-compute-platform` is retired as an active delivery repository and is retained only as historical migration/reference material. New Compute implementation and release evidence belong exclusively to `compute-control-panel`.

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

## Merge governance and evidence boundaries

A green CI result is evidence only for its **exact commit, workflow, environment and exercised assertions**. A GitHub mergeable indicator, merged feature child PR, or historical test receipt does not establish production authorization. PRs must state the target (`main` or an internal feature branch), base/head SHAs, affected authoritative writer and interface revision, test/negative-case receipts, migrations/rollback, unresolved gates and explicit non-goals. See the [PR evidence template](.github/PULL_REQUEST_TEMPLATE.md).

For changes involving runtime dispatch, protected effects, or provider release, the relevant owners must verify the applicable cross-service gates before promotion to `main`: [G01 RunIntent/Run identity and lost ACK](https://github.com/avaargsh/agent-control-panel/issues/3), [G02 Decision wire compatibility](https://github.com/avaargsh/agent-decision/issues/9), [G03 Guard ActionHash/Permit authority](https://github.com/avaargsh/EngageGuard/issues/3), [G04 Compute provider release/reconciliation](https://github.com/avaargsh/compute-control-panel/issues/3), and [G05 durable PostgreSQL/Temporal golden path](https://github.com/avaargsh/agent-runtime/issues/5). These issue references define review scope, **not** a claim that any gate has passed.

Documentation-only governance corrections may be merged independently when they do not enable a runtime path, publish an unratified protocol as authoritative, or misrepresent historical PR topology as current. A Draft implementation stacked on a non-main parent is **not approved for main** merely because its local tests pass. External side-effect outcomes in `UNKNOWN` remain `UNKNOWN` until inspected by their owning service; do not blindly dispatch, mark FAILED, or finalize cost. Branch protection/required-check enforcement is a separate repository-settings obligation and is **not** established by this README or the PR template.

## Documentation

- [Architecture baseline](docs/architecture/BASELINE.md)
- [P0 Golden Path](docs/roadmap/P0-GOLDEN-PATH.md)
