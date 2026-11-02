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

## Implementation status

### Implemented: P0 Run Core

- PostgreSQL-backed Session and Run persistence.
- Tenant-scoped Run retrieval.
- Run state machine with optimistic version checks.
- Atomic idempotency-key claim and request-hash conflict detection.
- Transactional outbox append for Run creation and state transitions.
- HTTP API for Run create/get/transition with strict JSON decoding and uniform errors.
- Loopback-only HTTP binding while authentication middleware is absent.

### Not implemented yet

Outbox publisher/consumer, workflow adapter, Sandbox Provider adapter, authentication/authorization, AgentBundle and AgentRelease APIs, federation, Context Projection, Evidence verification and operator UI.

## Local development

Requirements: Go 1.23+, PostgreSQL 14+ and `psql`. Run `go mod tidy` once after cloning to resolve the pinned PostgreSQL driver and produce `go.sum`.

```bash
export DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/agent_control?sslmode=disable'
make migrate
make test
LISTEN_ADDR=127.0.0.1:8080 make run
```

The binary intentionally refuses non-loopback listen addresses until authenticated tenant identity and authorization middleware are implemented. `X-Tenant-ID` is currently a local-development tenant context only, not an authentication mechanism.

See [HTTP API v1](docs/api/HTTP-API.md), [Architecture Baseline](docs/architecture/BASELINE.md), [Runtime ADR](docs/architecture/decisions/0001-runtime-stack.md) and [P0 Golden Path](docs/roadmap/P0-GOLDEN-PATH.md).

## Non-goals

This project does not implement a new Agent framework, model serving stack, durable workflow engine, sandbox runtime, MCP gateway, enterprise IAM, policy language or GPU scheduler. It does not treat a model response or workflow history as authorization evidence.
