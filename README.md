# Agent Control Panel

Agent Control Panel (ACP) is the control plane for self-hosted agent workloads. It owns Tenant and Project scope, Agent and Release configuration, SessionIdentity, and durable RunIntent admission.

A RunIntent records ACP's acceptance of an execution request. Agent Runtime creates the canonical Run and Workflow IDs and owns execution, retries, and recovery. ACP can retain verified references to Runtime records. EngageGuard owns approvals and protected effects. External query executors retain authority over query execution. Sandbox and compute providers manage execution infrastructure.

## What this repository implements

| Component | Implementation |
|---|---|
| Operations HTTP service | [`cmd/agent-control-panel`](cmd/agent-control-panel) exposes liveness, readiness, and service metadata. Readiness reflects process availability. |
| RunIntent admission | [`internal/admission`](internal/admission) validates execution input and authorizes it against the ACP catalog. The PostgreSQL repository persists the admitted input, principal snapshot, RunIntent, and Outbox event in one transaction. Admission is an internal Go interface. |
| RunIntent persistence and messaging | [`internal/runintent`](internal/runintent) and [`internal/inboxtransport`](internal/inboxtransport) implement PostgreSQL persistence, transactional Outbox publishing, ordered Inbox consumption, and transport handling. Schema changes live in [`migrations`](migrations). |
| Runtime reconciliation | [`internal/runtimeinspect`](internal/runtimeinspect) provides an authenticated, read-only client for inspecting RunIntent outcomes. Ambiguous outcomes remain `UNKNOWN` until reconciled with Runtime. |
| Internal execution authority | [`cmd/acp-authority-api`](cmd/acp-authority-api) serves tenant-scoped RunIntent lookups over mTLS with read-only PostgreSQL access. It can also serve signed Decision publication records when configured with release artifacts and a signing key. |
| Workspace persistence | [`internal/workspace`](internal/workspace) and the PostgreSQL repository implement manifest revisions, upload recovery, and verified reads of S3-compatible objects. |

The operations HTTP service exposes GET endpoints only. The table describes repository components and does not establish production deployment or authorize Runtime dispatch, protected effects, or provider mutations.

## Local development

Use the Go version declared by [`go.mod`](go.mod) or the patched version pinned in [CI](.github/workflows/go.yml).

```sh
go run ./cmd/agent-control-panel
```

In another terminal:

```sh
curl --fail http://127.0.0.1:8080/livez
curl --fail http://127.0.0.1:8080/readyz
curl --fail http://127.0.0.1:8080/api/v1/meta
```

`LISTEN_ADDR` defaults to `127.0.0.1:8080`.

Run the Go test suite with `go test -race ./...`. PostgreSQL tests require `PGTEST_DSN` pointing to an isolated test database. The [Go and PostgreSQL workflow](.github/workflows/go.yml) shows the CI setup. The [RunIntent admission guide](docs/implementation/RUNINTENT-ADMISSION.md) documents the opt-in live identity-provider test.

## Changes and release evidence

Use the [PR evidence template](.github/PULL_REQUEST_TEMPLATE.md) to record the base and head commits, affected authority boundaries, verification, and any open gates. CI evidence applies to the tested commit, environment, and assertions. Changes that enable Runtime dispatch, protected effects, or provider mutations require evidence from the services that own those operations.

## Documentation

- [Domain ownership](docs/architecture/DOMAIN-OWNERSHIP.md)
- [Architecture baseline](docs/architecture/BASELINE.md)
- [P0 Golden Path design](docs/roadmap/P0-GOLDEN-PATH.md)
- [Workspace manifest persistence](docs/implementation/WORKSPACE-MANIFEST-CAS.md)
