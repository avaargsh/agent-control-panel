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

### Build and run the local operations service

Prerequisites: Git, curl, and the Go version declared by [`go.mod`](go.mod) (prefer the patched version pinned in [CI](.github/workflows/go.yml)). These commands use a POSIX shell on Linux or macOS. The initial build may need network access to download Go modules. The local operations service does not need PostgreSQL, Runtime, Guard, or credentials.

```sh
git clone https://github.com/avaargsh/agent-control-panel.git
cd agent-control-panel
go version
mkdir -p bin
go build -o bin/agent-control-panel ./cmd/agent-control-panel
./bin/agent-control-panel
```

`./bin/agent-control-panel -version` prints the version, commit, and build date, then exits without listening or reading the environment. `-h` and `-help` print usage and exit the same way. If not injected, the version is `devel`; the commit and modified state use `vcs.revision` and `vcs.modified` when available. The build date must be injected; a commit timestamp is not a build date. Unavailable metadata prints as `unknown`. To start the listener, omit all arguments.

```sh
./bin/agent-control-panel -version
go build -ldflags "-X main.version=v0.1.0 -X main.commit=abc123 -X main.buildDate=2026-11-28T00:00:00Z -X main.modified=false" -o bin/agent-control-panel ./cmd/agent-control-panel
```

`LISTEN_ADDR` defaults to `127.0.0.1:8080`. The `control plane listening` log reports the actual bound address. If port 8080 is busy, run `LISTEN_ADDR=127.0.0.1:0 ./bin/agent-control-panel` instead; the OS assigns a free loopback port. Keep the service running in this terminal.

In another terminal, set `ADDR` to the address printed by the service (replace the example below when using a dynamic port):

```sh
ADDR=127.0.0.1:8080
curl --fail --show-error --silent "http://$ADDR/livez"
curl --fail --show-error --silent "http://$ADDR/readyz"
curl --fail --show-error --silent "http://$ADDR/api/v1/meta"
```

Expected responses, respectively: `ok`, `ready`, and a JSON object with `service` equal to `agent-control-panel` and `api_version` equal to `v1`. Readiness confirms the local HTTP process is available, not database connectivity or end-to-end execution readiness. Stop the service with Ctrl-C in its terminal. To remove the local build, delete `bin/agent-control-panel` from the repository checkout.

For source development, `go run ./cmd/agent-control-panel` remains an alternative. Keep the operations listener on loopback for this demo; the endpoints are not a production deployment interface.

Run the Go test suite with `go test -race ./...`. PostgreSQL tests require `PGTEST_DSN` pointing to an isolated test database. The [Go and PostgreSQL workflow](.github/workflows/go.yml) shows the CI setup. The [RunIntent admission guide](docs/implementation/RUNINTENT-ADMISSION.md) documents the opt-in live identity-provider test.

To try the Goal CLI with the bundled manifest, follow the [offline Issue Goal demo](docs/implementation/ISSUE-GOAL-PREPARE.md#try-the-offline-demo). The demo needs no database or GitHub credentials.

For a disposable real PostgreSQL/JetStream recovery demonstration, see the [local integration demo](experiments/jetstream-poc/LOCAL-REPRO.md). It is not a deployable broker worker or production acceptance.

## Changes and release evidence

Use the [PR evidence template](.github/PULL_REQUEST_TEMPLATE.md) to record the base and head commits, affected authority boundaries, verification, and any open gates. CI evidence applies to the tested commit, environment, and assertions. Changes that enable Runtime dispatch, protected effects, or provider mutations require evidence from the services that own those operations.

## Documentation

- [Domain ownership](docs/architecture/DOMAIN-OWNERSHIP.md)
- [Architecture baseline](docs/architecture/BASELINE.md)
- [P0 Golden Path design](docs/roadmap/P0-GOLDEN-PATH.md)
- [Workspace manifest persistence](docs/implementation/WORKSPACE-MANIFEST-CAS.md)
