# Run the JetStream Inbox demonstration locally

This is an isolated **non-production integration demo**, not an installable
ACP broker worker or an authorization boundary. It uses disposable PostgreSQL
and NATS containers, generated test credentials, random loopback ports, and
the actual Go receiver and journal code. Do not use a production Docker host
or database. No GitHub token or existing database is required.

## Prerequisites

- Linux (or a Linux development VM), Bash, Docker Engine running locally,
  OpenSSL, and a C compiler for the Go race detector.
- Go **1.27.4**, matching the audited toolchain in the repository CI.
- Network access for the first image/module downloads. PostgreSQL uses the
  same version-family tag as CI; the NATS image uses an immutable digest.

Clone the repository and select this change's branch/commit until it is
reviewed and merged. From the repository root:

```sh
bash experiments/jetstream-poc/run-local.sh
```

The script verifies prerequisites, starts disposable containers, waits for
readiness, runs the nested Go integration suite with the race detector, fails
on unexpected skips, checks named real-broker cases, then removes only the
containers it created and their anonymous volumes. It overrides inherited
`PGTEST_DSN` and `NATS_POC_URL` with its own local fixtures. Successful output
includes these markers:

```text
--- PASS: TestJetStreamRealBrokerAckLossConflictAndDLQFailure (...)
--- PASS: TestRealJetStreamCrashAfterPGCommitBeforeBrokerACK (...)
--- PASS: TestRealJetStreamCrashAfterConfirmedDLQBeforeSourceACK (...)
--- PASS: TestRealJetStreamCompetingDeliveriesSinglePublishThenRecovery (...)
--- PASS: TestRealJetStreamBrokerRestartPreservesConfirmedDLQ (...)
--- PASS: TestRealJetStreamMTLSAndTenantIsolation/AuthenticatedInboxDLQRecovery (...)
--- PASS: TestRealDispositionInspectorWithRestrictedRoleAndAmbiguousPublish (...)
--- PASS: TestDispositionInspectCLIRealEvidence (...)
--- PASS: TestDispositionInspectCLIRejectsUnsafeInputs (...)
JETSTREAM_DISPOSITION_CLI_LIVE_EXEC_PASS
JETSTREAM_DISPOSITION_CLI_SMOKE_PASS
JETSTREAM_LOCAL_REPRO_PASS
```

The demo also builds the actual disposition-inspect executable in a private
temporary directory, checks its help and invalid-argument exit status, and
removes the binary and temporary logs. The live test also builds and executes the actual command in a separate OS
process against PostgreSQL/NATS evidence, comparing its JSON output to the
verified helper result and checking that the journal remains unchanged. See the
[inspection guide](DISPOSITION-INSPECTION.md) for using the command on
separately prepared fixtures.

A nonzero exit is a failed demonstration, including failure to clean up.
If startup fails, the script prints bounded fixture logs. Check Docker daemon
access, image pull access, Go version, CGO/compiler availability, and local
resource availability. If the shell or host is forcibly terminated, list
your Docker containers and remove the particular abandoned demo containers
and their anonymous volumes after confirming their identity. Do not prune
unrelated containers or volumes.

For a manual test against **disposable** PostgreSQL and NATS instances, see
[the POC README](README.md). The manual command may skip integration tests
when those services are not configured; the demo rejects such skips.

## What the demo establishes

It exercises real broker deliveries, a durable PostgreSQL Inbox, ACK loss,
DLQ conflict settlement, receiver SIGKILL and redelivery, with durable
evidence verified in the test suite. The CI workflow
[`JetStream local reproduction`](../../.github/workflows/jetstream-local-demo.yml)
runs this same entry point when the demo changes.

A passing demo does not establish production broker authentication, tenant
IAM, physical disk durability, HA, or
an operationally approved UNKNOWN recovery procedure. See
[issue #16](https://github.com/avaargsh/agent-control-panel/issues/16) for the
remaining evidence gates. This demo does not start a production service,
dispatch Runtime work, grant permissions, or create a production migration.
