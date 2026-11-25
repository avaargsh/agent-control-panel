# Real JetStream + PostgreSQL Inbox POC (Draft)

Parent chain: [ACP #17](https://github.com/avaargsh/agent-control-panel/pull/17) →
[#15](https://github.com/avaargsh/agent-control-panel/pull/15) →
[#7](https://github.com/avaargsh/agent-control-panel/pull/7).
Scope gate: [P0 issue #16](https://github.com/avaargsh/agent-control-panel/issues/16).

**Not a deployable broker receiver or production-ready DLQ.** The experiment is
deliberately isolated in its own Go module and CI workflow. It introduces no
NATS dependency into the ACP service's root `go.mod` and does not change
checksum-recorded PostgreSQL v1/v2 migrations.

## Reproduce

From the repository root, run `bash experiments/jetstream-poc/run-local.sh`.
See [local reproduction](LOCAL-REPRO.md) for prerequisites and cleanup, and
[read-only disposition inspection](DISPOSITION-INSPECTION.md) for UNKNOWN diagnosis.

For manual disposable fixtures:

1. Run PostgreSQL 16 with an account permitted to create disposable schemas.
2. Run an **actual** NATS Server 2.15.2 with JetStream enabled. The POC pins
   the official multi-platform image manifest:
   `nats:2.15.2@sha256:b6c40dcfe5ae9174dcafa9c43f800afb93b8b0ffcde02ac00efc6b66031d9a50`.
3. Set `PGTEST_DSN` and `NATS_POC_URL`; from this directory run
   `go mod verify && go test -race -count=1 -v ./...`.
4. The mTLS test creates a separate disposable JetStream server, a temporary
   CA and server/client certificates. It requires a mapped client certificate
   and verifies two isolated NATS accounts with separate JetStream streams
   and subject ACLs.
5. On GitHub Actions, `.github/workflows/jetstream-poc.yml` starts the real
   server and PostgreSQL 16, verifies the pinned nested module, runs the
   race-enabled integration suite, and repeats the mTLS test on the literal
   PR source SHA.

## Implemented and exercised contract

- A named FileStorage stream and durable pull consumer with explicit
  acknowledgments are created on the **running NATS server**, not mocked.
- For an ordinary event, PostgreSQL receives it durably before the broker
  confirms `DoubleAck`. Lost/withheld ACK causes real JetStream redelivery,
  while `(consumer_name,event_id)` is still one durable Inbox row.
- A changed payload reusing an already APPLIED event ID is appended to
  `inbox_event_conflicts`. A metadata-only DLQ record includes source
  stream/consumer/subject/stream-sequence, reason and body SHA-256. The source
  is `DoubleAck`ed **only after** a confirmed DLQ `PubAck` from the expected
  stream.
- Injecting a wrong expected DLQ stream causes publish failure and prevents
  source ACK. JetStream redelivers; a later successful delivery persists the
  next DLQ record without duplicating the PostgreSQL archive entry.
- A separate OS process receives the **real JetStream** delivery, commits
  PostgreSQL state, then receives `SIGKILL` immediately before ACK. A newly
  connected process observes actual JetStream redelivery, keeps one Inbox
  record and applies exactly one ordered cursor version.
- The separate mTLS integration uses NATS `verify_and_map` to map a client
  certificate subject to an allowlisted workload identity. The raw broker INFO
  greeting advertises required TLS; the test does not independently establish
  wire-level plaintext rejection. TLS clients without certificates and
  CA-trusted but unmapped client certificates are rejected. Two NATS accounts each create and publish to their
  own JetStream stream. A cross-account stream lookup must return stream
  not found. A cross-tenant Core NATS publish and subscription must each
  return a broker permissions violation for the attempted operation.
  The test generates temporary certificates and keys. Both mapped accounts
  also exercise actual Inbox/DLQ settlement and ACK-loss recovery.
- Additional candidate tests exercise exclusive publish claims, competing
  real deliveries, FileStorage rejection of volatile DLQ streams, isolated
  broker SIGKILL/start with retained evidence and ACK rollback recovery,
  and read-only disposition diagnosis with a SELECT-only test role.
  Individual candidate evidence is not joint acceptance; consult exact-head CI.

## PostgreSQL journal integrity and restricted-role test

The isolated POC migration now uses one PostgreSQL transaction for first
creation and installs a row-level `BEFORE UPDATE OR DELETE` trigger and
statement-level `BEFORE TRUNCATE` trigger. Allowed state changes are monotonic
only (`publish_started=false→true`, then `published=false→true`).
Immutable identity, digest, evidence payload, creation and confirmation
timestamps cannot be overwritten. The broker adapter still independently
verifies retained DLQ evidence before the source ACK.

When `Migrate` finds an **existing** journal table it does not recreate or
silently repair any guard. It checks the PostgreSQL catalog for the exact
primary-key column order, both pinned CHECK predicates, enabled trigger event
bitmaps, unrestricted update column scope, absent `WHEN` clauses and the
expected PL/pgSQL function source/security attributes. A mismatch yields
`ErrDispositionSchemaDrift`.

A PostgreSQL 16 test-only `NOLOGIN` worker role with schema `USAGE`,
table `SELECT/INSERT` and column-specific
`UPDATE(publish_started,published,published_at)` proves that routine
settlement state writes are possible while direct evidence edits, DELETE,
TRUNCATE and DDL fail with insufficient privilege. An attempted state rollback
also fails through the database trigger. This uses `SET LOCAL ROLE` from the
test administrator, **not** a deployed service credential. The guard verifies
catalog state when the POC migration is called; a privileged actor could still
alter or disable guards afterward unless real deployment IAM and operational
reverification are implemented.

## Explicitly not proven

- **DLQ publish + source ACK remains non-atomic across JetStream and PG.**
  This POC now includes a schema-local PostgreSQL disposition journal keyed by
  `(source_stream,source_consumer,source_sequence)`, immutable evidence bytes,
  and a confirmed publication state. JetStream DLQ uses one hashed subject
  per disposition with `DiscardNewPerSubject` and `MaxMsgsPerSubject=1`,
  retaining just one record even after the `Nats-Msg-Id` dedup window.
- A crash after a successful DLQ PubAck **but before journal confirmation**
  now retains a PostgreSQL `publish_started` fence written before any
  JetStream publish attempt. On retry, an existing exact retained broker
  record is verified and marked confirmed; if it has vanished, the worker
  returns `ErrDLQPublishUncertain` and does **not** republish or ACK.
  A PostgreSQL trigger-injected failure between real PubAck and journal
  confirmation verifies this fail-closed behavior. Operator resolution for
  the indefinite UNKNOWN state is still an unimplemented governance gate.
- Privileged broker deletion/purge, DLQ stream recreation, administrative
  journal/catalog tampering **after startup verification**, multi-worker
  races across independent competing worker processes, retention expiry and
  network partition are not independently accepted.
  The journal table, trigger migration and test role all live in disposable
  POC schemas. No production ACP migration, independently provisioned DB
  identity, grant-revocation/restore drill or hardened least-privilege contract
  exists yet.
- The existing ACK/DLQ process-fault tests still use an unauthenticated
  single-node NATS container. The separate mTLS test exercises Inbox/DLQ
  recovery and account isolation but not cross-process crash recovery over mTLS.
- No SPIFFE integration, certificate rotation/revocation, JetStream quorum/HA,
  physical disk durability or power-loss proof, approved DLQ confidentiality/replay
  controls, bounded poison-message policy, redelivery budget, metrics,
  rate limits, process supervisor, or cross-tenant load test is accepted.
- No authenticated ACP→Runtime `StartRun` path, initiating
  subject/actor/policy snapshot or G01/G05 staging golden-path acceptance.
- The POC image is pinned to an immutable multi-platform manifest digest, but
  that alone is not full supply-chain attestation or production image approval.

**Merge boundary:** #16 remains open and #107 requires actual main branch
protection and manual approval. Single-node POC evidence cannot authorize
production. Record exact-head workflow links before treating any revision
as tested.
