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

1. Run PostgreSQL 16 with an account permitted to create disposable schemas.
2. Run an **actual** NATS Server 2.15.2 with JetStream enabled
   (`nats:2.15.2 -js -sd /data`).
3. Set `PGTEST_DSN` and `NATS_POC_URL`; from this directory run
   `go mod verify && go test -race -count=1 -v ./...`.
4. On GitHub Actions, `.github/workflows/jetstream-poc.yml` starts the
   real server and PostgreSQL 16, verifies the pinned nested module and runs
   this package's race-enabled integration suite.

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

## Explicitly not proven

- **DLQ publish + source ACK cannot be atomic across JetStream and PG.** A
  crash in between can duplicate DLQ records after the JetStream
  `Nats-Msg-Id` duplicate window. Permanent, operator-verified
  dispositions require an ACP-owned durable journal with unique identity,
  reconciliation and retention policy; the current POC does not implement it.
- The tests use a **single unauthenticated NATS container** and a privileged
  disposable PostgreSQL user. They do not demonstrate TLS/mTLS, SPIFFE,
  real tenant-scoped broker ACLs, role grants, external WORM evidence, JetStream
  quorum/HA, persistent volumes across server restart, or approved DLQ
  confidentiality/replay controls.
- Receiver decoding rejects malformed/unknown envelope fields and untrusted
  stream/consumer/subject metadata, but there is no production poison-message
  policy, bounded redelivery budget, metrics, rate limits, process supervisor,
  cross-tenant load test or external service authentication.
- No authenticated ACP→Runtime `StartRun` path, initiating
  subject/actor/policy snapshot or G01/G05 staging golden-path acceptance.
- The NATS image is version-tag pinned for repeatability but still requires a
  reviewed **immutable image digest** for release-grade supply-chain evidence.

**Merge verdict:** keep #17, #15 and #7 Draft. The real single-node broker
CI upgrades a narrow subset of P0 #16 evidence; it cannot close the full issue
or authorize production. Record exact-head workflow link and log artifacts in
the PR before treating any specific revision as tested.
