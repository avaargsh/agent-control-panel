# Read-only disposition inspection (POC)

The nested Go module exposes `(*DispositionJournal).InspectDisposition`
for diagnosis of one known source stream, durable consumer and positive
stream sequence. Use the same trusted POC configuration as the receiver and
already-authorized PostgreSQL and NATS connections. This is an internal
diagnostic API, not a production operator endpoint or an approval mechanism.

```go
observation, err := journal.InspectDisposition(ctx, js, cfg, sourceSequence)
if err != nil {
    // Stop: the evidence could not be reliably inspected.
    return err
}
// observation.JournalState and observation.BrokerState are diagnostics only.
```

| Journal state | Broker state | Interpretation |
| --- | --- | --- |
| NOT_FOUND | NOT_CHECKED | No journal row at the exact key; no settlement authority. |
| NOT_STARTED | MISSING | Publication has not been claimed at the observed instant. |
| ATTEMPT_UNCONFIRMED | MATCHING | Retained bytes match journal; confirmation still not recorded. |
| ATTEMPT_UNCONFIRMED | MISSING | Ambiguous publication; stop and escalate. |
| CONFIRMED | MATCHING | Retained bytes match; not proof of source ACK. |
| CONFIRMED | MISSING | Previously confirmed evidence is no longer present; escalate. |
| Any existing state | MISMATCH | Evidence conflict; escalate. |

A broker stream lookup failure, permission error, transport error or
inconsistent configured DLQ identity is an error, never proof that a
message is absent. Any other combination must be investigated. The reads
are not a distributed snapshot; the states may change between reads or
immediately afterward.

The inspector does not return raw payloads, create a journal row, confirm a
publication, republish, delete, or acknowledge source messages. Do not use
its result to issue any of those actions. No production tenant authorization,
operator identity, audit workflow or reconciliation permit is implemented.

Run the real PostgreSQL/NATS test using disposable fixtures from the POC
README:

```sh
go test -race -count=1 -v -run '^TestRealDispositionInspectionIsReadOnlyAndDistinguishesEvidence$' .
```

The named test must report PASS, not SKIP. To exercise a real broker
publication whose PostgreSQL confirmation failed, including the SELECT-only
test role and denied mutation attempts, run:

```sh
go test -race -count=1 -v -run '^TestRealDispositionInspectorWithRestrictedRoleAndAmbiguousPublish
```

This fixture uses an administrator-created NOLOGIN role and SET ROLE, not
an independently authenticated operator principal. It verifies that
inspection works with SELECT-only grants and that the journal remains
unconfirmed when retained evidence disappears. No production grants are
installed. See #16 for outstanding governance and production recovery work.

## Local command (disposable fixtures only)

From the nested module, build and run the read-only diagnostic command:

```sh
go build -o /tmp/acp-disposition-inspect ./cmd/disposition-inspect
/tmp/acp-disposition-inspect -help
```

Use a separately prepared disposable PostgreSQL schema named
`test_jetstream_<digits>` containing the POC journal, and a local NATS server
containing the corresponding DLQ stream. Supply `PGTEST_DSN`,
`NATS_POC_URL` and `ACP_POC_SCHEMA` in the environment. Do not put
credentials in command-line flags or logs. The command deliberately
requires numeric loopback endpoints and does not create schemas, streams,
or records. PostgreSQL connections request server-side read-only transactions.
Use a SELECT-only database role and appropriately restricted NATS identity
where available; loopback and schema naming alone are not security boundaries.

```sh
/tmp/acp-disposition-inspect \
  -source-stream SOURCE -source-consumer DURABLE \
  -dlq-stream DLQ -dlq-subject poc.dlq -sequence 1
```

The values above are placeholders for the existing disposable fixture's
exact stream, consumer, prefix and source sequence. Example diagnostic
output (not settlement authorization):

```json
{"JournalState":"ATTEMPT_UNCONFIRMED","BrokerState":"MATCHING"}
```

Exit 0 means that the observation completed, not that it is safe to ACK
or republish. Exit 1 means inspection/output failed; exit 2 means input
validation failed. Errors are intentionally generic and do not include
DSNs or evidence payloads. This command supports local NATS endpoints only,
not the separate mTLS fixture or production brokers.

The one-command demo creates and cleans up its own temporary fixtures,
so those fixtures are no longer available to inspect after it exits.
To validate the command against actual fixtures, run:

```sh
go test -race -count=1 -v -run '^TestDispositionInspectCLI' .
```

The live test requires the disposable PostgreSQL/NATS configuration described
in the POC README. It also builds a race-enabled CLI executable and runs it
as a separate OS process against the same retained evidence; require the
named test PASS (not SKIP) and JETSTREAM_DISPOSITION_CLI_LIVE_EXEC_PASS.
 .
```

This fixture uses an administrator-created NOLOGIN role and SET ROLE, not
an independently authenticated operator principal. It verifies that
inspection works with SELECT-only grants and that the journal remains
unconfirmed when retained evidence disappears. No production grants are
installed. See #16 for outstanding governance and production recovery work.

## Local command (disposable fixtures only)

From the nested module, build and run the read-only diagnostic command:

```sh
go build -o /tmp/acp-disposition-inspect ./cmd/disposition-inspect
/tmp/acp-disposition-inspect -help
```

Use a separately prepared disposable PostgreSQL schema named
`test_jetstream_<digits>` containing the POC journal, and a local NATS server
containing the corresponding DLQ stream. Supply `PGTEST_DSN`,
`NATS_POC_URL` and `ACP_POC_SCHEMA` in the environment. Do not put
credentials in command-line flags or logs. The command deliberately
requires numeric loopback endpoints and does not create schemas, streams,
or records. PostgreSQL connections request server-side read-only transactions.
Use a SELECT-only database role and appropriately restricted NATS identity
where available; loopback and schema naming alone are not security boundaries.

```sh
/tmp/acp-disposition-inspect \
  -source-stream SOURCE -source-consumer DURABLE \
  -dlq-stream DLQ -dlq-subject poc.dlq -sequence 1
```

The values above are placeholders for the existing disposable fixture's
exact stream, consumer, prefix and source sequence. Example diagnostic
output (not settlement authorization):

```json
{"JournalState":"ATTEMPT_UNCONFIRMED","BrokerState":"MATCHING"}
```

Exit 0 means that the observation completed, not that it is safe to ACK
or republish. Exit 1 means inspection/output failed; exit 2 means input
validation failed. Errors are intentionally generic and do not include
DSNs or evidence payloads. This command supports local NATS endpoints only,
not the separate mTLS fixture or production brokers.

The one-command demo creates and cleans up its own temporary fixtures,
so those fixtures are no longer available to inspect after it exits.
To validate the command against actual fixtures, run:

```sh
go test -race -count=1 -v -run '^TestDispositionInspectCLI' .
```

The live test requires the disposable PostgreSQL/NATS configuration described
in the POC README. It also builds a race-enabled CLI executable and runs it
as a separate OS process against the same retained evidence; require the
named test PASS (not SKIP) and JETSTREAM_DISPOSITION_CLI_LIVE_EXEC_PASS.
