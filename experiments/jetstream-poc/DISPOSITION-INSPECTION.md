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
 .
```

This fixture uses an administrator-created NOLOGIN role and SET ROLE, not
an independently authenticated operator principal. It verifies that
inspection works with SELECT-only grants and that the journal remains
unconfirmed when retained evidence disappears. No production grants are
installed. See #16 for outstanding governance and production recovery work.
