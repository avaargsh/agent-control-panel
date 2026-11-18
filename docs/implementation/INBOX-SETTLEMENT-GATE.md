# Inbox broker settlement gate — stacked Draft PR #15

This transport-neutral helper sits **after** `postgres.Repository.ReceiveInboxEvent`
and **before** any broker delivery is terminally settled. It is stacked on
[ACP PR #7](https://github.com/avaargsh/agent-control-panel/pull/7);
it does not select a broker or change the checksum-pinned PostgreSQL schema.

## Settlement contract

- `Receiver.ReceiveInboxEvent` must return success **only after the Inbox
  transaction has committed**, including immutable changed-redelivery evidence.
- A newly inserted event (`Inserted=true`) or unchanged duplicate
  (`Duplicate=true`) may be ACKed after the commit. **ACK is not proof
  that projection succeeded**: projection is handled by the separate
  ordered Inbox worker.
- `Conflict=true` is an explicit `EVENT_ID_CONFLICT` disposition, even
  when the original event is already `APPLIED` and `Quarantined=false`.
- Other `Quarantined=true` deliveries require `INBOX_QUARANTINED` disposition.
  Neither category may silently receive a successful normal ACK.
- A receive failure or an inconsistent receive result produces no settlement.
  An ACK or DLQ failure returns an error; the broker adapter must preserve
  its at-least-once redelivery/reconciliation responsibility.
- The concrete `Delivery.DeadLetter` implementation must be **durable,
  idempotent and terminal** before returning success. Different transports
  may implement this as a broker-native reject/DLQ or a verified durable
  transfer followed by safe source disposition. This package supplies no
  such implementation and guarantees no broker-level atomicity.

## Tests / evidence boundary

- Table-driven tests assert that settlement does not occur before successful
  durable receive; conflicts and quarantine route to DLQ, while database
  errors and failed settlement return explicit failures.
- PostgreSQL-backed integration test starts with committed Inbox intake,
  simulates a lost broker ACK, repeats the same delivery without duplicating
  the Inbox row, marks the original `APPLIED`, then verifies a conflicting
  replay is archived exactly once before invoking the simulated DLQ path.
- CI PostgreSQL 16 and `go test -race -count=1 ./...` validate only these
  repository and local-adapter behaviors; a fake broker callback is **not**
  a real broker or cross-process SIGKILL test.

## Required before promotion

1. Choose and implement a concrete broker receiver with independently
   verified ACK, DLQ durability, replay and delivery-idempotency semantics.
2. Test a receiver process killed after PostgreSQL commit but before ACK,
   then restart and verify unchanged redelivery and conflicting-redelivery
   handling against the real broker.
3. Prove identity/tenant controls, operator-supervised replay, DLQ alerts,
   least-privilege PostgreSQL deployment roles and retention.
4. Complete authenticated Runtime dispatch/reconciliation, subject/policy
   binding and G01/G05 staging gates.

**Keep PR #15, PR #7 and the parent stack Draft.** PostgreSQL-backed local
integration is not broker, Runtime, or production acceptance.
