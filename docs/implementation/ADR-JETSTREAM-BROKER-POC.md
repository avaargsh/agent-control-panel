# ADR: NATS JetStream candidate for ACP Inbox broker POC

Status: **PROPOSED FOR POC ONLY — NOT RATIFIED FOR PRODUCTION**
Date: 2026-11-05
Tracks: [ACP #16](https://github.com/avaargsh/agent-control-panel/issues/16),
[ACP Draft PR #15](https://github.com/avaargsh/agent-control-panel/pull/15)

## Decision scope

Evaluate a **pinned NATS JetStream server + Go `nats.go/jetstream` client**
as the first actual-broker experiment for the existing ACP Inbox settlement
contract. This is a testing proposal, **not** permission to merge the stacked
Control Plane PRs or to select the broker for all platform services.

JetStream offers durable streams, durable pull consumers, explicit per-message
acknowledgments, confirmed consumer double-ACK and publish acknowledgments.
The existing ACP PostgreSQL Inbox remains the authority for event idempotency,
aggregate ordering, conflict evidence and projection commits.

## Required JetStream semantics

1. Configure a durable **pull consumer** with explicit acknowledgments and
   bounded in-flight messages. Do not use Core NATS pub/sub or AckAll for this
   acceptance gate. Pin the server/client versions and test them together.
2. The source delivery is terminally ACKed only after PostgreSQL commits.
   Prefer `jetstream.Msg.DoubleAck(ctx)` to confirm the server accepted the
   consumer ACK. If an ACK times out, the result is **uncertain**, not
   proof that no ACK occurred; PostgreSQL idempotency must absorb redelivery.
3. JetStream does **not** provide an automatic durable dead-letter queue. A
   MaxDeliver advisory or `Term()` alone does not satisfy the requirement to
   retain a conflicting payload. An explicit DLQ stream and operator policy
   must be deployed and independently verified.
4. For a conflicting or quarantined delivery, publish the complete approved,
   redacted evidence envelope to a DLQ stream with a deterministic identity
   including the source stream/sequence, tenant, consumer, reason and canonical
   envelope digest. Require a positive JetStream `PubAck` from the expected
   DLQ stream. Only then double-ACK the source message.
5. DLQ publish and source ACK are **not one atomic transaction**. A crash
   after DLQ publication but before source ACK will redeliver and may
   republish to DLQ. JetStream's `Nats-Msg-Id` deduplication is limited by a
   configured window: **do not claim it provides permanent deduplication**.
   A durable, unique disposition journal/reconciler is needed before
   calling this path production-safe. A conflict after original APPLIED must
   never revert the original record or become a normal ACK.
6. Receiving a broker payload, publishing to DLQ or acknowledging it must
   use distinct least-privilege broker credentials. Verify subject and
   stream scope, tenant origin, payload sizes, DLQ retention and replay IAM.
   Checkpoint or event payload content cannot authorize replay.

## POC acceptance matrix (currently UNKNOWN)

| Injection | Mandatory observation |
| --- | --- |
| SIGKILL after PG commit / before source ACK | New process receives the same delivery; one Inbox row and one projection |
| ACK accepted but response lost | Duplicate is harmless; uncertain ACK never triggers second business execution |
| DB failure before commit | No source ACK; original delivery remains recoverable |
| Changed redelivery after original APPLIED | Immutable conflict archive, confirmed DLQ PubAck, no normal ACK |
| Crash after DLQ PubAck / before source ACK | Repeat is safe; no unreconciled duplicate terminal disposition |
| DLQ stream unavailable / PubAck timeout | Source is not falsely completed; alert and bounded redelivery |
| MaxDeliver exhausted | Advisory is not treated as a durable DLQ record; operator recovery exists |
| Dedup window exceeded | Durable idempotency still holds independent of broker `Nats-Msg-Id` |
| Tenant/subject spoof and unauthorized replay | Fail-closed authorization, audit trail |
| Restart and backlog | Correct gap blocking, ordered Inbox projection, DLQ and lag visibility |

Test in a real NATS process and PostgreSQL 16, with at least two OS
receiver processes for SIGKILL/ACK-loss. Record exact Git SHA, broker image
digest/version, Go client version, protocol/config, event IDs, SQL and broker
state before/after, logs and linked CI run. A single locally faked delivery
is **not** real-broker acceptance; a single broker node is **not** HA or
production resiliency evidence.

## Source contracts

- https://docs.nats.io/concepts/jetstream
- https://github.com/nats-io/nats.go/blob/main/jetstream/README.md
- https://github.com/nats-io/nats.go/blob/main/jetstream/message.go
- https://github.com/nats-io/nats.docs.v2/blob/main/learn/jetstream/acknowledgment.md
- https://github.com/nats-io/nats.docs/blob/master/using-nats/jetstream/model_deep_dive.md

## Deferred decisions

The exact server/client versions, DLQ stream naming/retention, immutable
disposition journal schema, consumer quotas and authN/authZ bindings require
service-owner review and a separate implementation PR. Kafka or another
broker remains a valid alternative if the above failure envelope cannot be
satisfied in the target deployment. ACP #16 stays OPEN and all stacked PRs
stay Draft.
