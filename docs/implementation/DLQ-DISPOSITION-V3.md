# DLQ disposition v3 — versioned schema contract (Draft)

Parent: [ACP Draft PR #19](https://github.com/avaargsh/agent-control-panel/pull/19) stacked on
[JetStream POC PR #17](https://github.com/avaargsh/agent-control-panel/pull/17).
P0 acceptance: [Issue #16](https://github.com/avaargsh/agent-control-panel/issues/16).

## Purpose and ownership

The embedded, checksum-pinned `migrations/0003_dlq_dispositions.sql`
adds a durable ACP **schema contract** for immutable DLQ disposition intent,
source delivery identity, evidence hash/bytes and monotonic publication
fencing. It does **not** connect or enable a broker adapter; the JetStream
experiments still use their own disposable `poc_dlq_dispositions` table.
The schema is controlled by ACP's existing transactional `Migrate` runner
and recorded as version 3 in `schema_migrations`, while v1/v2 source files
remain untouched.

- Unique authority: `(source_stream,source_consumer,source_sequence)` is one
  source broker delivery, with `tenant_id` and `consumer_name` retained as
  immutable evidence attributes. Mapping to a trusted authenticated tenant
  principal and binding the broker source to that tenant is **not yet
  implemented**; this table must not be treated as a permission decision.
- Stable identity, digest, reason, configured DLQ target and evidence bytes
  cannot be overwritten. `publish_started` can advance false→true;
  `published` may advance false→true only after the attempt fence is set;
  confirmed records cannot be rolled back or have their timestamps changed.
- A trigger rejects DELETE, TRUNCATE and unsafe UPDATE. PostgreSQL CHECK
  predicates provide additional independent state invariants.
- The migration runner validates the current relation and ordered primary
  key, enabled row/statement triggers (`tgtype`, `tgattr`, `tgqual`,
  `tgfoid`), the exact PL/pgSQL function source and security attributes,
  PostgreSQL-compiled critical CHECK predicates and absence of grants to
  `PUBLIC` on the table/function. A matching filename/ledger checksum
  alone is never sufficient to prove live catalog integrity.
- When the history records v3, missing or weakened guards **fail closed**
  with `ErrSchemaDrift`; they are never silently recreated. An existing
  relation without v3 ledger is **unversioned**, not automatically adopted.

## DB privilege contract (not provisioned by migration)

`0003` explicitly removes `PUBLIC` access but **does not create a
runtime user or authorize any service**. The test suite uses an admin session
and `SET LOCAL ROLE` to validate a disposable `NOLOGIN` role; it grants
only schema USAGE, table SELECT, column-scoped INSERT of immutable identity
and evidence columns, and UPDATE on
`(publish_started,published,published_at)`. It proves denial of direct
status-column INSERT, evidence/tenant UPDATE, DELETE/TRUNCATE and DDL.
The trigger additionally denies rollback with an SQLSTATE error.

This is **not sufficient** production IAM: a role permitted to update
publication fields is still a trusted writer; the database cannot verify a
broker PubAck by itself. Table-wide SELECT is not tenant-restricted and
must not be deployed before an independently ratified tenant isolation
model. Privileged DB owners/superusers can modify the guards, while a real
service may require separate credentials and an independently controlled
migration/verification role.

## Validation and rollout gates

The root Go/PostgreSQL CI uses PostgreSQL 16 and executes `Migrate` from
fresh schema and simulated recorded-v2 upgrades, checks v3 checksum,
immutable behavior, trigger/catalog/CHECK drift and a restricted role.
The nested JetStream CI separately tests real NATS with the existing POC
adapter. The two CI jobs are different evidence types and do not form
a production golden path.

Before merging/promoting: implement and review production DB role provisioning,
tenant-scoped RLS/credential boundary or equivalent isolated catalogs,
migration ownership separation from runtime, restore and failover tests with
immutable evidence, real broker source auth/mTLS/ACL, authorized manual
UNKNOWN reconciliation and ACP↔Runtime G01/G05 staging. The NATS DLQ
PubAck and source ACK are **not atomically committed** with PostgreSQL.

**Merge policy: Draft #19, #17, #15 and #7; P0 #16 remains open.**
