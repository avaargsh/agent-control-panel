# Authority Cutover: Shared-Object DCL Procedure

## Scope and security boundary

The database-local `ddl_command_start` event trigger installed by
`migrations/authority-cutover/0003_acl_change_barrier.sql` fences local
relation, schema, sequence and routine DDL/ACL changes. PostgreSQL does not
fire event triggers for shared-object commands such as role definitions,
role memberships, databases and tablespaces.

Therefore, the event trigger alone does **not** serialize `GRANT role TO`,
`REVOKE role FROM`, or other shared-object DCL with an admitted authority
request. A trusted cluster administrator must use the explicit procedure
below. This is an operational control, not protection against a malicious or
uncoordinated superuser.

The request path holds a shared session advisory lock on
`0x41435044444c464e` (decimal `4702690690038777422`) through the final HTTP
response flush. Local DDL obtains the matching transaction-exclusive lock
through the event trigger. Shared-object DCL must acquire that same key
explicitly.

## Required cutover sequence

1. Use the trusted ACP coordinator to persist `OPEN -> DRAINING`, drain all
   in-flight requests, and acquire the exclusive admission `CutoverLease`.
   Keep the durable state non-`OPEN` and retain the exclusive admission lock
   throughout the shared-object change.
2. In the same PostgreSQL database used by the ACP authority service, execute
   role membership changes in a transaction that acquires the DDL fence first:

   ```sql
   BEGIN;
   SET LOCAL lock_timeout = '30s';
   SELECT pg_catalog.pg_advisory_xact_lock(4702690690038777422);

   -- Example only: replace with the narrowly scoped, approved change.
   -- GRANT acp_cutover_observer TO acp_authority_reader;
   -- REVOKE acp_cutover_observer FROM acp_authority_reader;

   COMMIT;
   ```

   Do not run shared-object `GRANT`/`REVOKE` outside the fenced transaction.
   If the lock times out, the transaction must abort without applying DCL.
3. Re-attest the Coordinator and every Observer using their independently
   authenticated LOGINs on the actual service backends. Verify role
   membership, ADMIN OPTION, role flags, effective ACLs and the expected
   owner-managed catalog state. A successful DCL statement is not sufficient
   evidence that the service roles remain least-privileged.
4. Record the observed DCL outcome and complete the durable cutover state
   transitions. Reopen admission only after the exact expected role state has
   been independently read back and all required service identities pass
   re-attestation.
5. If the DCL transaction loses its connection or COMMIT acknowledgement,
   treat the outcome as unknown. Keep admission closed, inspect
   `pg_auth_members` and `pg_roles` using an independent trusted administrator,
   then reconcile. Never blindly replay an uncertain permission change.

## Operational constraints

- Advisory locks are database-scoped. Use distinct service LOGINs and role
  memberships per service database. If a shared cluster role affects service
  identities in multiple databases, this single-database fence is insufficient:
  coordinate the admission and DDL barriers in every affected database before
  changing the cluster-wide role membership.
- A cluster superuser can bypass this procedure, disable or replace the event
  trigger, or alter the advisory-lock protocol. Superusers and cluster
  administrators remain trusted principals; this design does not claim
  arbitrary-DBA atomicity.
- Do not issue Guard Permits, dispatch AgentD commands, or infer physical
  resource release from a successful database cutover. Runtime, EngageGuard
  and Compute Control Plane retain their respective authority boundaries.
- Keep the authority service fail-closed if the event trigger is absent,
  disabled, or does not match the expected function and lock key.
