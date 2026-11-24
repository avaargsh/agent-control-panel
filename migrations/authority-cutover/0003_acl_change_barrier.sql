-- Serialize local DDL against in-flight authority reads.
-- Run as a PostgreSQL cluster administrator: CREATE EVENT TRIGGER is
-- superuser-only. The request path holds a session-level shared advisory lock
-- with the same key until the HTTP response has been flushed. This event
-- trigger takes the transaction-level exclusive lock for local DDL, including
-- GRANT and REVOKE, so those changes cannot commit inside an admitted read.
--
-- PostgreSQL event triggers do not fire for commands targeting shared objects
-- (roles, databases and tablespaces). Changes to those objects remain in the
-- trusted cluster-administrator/cutover procedure; superusers are outside the
-- protection boundary of this local-object fence.
BEGIN;

CREATE OR REPLACE FUNCTION public.acp_authority_catalog_change_fence()
RETURNS event_trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $function$
BEGIN
    PERFORM pg_catalog.pg_advisory_xact_lock(4702690686029549398);
END;
$function$;

COMMENT ON FUNCTION public.acp_authority_catalog_change_fence() IS
    'Transaction-scoped DDL fence paired with ACP authority request shared advisory leases';

DROP EVENT TRIGGER IF EXISTS acp_authority_catalog_change_fence;

CREATE EVENT TRIGGER acp_authority_catalog_change_fence
    ON ddl_command_start
    EXECUTE FUNCTION public.acp_authority_catalog_change_fence();

COMMIT;
