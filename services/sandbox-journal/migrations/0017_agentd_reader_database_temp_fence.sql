-- 0017: forward-only AgentD reader database TEMP privilege fence.
-- Preserve the exact deployed 0015 and 0016 bytes and their recorded checksums.
-- PostgreSQL grants TEMPORARY to PUBLIC on newly created databases by default.
-- This migration is ONLY for the dedicated Sandbox-owned PostgreSQL database.
-- Never apply to an ACP/shared database: revocation affects every DB login.
BEGIN;

DO $agentd_temp_revoke$
BEGIN
  IF to_regclass('public.sandbox_agentd_evidence_reader_tenants') IS NULL OR
     to_regclass('public.sandbox_agentd_attempts') IS NULL THEN
    RAISE EXCEPTION 'AgentD TEMP fence requires prior 0015/0016 schema'
      USING ERRCODE = '23514';
  END IF;
  EXECUTE format('REVOKE TEMPORARY ON DATABASE %I FROM PUBLIC', current_database());
END;
$agentd_temp_revoke$;

COMMIT;
