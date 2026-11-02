-- PostgreSQL 16 schema-level tenant isolation smoke test.
-- This transaction rolls back all fixtures after asserting invariants.
BEGIN;

INSERT INTO outbox_events (
 event_id,producer,event_type,schema_version,tenant_id,aggregate_type,
 aggregate_id,aggregate_version,occurred_at,correlation_id,payload
) VALUES
 ('00000000-0000-0000-0000-000000000101','agent-control-panel','agent.intent.created',1,
  'tenant-alpha','run_intent','shared-logical-id',1,now(),'corr-alpha','{}'::jsonb),
 ('00000000-0000-0000-0000-000000000102','agent-control-panel','agent.intent.created',1,
  'tenant-beta','run_intent','shared-logical-id',1,now(),'corr-beta','{}'::jsonb);

INSERT INTO inbox_events (
 consumer_name,event_id,producer,event_type,schema_version,tenant_id,
 aggregate_type,aggregate_id,aggregate_version,payload,state
) VALUES
 ('run-projection','00000000-0000-0000-0000-000000000201',
  'agent-runtime','agent.run.created',1,'tenant-alpha','run','shared-logical-id',1,'{}'::jsonb,'RECEIVED'),
 ('run-projection','00000000-0000-0000-0000-000000000202',
  'agent-runtime','agent.run.created',1,'tenant-beta','run','shared-logical-id',1,'{}'::jsonb,'RECEIVED');

INSERT INTO inbox_aggregate_claims (
 consumer_name,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_id
) VALUES
 ('run-projection','tenant-alpha','run','shared-logical-id',1,
  '00000000-0000-0000-0000-000000000201'),
 ('run-projection','tenant-beta','run','shared-logical-id',1,
  '00000000-0000-0000-0000-000000000202');

INSERT INTO inbox_cursors (
 consumer_name,tenant_id,aggregate_type,aggregate_id,last_applied_version
) VALUES
 ('run-projection','tenant-alpha','run','shared-logical-id',1),
 ('run-projection','tenant-beta','run','shared-logical-id',1);

DO $test$
DECLARE
  n integer;
BEGIN
  SELECT COUNT(*) INTO n FROM outbox_events
    WHERE aggregate_type='run_intent' AND aggregate_id='shared-logical-id';
  IF n <> 2 THEN RAISE EXCEPTION 'cross-tenant Outbox aggregate collision: %', n; END IF;
  SELECT COUNT(*) INTO n FROM inbox_aggregate_claims
    WHERE aggregate_type='run' AND aggregate_id='shared-logical-id';
  IF n <> 2 THEN RAISE EXCEPTION 'cross-tenant Inbox claim collision: %', n; END IF;
  SELECT COUNT(*) INTO n FROM inbox_cursors
    WHERE aggregate_type='run' AND aggregate_id='shared-logical-id';
  IF n <> 2 THEN RAISE EXCEPTION 'cross-tenant Inbox cursor collision: %', n; END IF;
END
$test$;

-- The same tenant + consumer + aggregate/version is not claimable twice.
INSERT INTO inbox_events (
 consumer_name,event_id,producer,event_type,schema_version,tenant_id,
 aggregate_type,aggregate_id,aggregate_version,payload,state
) VALUES (
 'run-projection','00000000-0000-0000-0000-000000000203',
 'agent-runtime','agent.run.created',1,'tenant-alpha','run','shared-logical-id',1,'{}'::jsonb,'RECEIVED'
);
DO $test$
BEGIN
  BEGIN
    INSERT INTO inbox_aggregate_claims (
      consumer_name,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_id
    ) VALUES (
      'run-projection','tenant-alpha','run','shared-logical-id',1,
      '00000000-0000-0000-0000-000000000203'
    );
    RAISE EXCEPTION 'same-tenant duplicate aggregate claim was accepted';
  EXCEPTION WHEN unique_violation THEN NULL;
  END;
END
$test$;

-- A claim cannot attribute an existing event to a different tenant.
DO $test$
BEGIN
  BEGIN
    INSERT INTO inbox_aggregate_claims (
      consumer_name,tenant_id,aggregate_type,aggregate_id,aggregate_version,event_id
    ) VALUES (
      'run-projection','tenant-beta','run','foreign-aggregate',2,
      '00000000-0000-0000-0000-000000000203'
    );
    RAISE EXCEPTION 'cross-tenant event attribution was accepted';
  EXCEPTION WHEN foreign_key_violation THEN NULL;
  END;
END
$test$;

ROLLBACK;
