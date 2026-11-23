BEGIN;

-- Bounded tenant+Run authority selector, and only for durable accepted Runs.
-- Deliberately NONUNIQUE: the resolver must detect duplicate accepted
-- mappings via LIMIT 2 and fail closed instead of trusting arbitrary rows.
-- INCLUDE permits retrieving the original immutable ID/digest from the index.
-- Apply through the checksum-ledger migration runner under maintenance
-- controls: ordinary CREATE INDEX takes a DDL lock during construction.
CREATE INDEX run_intents_guard_accepted_runtime_lookup
    ON run_intents (tenant_id, runtime_run_id)
    INCLUDE (id, request_digest)
    WHERE status = 'ACCEPTED';

COMMIT;
