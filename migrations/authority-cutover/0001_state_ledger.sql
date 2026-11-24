-- Opt-in bootstrap for the dedicated authority cutover store.
-- Run exactly once against a fresh database under the intended table owner.
-- This does NOT configure coordinator/observer LOGINs or enable HTTP admission.
-- Never use this script to recover an existing or partially restored database.
BEGIN;

CREATE TABLE public.acp_authority_cutover_changes (
 change_id text PRIMARY KEY CHECK (change_id <> '' AND change_id = btrim(change_id)),
 manifest_digest text NOT NULL CHECK (manifest_digest ~ '^sha256:[0-9a-f]{64}$'),
 operator_id text NOT NULL CHECK (operator_id <> '' AND operator_id = btrim(operator_id)),
 start_generation bigint NOT NULL UNIQUE CHECK (start_generation > 0),
 UNIQUE (change_id, manifest_digest, operator_id, start_generation)
);

CREATE TABLE public.acp_authority_cutover_state (
 id integer PRIMARY KEY CHECK (id = 1),
 generation bigint NOT NULL CHECK (generation > 0),
 revision bigint NOT NULL CHECK (revision >= generation),
 phase text NOT NULL CHECK (phase IN ('OPEN','DRAINING','CLOSED','VERIFYING')),
 change_id text NOT NULL,
 manifest_digest text NOT NULL,
 operator_id text NOT NULL,
 CONSTRAINT cutover_state_shape CHECK (
  (revision = 1 AND generation = 1 AND phase = 'OPEN'
   AND change_id = '' AND manifest_digest = '' AND operator_id = '')
  OR
  (revision >= 2
   AND change_id <> '' AND change_id = btrim(change_id)
   AND manifest_digest ~ '^sha256:[0-9a-f]{64}$'
   AND operator_id <> '' AND operator_id = btrim(operator_id)
   AND phase = CASE (revision - 2) % 4
    WHEN 0 THEN 'DRAINING' WHEN 1 THEN 'CLOSED'
    WHEN 2 THEN 'VERIFYING' WHEN 3 THEN 'OPEN' END
   AND generation = (revision - 2) / 4 + 1
    + CASE WHEN phase IN ('VERIFYING','OPEN') THEN 1 ELSE 0 END)
 )
);

CREATE TABLE public.acp_authority_cutover_transitions (
 revision bigint PRIMARY KEY CHECK (revision > 1),
 generation bigint NOT NULL CHECK (generation > 0),
 phase text NOT NULL CHECK (phase IN ('OPEN','DRAINING','CLOSED','VERIFYING')),
 change_id text NOT NULL,
 manifest_digest text NOT NULL,
 operator_id text NOT NULL,
 start_generation bigint GENERATED ALWAYS AS ((revision - 2) / 4 + 1) STORED,
 CONSTRAINT cutover_transition_shape CHECK (
  phase = CASE (revision - 2) % 4
   WHEN 0 THEN 'DRAINING' WHEN 1 THEN 'CLOSED'
   WHEN 2 THEN 'VERIFYING' WHEN 3 THEN 'OPEN' END
  AND generation = start_generation
   + CASE WHEN phase IN ('VERIFYING','OPEN') THEN 1 ELSE 0 END
 ),
 CONSTRAINT cutover_transition_claim FOREIGN KEY
  (change_id, manifest_digest, operator_id, start_generation)
  REFERENCES public.acp_authority_cutover_changes
  (change_id, manifest_digest, operator_id, start_generation)
);

REVOKE ALL ON TABLE public.acp_authority_cutover_state,
 public.acp_authority_cutover_changes,
 public.acp_authority_cutover_transitions FROM PUBLIC;

INSERT INTO public.acp_authority_cutover_state
 (id, generation, revision, phase, change_id, manifest_digest, operator_id)
 VALUES (1, 1, 1, 'OPEN', '', '', '');

COMMIT;
