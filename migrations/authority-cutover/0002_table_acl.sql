-- Apply only to a fresh 0001 schema owned by a dedicated NOLOGIN role.
-- Cluster administrator must pre-provision these two NOLOGIN group roles,
-- ensure no other table/column grants or elevated role memberships, and
-- grant separate authenticated LOGINs only their intended group.
-- Database/schema owner must deny CREATE on public and TEMP on the database
-- to these principals, including inherited and PUBLIC privileges.
-- This is a table-grant bootstrap, NOT a privilege-drift repair or attestation.
BEGIN;

REVOKE ALL ON TABLE public.acp_authority_cutover_state,
 public.acp_authority_cutover_changes,
 public.acp_authority_cutover_transitions FROM PUBLIC;

GRANT SELECT ON TABLE public.acp_authority_cutover_state,
 public.acp_authority_cutover_changes,
 public.acp_authority_cutover_transitions
 TO acp_cutover_coordinator, acp_cutover_observer;

GRANT UPDATE (generation, revision, phase, change_id, manifest_digest, operator_id)
 ON public.acp_authority_cutover_state TO acp_cutover_coordinator;

GRANT INSERT (change_id, manifest_digest, operator_id, start_generation)
 ON public.acp_authority_cutover_changes TO acp_cutover_coordinator;

GRANT INSERT (revision, generation, phase, change_id, manifest_digest, operator_id)
 ON public.acp_authority_cutover_transitions TO acp_cutover_coordinator;

COMMIT;
