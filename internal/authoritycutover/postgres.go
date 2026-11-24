package authoritycutover

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrStoreUnavailable = errors.New("cutover store unavailable")
	ErrOutcomeUnknown   = errors.New("cutover commit outcome unknown")
)

// PostgresStore persists owner-verified state transitions. It is not a
// drain verifier, DCL executor, migration runner or an HTTP admission gate.
// The pool must belong to the dedicated trusted coordinator.
type PostgresStore struct {
	pool *pgxpool.Pool
}

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore {
	return &PostgresStore{pool: pool}
}

type stateQueryer interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

const observeSQL = `SELECT s.generation,s.revision,s.phase,s.change_id,s.manifest_digest,s.operator_id,
	CASE WHEN s.change_id='' THEN NOT EXISTS (
		SELECT 1 FROM public.acp_authority_cutover_changes
	) AND NOT EXISTS (
		SELECT 1 FROM public.acp_authority_cutover_transitions
	) ELSE EXISTS (
		SELECT 1 FROM public.acp_authority_cutover_changes c
		WHERE c.change_id=s.change_id AND c.manifest_digest=s.manifest_digest
		AND c.operator_id=s.operator_id
		AND c.start_generation=s.generation-CASE WHEN s.phase IN ('OPEN','VERIFYING') THEN 1 ELSE 0 END
		AND (SELECT count(*) FROM public.acp_authority_cutover_changes)=c.start_generation
		AND (SELECT count(DISTINCT start_generation) FROM public.acp_authority_cutover_changes)=c.start_generation
		AND NOT EXISTS (
			SELECT 1 FROM public.acp_authority_cutover_changes newer
			WHERE newer.start_generation>c.start_generation
		)
	) AND EXISTS (
		SELECT 1 FROM public.acp_authority_cutover_transitions h
		WHERE h.revision=s.revision AND h.generation=s.generation
		AND h.phase=s.phase AND h.change_id=s.change_id
		AND h.manifest_digest=s.manifest_digest AND h.operator_id=s.operator_id
	) AND NOT EXISTS (
		SELECT 1 FROM public.acp_authority_cutover_transitions newer
		WHERE newer.revision>s.revision
	) AND (
		SELECT count(*) FROM public.acp_authority_cutover_transitions
	)=s.revision-1 AND NOT EXISTS (
		SELECT 1 FROM public.acp_authority_cutover_transitions historical
		WHERE NOT EXISTS (
			SELECT 1 FROM public.acp_authority_cutover_changes claim
			WHERE claim.change_id=historical.change_id
			AND claim.manifest_digest=historical.manifest_digest
			AND claim.operator_id=historical.operator_id
			AND claim.start_generation=historical.generation-CASE WHEN historical.phase IN ('OPEN','VERIFYING') THEN 1 ELSE 0 END
		)
	) AND NOT EXISTS (
		SELECT 1 FROM public.acp_authority_cutover_transitions h
		JOIN public.acp_authority_cutover_changes c ON c.change_id=h.change_id
		WHERE (h.revision-2)/4+1<>c.start_generation
		OR h.phase<>CASE (h.revision-2)%4
			WHEN 0 THEN 'DRAINING' WHEN 1 THEN 'CLOSED'
			WHEN 2 THEN 'VERIFYING' WHEN 3 THEN 'OPEN' END
	) END
	FROM public.acp_authority_cutover_state s WHERE s.id=1`

// admissionHeadSQL is the bounded request-path check. It verifies the
// singleton state shape, the current immutable change claim, the exact head
// transition and absence of a newer revision using indexed lookups. The full
// historical audit remains in observeSQL for trusted coordinator operations;
// it is deliberately not repeated on every HTTP admission.
const admissionHeadSQL = `SELECT s.generation,s.revision,s.phase,s.change_id,s.manifest_digest,s.operator_id,
	CASE WHEN s.revision=1 THEN
		s.generation=1 AND s.phase='OPEN' AND s.change_id='' AND s.manifest_digest='' AND s.operator_id=''
		AND NOT EXISTS (SELECT 1 FROM public.acp_authority_cutover_changes)
		AND NOT EXISTS (SELECT 1 FROM public.acp_authority_cutover_transitions)
	ELSE
		s.revision>=2
		AND s.phase=CASE (s.revision-2)%4
			WHEN 0 THEN 'DRAINING' WHEN 1 THEN 'CLOSED'
			WHEN 2 THEN 'VERIFYING' WHEN 3 THEN 'OPEN' END
		AND s.generation=(s.revision-2)/4+1
			+ CASE WHEN s.phase IN ('VERIFYING','OPEN') THEN 1 ELSE 0 END
		AND EXISTS (
			SELECT 1 FROM public.acp_authority_cutover_changes c
			WHERE c.change_id=s.change_id AND c.manifest_digest=s.manifest_digest
			AND c.operator_id=s.operator_id AND c.start_generation=(s.revision-2)/4+1
		)
		AND EXISTS (
			SELECT 1 FROM public.acp_authority_cutover_transitions h
			WHERE h.revision=s.revision AND h.generation=s.generation
			AND h.phase=s.phase AND h.change_id=s.change_id
			AND h.manifest_digest=s.manifest_digest AND h.operator_id=s.operator_id
		)
		AND NOT EXISTS (
			SELECT 1 FROM public.acp_authority_cutover_transitions newer
			WHERE newer.revision>s.revision
		)
	END
	FROM public.acp_authority_cutover_state s WHERE s.id=1`

func readAdmissionHead(ctx context.Context, q stateQueryer) (Record, error) {
	var r Record
	var phase string
	var headOK bool
	if err := q.QueryRow(ctx, admissionHeadSQL).Scan(
		&r.Generation, &r.Revision, &phase, &r.Change.ID, &r.Change.ManifestDigest, &r.Change.Operator, &headOK,
	); err != nil {
		return Record{}, fmt.Errorf("%w: read admission head: %w", ErrStoreUnavailable, err)
	}
	r.Phase = Phase(phase)
	if !r.valid() || !headOK || (r.Change == (Change{}) && (r.Phase != Open || r.Generation != 1 || r.Revision != 1)) {
		return Record{}, ErrInvalid
	}
	return r, nil
}

func readRecord(ctx context.Context, q stateQueryer, lock bool) (Record, error) {
	query := observeSQL
	if lock {
		query += " FOR UPDATE OF s"
	}
	var r Record
	var phase string
	var claimOK bool
	if err := q.QueryRow(ctx, query).Scan(&r.Generation, &r.Revision, &phase, &r.Change.ID, &r.Change.ManifestDigest, &r.Change.Operator, &claimOK); err != nil {
		return Record{}, fmt.Errorf("%w: read state: %w", ErrStoreUnavailable, err)
	}
	r.Phase = Phase(phase)
	if !r.valid() || !claimOK || (r.Change == (Change{}) && (r.Phase != Open || r.Generation != 1 || r.Revision != 1)) {
		return Record{}, ErrInvalid
	}
	return r, nil
}

// Observe returns only a structurally valid durable record with a matching
// change claim, or an error. Missing state never means OPEN.
func (s *PostgresStore) Observe(ctx context.Context) (Record, error) {
	if s == nil || s.pool == nil {
		return Record{}, ErrStoreUnavailable
	}
	return readRecord(ctx, s.pool, false)
}

// ObserveVerified acquires one backend, attests its independent LOGIN and
// reads the ledger through that same backend. This closes accidental pool
// identity/backend mismatch between the two operations. It is not an atomic
// fence against privileged DCL committed after the attestation.
func (s *PostgresStore) ObserveVerified(ctx context.Context, login string, mode RoleMode) (Record, error) {
	if s == nil || s.pool == nil {
		return Record{}, ErrStoreUnavailable
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return Record{}, fmt.Errorf("%w: acquire verified observer: %w", ErrStoreUnavailable, err)
	}
	defer conn.Release()
	if err := VerifyPostgresRole(ctx, conn.Conn(), login, mode); err != nil {
		return Record{}, err
	}
	return readRecord(ctx, conn, false)
}

// Apply atomically claims a new change ID and updates the full expected
// record. External drain, DCL outcome and re-attestation evidence must be
// independently validated by the trusted caller before invoking Apply.
// A commit error is conservatively unknown; reconcile by Observe and
// authoritative effect readback, never automatically retry DCL.
func (s *PostgresStore) Apply(ctx context.Context, expected Record, action Action, change Change) (Record, error) {
	if s == nil || s.pool == nil {
		return Record{}, ErrStoreUnavailable
	}
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Record{}, fmt.Errorf("%w: begin: %w", ErrStoreUnavailable, err)
	}
	return applyTransaction(ctx, tx, expected, action, change)
}

// ApplyVerified requires the expected independently authenticated Coordinator
// LOGIN and performs the state transition on the same acquired backend. The
// role probe is a point-in-time admission check, not an atomic DCL fence.
func (s *PostgresStore) ApplyVerified(ctx context.Context, login string, expected Record, action Action, change Change) (Record, error) {
	if s == nil || s.pool == nil {
		return Record{}, ErrStoreUnavailable
	}
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return Record{}, fmt.Errorf("%w: acquire verified coordinator: %w", ErrStoreUnavailable, err)
	}
	defer conn.Release()
	if err := VerifyPostgresRole(ctx, conn.Conn(), login, CoordinatorRole); err != nil {
		return Record{}, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return Record{}, fmt.Errorf("%w: begin verified transaction: %w", ErrStoreUnavailable, err)
	}
	return applyTransaction(ctx, tx, expected, action, change)
}

func applyTransaction(ctx context.Context, tx pgx.Tx, expected Record, action Action, change Change) (Record, error) {
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	// Serialize coordinators on the singleton row. Use a second statement
	// after acquiring the lock so the claim lookup sees a fresh snapshot
	// even when another coordinator committed while this one was waiting.
	var id int
	if err := tx.QueryRow(ctx, "SELECT id FROM public.acp_authority_cutover_state WHERE id=1 FOR UPDATE").Scan(&id); err != nil {
		return Record{}, fmt.Errorf("%w: lock state: %w", ErrStoreUnavailable, err)
	}
	current, err := readRecord(ctx, tx, false)
	if err != nil {
		return Record{}, err
	}
	next, err := Advance(current, expected, action, change)
	if err != nil {
		return Record{}, err
	}
	if action == Begin {
		tag, err := tx.Exec(ctx, `INSERT INTO public.acp_authority_cutover_changes
			(change_id,manifest_digest,operator_id,start_generation) VALUES ($1,$2,$3,$4)
			ON CONFLICT (change_id) DO NOTHING`, change.ID, change.ManifestDigest, change.Operator, current.Generation)
		if err != nil {
			return Record{}, fmt.Errorf("%w: claim change: %w", ErrStoreUnavailable, err)
		}
		if tag.RowsAffected() != 1 {
			return Record{}, ErrConflict
		}
	}
	tag, err := tx.Exec(ctx, `UPDATE public.acp_authority_cutover_state
		SET generation=$1,revision=$2,phase=$3,change_id=$4,manifest_digest=$5,operator_id=$6
		WHERE id=1 AND generation=$7 AND revision=$8 AND phase=$9
		AND change_id=$10 AND manifest_digest=$11 AND operator_id=$12`,
		next.Generation, next.Revision, string(next.Phase), next.Change.ID, next.Change.ManifestDigest, next.Change.Operator,
		current.Generation, current.Revision, string(current.Phase), current.Change.ID, current.Change.ManifestDigest, current.Change.Operator)
	if err != nil {
		return Record{}, fmt.Errorf("%w: update state: %w", ErrStoreUnavailable, err)
	}
	if tag.RowsAffected() != 1 {
		return Record{}, ErrConflict
	}
	// Append the full transition record in the same transaction as the state
	// and change claim. Never update or delete previous revisions here.
	tag, err = tx.Exec(ctx, `INSERT INTO public.acp_authority_cutover_transitions
		(revision,generation,phase,change_id,manifest_digest,operator_id)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		next.Revision, next.Generation, string(next.Phase), next.Change.ID, next.Change.ManifestDigest, next.Change.Operator)
	if err != nil {
		return Record{}, fmt.Errorf("%w: append transition: %w", ErrStoreUnavailable, err)
	}
	if tag.RowsAffected() != 1 {
		return Record{}, ErrConflict
	}
	// Read back inside the transaction to detect an inconsistent claim or
	// database-side rewrite before returning any successful state.
	observed, err := readRecord(ctx, tx, false)
	if err != nil {
		return Record{}, err
	}
	if observed != next {
		return Record{}, ErrConflict
	}
	if err := tx.Commit(ctx); err != nil {
		return Record{}, fmt.Errorf("%w: %w", ErrOutcomeUnknown, err)
	}
	return next, nil
}
