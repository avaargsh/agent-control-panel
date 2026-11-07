package jetstreampoc

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

var ErrDispositionSchemaDrift = errors.New("disposition journal schema protection drift")

// This body is pinned to the POC journal schema. A same-name CREATE OR REPLACE
// FUNCTION must not bypass detection by preserving the PostgreSQL function OID.
const pocDispositionGuardBody = `BEGIN
	IF TG_OP = 'DELETE' OR TG_OP = 'TRUNCATE' THEN
		RAISE EXCEPTION 'disposition evidence is append-only';
	END IF;
	IF NEW.source_stream IS DISTINCT FROM OLD.source_stream
		OR NEW.source_consumer IS DISTINCT FROM OLD.source_consumer
		OR NEW.source_sequence IS DISTINCT FROM OLD.source_sequence
		OR NEW.delivery_hash IS DISTINCT FROM OLD.delivery_hash
		OR NEW.reason IS DISTINCT FROM OLD.reason
		OR NEW.dlq_stream IS DISTINCT FROM OLD.dlq_stream
		OR NEW.dlq_subject IS DISTINCT FROM OLD.dlq_subject
		OR NEW.evidence IS DISTINCT FROM OLD.evidence
		OR NEW.created_at IS DISTINCT FROM OLD.created_at THEN
		RAISE EXCEPTION 'immutable disposition identity or evidence changed';
	END IF;
	IF (OLD.publish_started AND NOT NEW.publish_started)
		OR (OLD.published AND (NOT NEW.published OR NEW.published_at IS DISTINCT FROM OLD.published_at))
		OR (NEW.published AND NOT OLD.publish_started) THEN
		RAISE EXCEPTION 'disposition status rollback or unauthorized confirmation';
	END IF;
	RETURN NEW;
END;`

// Install only on first creation, never "repair" a previously existing table.
// An owner who drops or weakens a guard must encounter a fail-closed error,
// not an automatic CREATE OR REPLACE that hides the drift.
func installDispositionGuards(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, "CREATE FUNCTION poc_reject_unsafe_disposition_mutation() RETURNS trigger LANGUAGE plpgsql AS $$\n"+
		pocDispositionGuardBody+"\n$$")
	if err != nil {
		return fmt.Errorf("create POC journal guard function: %w", err)
	}
	_, err = tx.Exec(ctx, `
		CREATE TRIGGER poc_dlq_no_unsafe_update_delete
		BEFORE UPDATE OR DELETE ON poc_dlq_dispositions
		FOR EACH ROW EXECUTE FUNCTION poc_reject_unsafe_disposition_mutation()
	`)
	if err != nil {
		return fmt.Errorf("create POC journal row guard: %w", err)
	}
	_, err = tx.Exec(ctx, `
		CREATE TRIGGER poc_dlq_no_truncate
		BEFORE TRUNCATE ON poc_dlq_dispositions
		FOR EACH STATEMENT EXECUTE FUNCTION poc_reject_unsafe_disposition_mutation()
	`)
	if err != nil {
		return fmt.Errorf("create POC journal truncate guard: %w", err)
	}
	return nil
}

func verifyDispositionGuards(ctx context.Context, tx pgx.Tx) error {
	var identityKeys int
	err := tx.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_constraint c
		WHERE c.conrelid=to_regclass('poc_dlq_dispositions')
		  AND c.contype='p' AND c.convalidated
		  AND (
			SELECT array_agg(a.attname::text ORDER BY k.ordinality)
			FROM unnest(c.conkey) WITH ORDINALITY AS k(attnum,ordinality)
			JOIN pg_attribute a ON a.attrelid=c.conrelid AND a.attnum=k.attnum
		  )=ARRAY['source_stream','source_consumer','source_sequence']::text[]
	`).Scan(&identityKeys)
	if err != nil {
		return fmt.Errorf("verify disposition primary key: %w", err)
	}
	if identityKeys != 1 {
		return ErrDispositionSchemaDrift
	}

	// PostgreSQL tgtype bitmap: ROW=1 BEFORE=2 UPDATE=16 DELETE=8;
	// statement BEFORE TRUNCATE=34. Check tgattr (UPDATE OF narrowing)
	// and tgqual (WHEN condition), not merely trigger names.
	var triggers int
	err = tx.QueryRow(ctx, `
		SELECT count(*)
		FROM pg_trigger t
		WHERE t.tgrelid=to_regclass('poc_dlq_dispositions')
		  AND NOT t.tgisinternal
		  AND t.tgenabled='O'
		  AND t.tgattr::text=''
		  AND t.tgqual IS NULL
		  AND t.tgfoid=to_regprocedure('poc_reject_unsafe_disposition_mutation()')
		  AND (
			(t.tgname='poc_dlq_no_unsafe_update_delete' AND t.tgtype=27)
			OR
			(t.tgname='poc_dlq_no_truncate' AND t.tgtype=34)
		  )
	`).Scan(&triggers)
	if err != nil {
		return fmt.Errorf("verify disposition guard triggers: %w", err)
	}
	if triggers != 2 {
		return ErrDispositionSchemaDrift
	}

	var actualSource string
	err = tx.QueryRow(ctx, `
		SELECT p.prosrc FROM pg_proc p
		WHERE p.oid=to_regprocedure('poc_reject_unsafe_disposition_mutation()')
		  AND p.pronargs=0 AND p.prokind='f'
		  AND p.prolang=(SELECT oid FROM pg_language WHERE lanname='plpgsql')
		  AND p.prorettype='pg_catalog.trigger'::regtype
		  AND p.provolatile='v' AND NOT p.prosecdef AND p.proconfig IS NULL
	`).Scan(&actualSource)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrDispositionSchemaDrift
	}
	if err != nil {
		return fmt.Errorf("verify disposition guard function catalog: %w", err)
	}
	if strings.TrimSpace(actualSource) != strings.TrimSpace(pocDispositionGuardBody) {
		return ErrDispositionSchemaDrift
	}

	// Compare live CHECK predicates to PostgreSQL-compiled, pinned expressions,
	// not to constraint names. A same-name CHECK(TRUE) is schema drift.
	_, err = tx.Exec(ctx, `
		CREATE TEMP TABLE poc_expected_journal_checks
		(LIKE poc_dlq_dispositions) ON COMMIT DROP
	`)
	if err != nil {
		return fmt.Errorf("build expected journal CHECK relation: %w", err)
	}
	checks := []struct{ name, predicate string }{
		{"poc_dlq_published_at_check", "(published AND published_at IS NOT NULL) OR (NOT published AND published_at IS NULL)"},
		{"poc_dlq_requires_attempt", "NOT published OR publish_started"},
	}
	for _, check := range checks {
		_, err := tx.Exec(ctx, fmt.Sprintf(
			"ALTER TABLE pg_temp.poc_expected_journal_checks ADD CONSTRAINT %s CHECK (%s)",
			check.name, check.predicate))
		if err != nil {
			return fmt.Errorf("compile expected disposition check %s: %w", check.name, err)
		}
		var equal bool
		err = tx.QueryRow(ctx, `
			SELECT pg_get_expr(actual.conbin,actual.conrelid,false)=
			       pg_get_expr(expected.conbin,expected.conrelid,false)
			FROM pg_constraint actual
			JOIN pg_constraint expected ON actual.conname=expected.conname
			WHERE actual.conrelid=to_regclass('poc_dlq_dispositions')
			  AND expected.conrelid=to_regclass('pg_temp.poc_expected_journal_checks')
			  AND actual.conname=$1
			  AND actual.contype='c' AND expected.contype='c'
			  AND actual.convalidated
		`, check.name).Scan(&equal)
		if errors.Is(err, pgx.ErrNoRows) || err == nil && !equal {
			return fmt.Errorf("%w: invalid predicate for %s", ErrDispositionSchemaDrift, check.name)
		}
		if err != nil {
			return fmt.Errorf("verify disposition check %s: %w", check.name, err)
		}
	}
	return nil
}
