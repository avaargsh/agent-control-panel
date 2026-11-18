package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

var admissionCatalogTables = []string{
	"admission_tenants", "admission_projects", "admission_principals",
	"admission_memberships", "admission_releases", "admission_sessions",
}

func ensureAdmissionCatalogMigration(ctx context.Context, tx pgx.Tx, applied bool, source []byte, checksum string) error {
	sql := strings.TrimSpace(string(source))
	if !strings.HasPrefix(sql, "BEGIN;") || !strings.HasSuffix(sql, "COMMIT;") {
		return ErrSchemaDrift
	}
	sql = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(sql, "BEGIN;"), "COMMIT;"))
	if !applied {
		for _, name := range admissionCatalogTables {
			var exists bool
			if err := tx.QueryRow(ctx, "SELECT to_regclass($1) IS NOT NULL", name).Scan(&exists); err != nil {
				return err
			}
			if exists {
				return ErrSchemaDrift
			}
		}
		if _, err := tx.Exec(ctx, sql, pgx.QueryExecModeSimpleProtocol); err != nil {
			return fmt.Errorf("apply admission catalog migration v11: %w", err)
		}
		if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations(version,name,checksum) VALUES($1,$2,$3)",
			admissionCatalogMigrationVersion, admissionCatalogMigrationName, checksum); err != nil {
			return fmt.Errorf("record admission catalog migration v11: %w", err)
		}
	}
	// Compile identical relational constraints in disposable temporary
	// tables on this PostgreSQL server; compare structural semantics rather
	// than accepting look-alike same-name tables with weaker keys/checks.
	expected := sql
	for _, name := range admissionCatalogTables {
		expected = strings.ReplaceAll(expected, name, "acp_expected_"+name)
	}
	expected = strings.ReplaceAll(expected, "CREATE TABLE ", "CREATE TEMP TABLE ")
	expected = strings.ReplaceAll(expected, ");", ") ON COMMIT DROP;")
	if _, err := tx.Exec(ctx, expected, pgx.QueryExecModeSimpleProtocol); err != nil {
		return fmt.Errorf("compile expected admission catalog schema: %w", err)
	}
	for _, name := range admissionCatalogTables {
		var bound bool
		err := tx.QueryRow(ctx, `
			WITH pair AS (
				SELECT c.oid AS actual, e.oid AS expected, c.relnamespace AS actual_ns,
				       e.relnamespace AS expected_ns
				FROM pg_class c, pg_class e
				WHERE c.oid=to_regclass($1) AND e.oid=to_regclass($2)
				  AND c.relkind='r' AND c.relpersistence='p' AND c.relnamespace=current_schema()::regnamespace
				  AND e.relkind='r' AND e.relpersistence='t'
			),
			actual_columns AS (
				SELECT a.attnum, a.attname, a.atttypid, a.atttypmod, a.attnotnull,
				       a.atthasdef, a.attidentity, a.attgenerated, a.attcollation
				FROM pair JOIN pg_attribute a ON a.attrelid=pair.actual
				WHERE a.attnum>0 AND NOT a.attisdropped
			),
			expected_columns AS (
				SELECT a.attnum, a.attname, a.atttypid, a.atttypmod, a.attnotnull,
				       a.atthasdef, a.attidentity, a.attgenerated, a.attcollation
				FROM pair JOIN pg_attribute a ON a.attrelid=pair.expected
				WHERE a.attnum>0 AND NOT a.attisdropped
			),
			actual_constraints AS (
				SELECT c.contype, c.conkey, c.confkey, c.convalidated, c.condeferrable,
				       c.condeferred, c.confupdtype, c.confdeltype, c.confmatchtype,
				       c.connoinherit, pg_get_expr(c.conbin,c.conrelid,false) AS predicate,
				       ref.relname::text AS target,
				       coalesce(ref.relnamespace=pair.actual_ns,true) AS target_local
				FROM pair JOIN pg_constraint c ON c.conrelid=pair.actual
				LEFT JOIN pg_class ref ON ref.oid=c.confrelid
			),
			expected_constraints AS (
				SELECT c.contype, c.conkey, c.confkey, c.convalidated, c.condeferrable,
				       c.condeferred, c.confupdtype, c.confdeltype, c.confmatchtype,
				       c.connoinherit, pg_get_expr(c.conbin,c.conrelid,false) AS predicate,
				       replace(ref.relname::text,'acp_expected_','') AS target,
				       coalesce(ref.relnamespace=pair.expected_ns,true) AS target_local
				FROM pair JOIN pg_constraint c ON c.conrelid=pair.expected
				LEFT JOIN pg_class ref ON ref.oid=c.confrelid
			)
			SELECT EXISTS(SELECT 1 FROM pair)
			  AND NOT EXISTS(SELECT * FROM actual_columns EXCEPT ALL SELECT * FROM expected_columns)
			  AND NOT EXISTS(SELECT * FROM expected_columns EXCEPT ALL SELECT * FROM actual_columns)
			  AND NOT EXISTS(SELECT * FROM actual_constraints EXCEPT ALL SELECT * FROM expected_constraints)
			  AND NOT EXISTS(SELECT * FROM expected_constraints EXCEPT ALL SELECT * FROM actual_constraints)
			  AND NOT EXISTS(
				SELECT 1 FROM pair JOIN pg_constraint c ON c.conrelid=pair.actual
				LEFT JOIN pg_index i ON i.indexrelid=c.conindid
				WHERE c.contype IN ('p','u') AND
				      (i.indexrelid IS NULL OR NOT i.indisvalid OR NOT i.indisready OR NOT i.indislive OR NOT i.indisunique)
			  )
			  AND NOT EXISTS(
				SELECT 1 FROM pair JOIN pg_class c ON c.oid=pair.actual
				CROSS JOIN LATERAL aclexplode(coalesce(c.relacl,acldefault('r',c.relowner))) acl
				WHERE acl.grantee=0
			  )
			  AND NOT EXISTS(
				SELECT 1 FROM pair JOIN pg_attribute a ON a.attrelid=pair.actual
				CROSS JOIN LATERAL aclexplode(a.attacl) acl
				WHERE a.attnum>0 AND NOT a.attisdropped AND acl.grantee=0
			  )
		`, name, "pg_temp.acp_expected_"+name).Scan(&bound)
		if err != nil {
			return fmt.Errorf("verify admission catalog schema: %w", err)
		}
		if !bound {
			return ErrSchemaDrift
		}
	}
	return nil
}
