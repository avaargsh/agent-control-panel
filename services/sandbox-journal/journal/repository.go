// Package journal owns the independent Sandbox Service's durable, non-dispatch
// CommandJournal PRE-PERMIT gate. It MUST use a database separate from ACP.
// This is not an AgentD client, trusted Permit issuer or executor PEP.
package journal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/internal/identity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrUnavailable = errors.New("sandbox journal unavailable")
	ErrConflict    = errors.New("sandbox journal immutable command identity conflict")
	ErrNotFound    = errors.New("sandbox journal command not found")
	ErrCorrupt     = errors.New("sandbox journal corrupt persisted record")
)

const PermitUnavailable = "PERMIT_UNAVAILABLE"

type Record struct {
	Identity   identity.Intent
	Generation uint64
	State      string
	CreatedAt  time.Time
}

type Repository struct{ pool *pgxpool.Pool }

func New(pool *pgxpool.Pool) *Repository { return &Repository{pool: pool} }

// RecordPermitUnavailable performs one tenant-scoped idempotent INSERT plus
// immutable outbox INSERT in the SAME local transaction. This is a rejection
// receipt, not permission to dispatch. No method in this module starts a command.
func (r *Repository) RecordPermitUnavailable(ctx context.Context, in identity.Intent) (Record, bool, error) {
	if err := in.Validate(); err != nil {
		return Record{}, false, err
	}
	if r == nil || r.pool == nil {
		return Record{}, false, ErrUnavailable
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return Record{}, false, fmt.Errorf("begin sandbox journal: %w", err)
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	row := tx.QueryRow(ctx, `INSERT INTO sandbox_journal_commands
 (tenant_id,sandbox_uid,command_id,run_id,runtime_attempt_id,request_digest)
 VALUES($1,$2,$3,$4,$5,$6)
 ON CONFLICT (tenant_id,sandbox_uid,command_id) DO NOTHING
 RETURNING tenant_id,run_id,runtime_attempt_id,sandbox_uid,command_id,request_digest,generation,state,created_at`,
		in.TenantID, in.SandboxUID, in.CommandID, in.RunID, in.RuntimeAttemptID, in.RequestDigest)
	rec, err := scan(row)
	created := err == nil
	if errors.Is(err, pgx.ErrNoRows) {
		rec, err = scan(tx.QueryRow(ctx, `SELECT tenant_id,run_id,runtime_attempt_id,sandbox_uid,command_id,request_digest,generation,state,created_at
 FROM sandbox_journal_commands WHERE tenant_id=$1 AND sandbox_uid=$2 AND command_id=$3 FOR SHARE`, in.TenantID, in.SandboxUID, in.CommandID))
		if err != nil {
			return Record{}, false, fmt.Errorf("read replay: %w", err)
		}
		if rec.Identity != in {
			return Record{}, false, ErrConflict
		}
	} else if err != nil {
		return Record{}, false, dbError(err)
	}
	if created {
		_, err = tx.Exec(ctx, `INSERT INTO sandbox_journal_outbox
 (tenant_id,sandbox_uid,command_id,generation,event_type,payload)
 VALUES ($1,$2,$3,1,'sandbox.command.permit-unavailable',
 jsonb_build_object('run_id',$4::text,'runtime_attempt_id',$5::text,'request_digest',$6::text))`,
			in.TenantID, in.SandboxUID, in.CommandID, in.RunID, in.RuntimeAttemptID, in.RequestDigest)
		if err != nil {
			return Record{}, false, fmt.Errorf("atomic outbox append: %w", err)
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return Record{}, false, fmt.Errorf("commit sandbox journal: %w", err)
	}
	return rec, created, nil
}

// Get is tenant and command scoped. A missing row is not proof that an effect
// never happened elsewhere; only a trusted provider inspection can decide.
func (r *Repository) Get(ctx context.Context, tenantID, sandboxUID, commandID string) (Record, error) {
	if r == nil || r.pool == nil {
		return Record{}, ErrUnavailable
	}
	for _, s := range []string{tenantID, sandboxUID, commandID} {
		if s == "" {
			return Record{}, identity.ErrInvalid
		}
	}
	rec, err := scan(r.pool.QueryRow(ctx, `SELECT tenant_id,run_id,runtime_attempt_id,sandbox_uid,command_id,request_digest,generation,state,created_at
 FROM sandbox_journal_commands WHERE tenant_id=$1 AND sandbox_uid=$2 AND command_id=$3`, tenantID, sandboxUID, commandID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Record{}, ErrNotFound
	}
	if err != nil {
		return Record{}, fmt.Errorf("read command: %w", err)
	}
	return rec, nil
}
func scan(row pgx.Row) (Record, error) {
	var rec Record
	var generation int64
	err := row.Scan(&rec.Identity.TenantID, &rec.Identity.RunID, &rec.Identity.RuntimeAttemptID, &rec.Identity.SandboxUID, &rec.Identity.CommandID, &rec.Identity.RequestDigest, &generation, &rec.State, &rec.CreatedAt)
	if err != nil {
		return Record{}, err
	}
	if rec.Identity.Validate() != nil || generation != 1 || rec.State != PermitUnavailable || rec.CreatedAt.IsZero() {
		return Record{}, ErrCorrupt
	}
	rec.Generation = uint64(generation)
	return rec, nil
}
func dbError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return ErrConflict
	}
	return fmt.Errorf("write sandbox journal: %w", err)
}
