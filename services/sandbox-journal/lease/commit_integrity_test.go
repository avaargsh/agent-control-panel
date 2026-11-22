package lease

import (
	"context"
	"testing"
)

// Direct SQL must not commit an incomplete or forged lease/outbox aggregate,
// even when it bypasses the Go repository. The database is disposable PG16.
func TestLeaseCommitRefusesIncompleteOrForgedHistory(t *testing.T) {
	tests := []struct {
		name string
		run  func(context.Context, *Repository, Intent) error
	}{
		{
			name: "intent_without_original_outbox",
			run: func(ctx context.Context, repo *Repository, in Intent) error {
				_, err := repo.pool.Exec(ctx, `INSERT INTO sandbox_lease_intents
					(tenant_id,lease_intent_id,run_id,runtime_attempt_id,request_digest)
					VALUES ($1,$2,$3,$4,$5)`,
					in.TenantID, in.LeaseIntentID, in.RunID, in.RuntimeAttemptID, in.RequestDigest)
				return err
			},
		},
		{
			name: "cancel_state_without_cancel_outbox",
			run: func(ctx context.Context, repo *Repository, in Intent) error {
				if _, _, err := repo.Create(ctx, in); err != nil {
					return err
				}
				_, err := repo.pool.Exec(ctx, `UPDATE sandbox_lease_intents
					SET state='CANCELLED_BEFORE_PROVISION', generation=2, updated_at=clock_timestamp()
					WHERE tenant_id=$1 AND lease_intent_id=$2`, in.TenantID, in.LeaseIntentID)
				return err
			},
		},
		{
			name: "future_cancel_event_while_waiting",
			run: func(ctx context.Context, repo *Repository, in Intent) error {
				if _, _, err := repo.Create(ctx, in); err != nil {
					return err
				}
				_, err := repo.pool.Exec(ctx, `INSERT INTO sandbox_lease_intent_events
					(tenant_id,lease_intent_id,generation,event_type,payload)
					VALUES ($1,$2,2,'sandbox.lease-intent.cancelled-before-provision',
					jsonb_build_object('run_id',$3::text,'runtime_attempt_id',$4::text,'request_digest',$5::text))`,
					in.TenantID, in.LeaseIntentID, in.RunID, in.RuntimeAttemptID, in.RequestDigest)
				return err
			},
		},
		{
			name: "forged_initial_run_in_atomic_transaction",
			run: func(ctx context.Context, repo *Repository, in Intent) error {
				tx, err := repo.pool.Begin(ctx)
				if err != nil {
					return err
				}
				defer func() { _ = tx.Rollback(context.Background()) }()
				if _, err := tx.Exec(ctx, `INSERT INTO sandbox_lease_intents
					(tenant_id,lease_intent_id,run_id,runtime_attempt_id,request_digest)
					VALUES ($1,$2,$3,$4,$5)`,
					in.TenantID, in.LeaseIntentID, in.RunID, in.RuntimeAttemptID, in.RequestDigest); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO sandbox_lease_intent_events
					(tenant_id,lease_intent_id,generation,event_type,payload)
					VALUES ($1,$2,1,'sandbox.lease-intent.waiting-permit',
					jsonb_build_object('run_id','forged-run'::text,'runtime_attempt_id',$3::text,'request_digest',$4::text))`,
					in.TenantID, in.LeaseIntentID, in.RuntimeAttemptID, in.RequestDigest); err != nil {
					return err
				}
				return tx.Commit(ctx)
			},
		},
		{
			name: "extra_sensitive_field_in_initial_event",
			run: func(ctx context.Context, repo *Repository, in Intent) error {
				tx, err := repo.pool.Begin(ctx)
				if err != nil {
					return err
				}
				defer func() { _ = tx.Rollback(context.Background()) }()
				if _, err := tx.Exec(ctx, `INSERT INTO sandbox_lease_intents
					(tenant_id,lease_intent_id,run_id,runtime_attempt_id,request_digest)
					VALUES ($1,$2,$3,$4,$5)`,
					in.TenantID, in.LeaseIntentID, in.RunID, in.RuntimeAttemptID, in.RequestDigest); err != nil {
					return err
				}
				if _, err := tx.Exec(ctx, `INSERT INTO sandbox_lease_intent_events
					(tenant_id,lease_intent_id,generation,event_type,payload)
					VALUES ($1,$2,1,'sandbox.lease-intent.waiting-permit',
					jsonb_build_object('run_id',$3::text,'runtime_attempt_id',$4::text,
					'request_digest',$5::text,'raw_credential','forbidden'::text))`,
					in.TenantID, in.LeaseIntentID, in.RunID, in.RuntimeAttemptID, in.RequestDigest); err != nil {
					return err
				}
				return tx.Commit(ctx)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := testRepository(t)
			if err := tc.run(context.Background(), repo, sampleIntent()); err == nil {
				t.Fatal("database committed incomplete, future, or forged source-owned history")
			}
		})
	}
}

func TestLeaseCommitAcceptsCompleteTwoStageHistory(t *testing.T) {
	repo := testRepository(t)
	ctx := context.Background()
	in := sampleIntent()
	created, first, err := repo.Create(ctx, in)
	if err != nil || !first || created.Generation != 1 {
		t.Fatalf("creation rejected: %+v %v", created, err)
	}
	done, err := repo.CancelBeforeProvision(ctx, in.TenantID, in.LeaseIntentID, 1)
	if err != nil || done.Generation != 2 {
		t.Fatalf("cancel rejected: %+v %v", done, err)
	}
	got, err := repo.Get(ctx, in.TenantID, in.LeaseIntentID)
	if err != nil || got.Generation != 2 || got.State != CancelledBeforeProvision {
		t.Fatalf("committed complete history not readable: %+v %v", got, err)
	}
	if events(t, repo) != 2 {
		t.Fatalf("want exact created+cancelled events")
	}
}
