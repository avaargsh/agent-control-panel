package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/researchlock"
	"github.com/avaargsh/agent-control-panel/internal/workspace"
)

func gcBlob(name, letter string) workspace.Asset {
	return workspace.Asset{Path: name, Digest: "sha256:" + strings.Repeat(letter, 64), SizeBytes: 12}
}

func gcFixture(t *testing.T, seed int) (*Repository, workspace.Asset, researchlock.Lock) {
	t.Helper()
	repo, _ := testRepository(t)
	lock := workspacePinnedFixture(t, repo, seed)
	if _, _, err := repo.OpenWorkspace(context.Background(), lock); err != nil {
		t.Fatal(err)
	}
	asset := gcBlob("reports/draft.md", "a")
	if _, _, err := repo.StageWorkspaceAsset(context.Background(), lock, "gc-stage", asset, 1, approveAssets{}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.pool.Exec(context.Background(), "SELECT pg_sleep(1.15)"); err != nil {
		t.Fatal(err)
	}
	return repo, asset, lock
}

func TestGCClaimExclusiveFencingLeaseAndReclaim(t *testing.T) {
	repo, asset, lock := gcFixture(t, 150001)
	ctx := context.Background()
	first, err := repo.ClaimWorkspaceBlob(ctx, lock, asset.Digest, "collector-a", 1)
	if err != nil || first.Generation != 1 || first.HolderID != "collector-a" {
		t.Fatalf("first claim: %+v err=%v", first, err)
	}
	same, err := repo.ClaimWorkspaceBlob(ctx, lock, asset.Digest, "collector-a", 1)
	if err != nil || same != first {
		t.Fatalf("same collector replay must not renew lease: %+v err=%v", same, err)
	}
	if _, err := repo.ClaimWorkspaceBlob(ctx, lock, asset.Digest, "collector-b", 1); !errors.Is(err, ErrGCClaimBusy) {
		t.Fatalf("competing collector took active claim: %v", err)
	}
	if err := repo.CheckWorkspaceGCClaim(ctx, lock, asset.Digest, "collector-a", 1); err != nil {
		t.Fatalf("active claim check: %v", err)
	}
	renewed, err := repo.RenewWorkspaceGCClaim(ctx, lock, asset.Digest, "collector-a", 1, 1)
	if err != nil || renewed.Generation != 2 {
		t.Fatalf("renew did not advance fence: %+v %v", renewed, err)
	}
	if err := repo.CheckWorkspaceGCClaim(ctx, lock, asset.Digest, "collector-a", 1); !errors.Is(err, ErrGCStaleFence) {
		t.Fatalf("prior generation remained valid: %v", err)
	}
	if err := repo.CheckWorkspaceGCClaim(ctx, lock, asset.Digest, "collector-a", 2); err != nil {
		t.Fatalf("renewed claim not valid: %v", err)
	}
	if _, err := repo.pool.Exec(ctx, "SELECT pg_sleep(1.15)"); err != nil {
		t.Fatal(err)
	}
	if err := repo.CheckWorkspaceGCClaim(ctx, lock, asset.Digest, "collector-a", 2); !errors.Is(err, ErrGCStaleFence) {
		t.Fatalf("expired claim remained live: %v", err)
	}
	reclaimed, err := repo.ClaimWorkspaceBlob(ctx, lock, asset.Digest, "collector-b", 60)
	if err != nil || reclaimed.Generation != 3 || reclaimed.HolderID != "collector-b" {
		t.Fatalf("expired claim was not reclaimed with new fencing generation: %+v %v", reclaimed, err)
	}
	if err := repo.CheckWorkspaceGCClaim(ctx, lock, asset.Digest, "collector-a", 2); !errors.Is(err, ErrGCStaleFence) {
		t.Fatalf("expired holder check bypassed new fence: %v", err)
	}
	if err := New(repo.pool).CheckWorkspaceGCClaim(ctx, lock, asset.Digest, "collector-b", 3); err != nil {
		t.Fatalf("fresh Repository could not reconstruct current fence: %v", err)
	}
}

func TestGCClaimRejectsHistoricalV6AndV7Retention(t *testing.T) {
	for _, staged := range []bool{false, true} {
		t.Run(fmt.Sprintf("staged=%t", staged), func(t *testing.T) {
			repo, asset, lock := gcFixture(t, 150101+map[bool]int{false: 0, true: 10}[staged])
			ctx := context.Background()
			input := WorkspaceCommitInput{CommitID: "keep-history", ExpectedRevision: 0, Assets: []workspace.Asset{asset}}
			var err error
			if staged {
				// Create a new still-live stage for strict v7 commit, then allow expiry.
				if _, _, err = repo.StageWorkspaceAsset(ctx, lock, "new-stage", asset, 30, approveAssets{}); err != nil {
					t.Fatal(err)
				}
				_, err = repo.CommitStagedWorkspace(ctx, lock, input, approveAssets{})
			} else {
				_, err = repo.CommitWorkspace(ctx, lock, input, approveAssets{})
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repo.CommitWorkspace(ctx, lock, WorkspaceCommitInput{CommitID: "latest-empty", ExpectedRevision: 1}, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.ClaimWorkspaceBlob(ctx, lock, asset.Digest, "collector-a", 60); !errors.Is(err, ErrGCNotEligible) {
				t.Fatalf("historical reference not retained: %v", err)
			}
			var retained int
			if err := repo.pool.QueryRow(ctx, "SELECT count(*) FROM workspace_gc_observations WHERE disposition='RETAINED'").Scan(&retained); err != nil || retained != 1 {
				t.Fatalf("historical retention reason was not recorded: count=%d err=%v", retained, err)
			}
		})
	}
}

func TestGCClaimBlocksNewStageIntentAndCommitDuringLease(t *testing.T) {
	repo, asset, lock := gcFixture(t, 150301)
	ctx := context.Background()
	if _, err := repo.ClaimWorkspaceBlob(ctx, lock, asset.Digest, "collector-a", 30); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repo.StageWorkspaceAsset(ctx, lock, "new-stage", asset, 30, approveAssets{}); !errors.Is(err, ErrGCClaimBusy) {
		t.Fatalf("stage bypassed active GC fence: %v", err)
	}
	if _, _, err := repo.BeginWorkspaceUpload(ctx, lock, WorkspaceUploadInput{
		IntentID: "new-upload", Asset: asset, LeaseSeconds: 30,
	}); !errors.Is(err, ErrGCClaimBusy) {
		t.Fatalf("upload intent bypassed active GC fence: %v", err)
	}
	if _, err := repo.CommitWorkspace(ctx, lock, WorkspaceCommitInput{
		CommitID: "legacy-bypass", ExpectedRevision: 0, Assets: []workspace.Asset{asset},
	}, approveAssets{}); !errors.Is(err, ErrGCClaimBusy) {
		t.Fatalf("legacy commit bypassed GC fence: %v", err)
	}
	var revisions int64
	if err := repo.pool.QueryRow(ctx, "SELECT manifest_revision FROM research_workspaces WHERE tenant_id=$1 AND workspace_id=$2", lock.TenantID, lock.WorkspaceID).Scan(&revisions); err != nil || revisions != 0 {
		t.Fatalf("GC-denied commit changed revision: %d %v", revisions, err)
	}
}

func TestGCClaimFailsClosedForUnknownAndActiveUploads(t *testing.T) {
	repo, asset, lock := gcFixture(t, 150401)
	ctx := context.Background()
	input := WorkspaceUploadInput{IntentID: "unknown-remote", Asset: asset, LeaseSeconds: 300}
	if _, _, err := repo.BeginWorkspaceUpload(ctx, lock, input); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ClaimWorkspaceBlob(ctx, lock, asset.Digest, "collector-a", 30); !errors.Is(err, ErrGCNotEligible) {
		t.Fatalf("active upload intent eligible: %v", err)
	}
	var unknown int
	if err := repo.pool.QueryRow(ctx, "SELECT count(*) FROM workspace_gc_observations WHERE disposition='UNKNOWN'").Scan(&unknown); err != nil || unknown != 1 {
		t.Fatalf("active upload was not audited UNKNOWN: count=%d err=%v", unknown, err)
	}
	// Even an expired intent with no VERIFIED observation must remain UNKNOWN
	// rather than authorize reclaim based solely on elapsed time.
	if _, err := repo.pool.Exec(ctx, "UPDATE workspace_upload_intents SET expires_at=clock_timestamp()-interval '1 second' WHERE intent_id='unknown-remote'"); err == nil {
		t.Fatal("immutable intent was changed")
	}
	if _, err := repo.pool.Exec(ctx, "SELECT pg_sleep(0.02)"); err != nil {
		t.Fatal(err)
	}
}

func TestGCClaimConcurrentCollectorsOnlyOneWins(t *testing.T) {
	repo, asset, lock := gcFixture(t, 150501)
	ctx := context.Background()
	var wg sync.WaitGroup
	results := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := repo.ClaimWorkspaceBlob(ctx, lock, asset.Digest, fmt.Sprintf("collector-%d", i), 60)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	success, busy := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrGCClaimBusy) {
			busy++
		} else {
			t.Errorf("unexpected competing collector error: %v", err)
		}
	}
	if success != 1 || busy != 7 {
		t.Fatalf("concurrent claims success=%d busy=%d", success, busy)
	}
}

func TestGCClaimRequiresExactPinnedTenantPrincipalAndValidID(t *testing.T) {
	repo, asset, lock := gcFixture(t, 150601)
	ctx := context.Background()
	for _, mutation := range []func(*researchlock.Lock){
		func(l *researchlock.Lock) { l.TenantID = "other" },
		func(l *researchlock.Lock) { l.PrincipalID = "other" },
		func(l *researchlock.Lock) { l.SessionID = "other" },
	} {
		foreign := lock
		mutation(&foreign)
		if _, err := repo.ClaimWorkspaceBlob(ctx, foreign, asset.Digest, "collector", 60); !errors.Is(err, ErrWorkspaceScope) {
			t.Fatalf("forged lock permitted: %v", err)
		}
	}
	if _, err := repo.ClaimWorkspaceBlob(ctx, lock, asset.Digest, "../collector", 60); !errors.Is(err, workspace.ErrInvalidManifest) {
		t.Fatalf("invalid collector accepted: %v", err)
	}
	if _, err := repo.ClaimWorkspaceBlob(ctx, lock, asset.Digest, "collector", 301); !errors.Is(err, workspace.ErrInvalidManifest) {
		t.Fatalf("unbounded lease accepted: %v", err)
	}
}

func TestGCClaimSchemaDriftFailClosedAndNonownerRLS(t *testing.T) {
	t.Run("force RLS", func(t *testing.T) {
		repo, _ := testRepository(t)
		ctx := context.Background()
		if _, err := repo.pool.Exec(ctx, "ALTER TABLE workspace_gc_claims NO FORCE ROW LEVEL SECURITY"); err != nil {
			t.Fatal(err)
		}
		if err := Migrate(ctx, repo.pool); !errors.Is(err, ErrSchemaDrift) {
			t.Fatalf("GC claim FORCE RLS removed without detection: %v", err)
		}
	})
	t.Run("restricted role isolation", func(t *testing.T) {
		repo, asset, lock := gcFixture(t, 150701)
		ctx := context.Background()
		if _, err := repo.ClaimWorkspaceBlob(ctx, lock, asset.Digest, "collector", 60); err != nil {
			t.Fatal(err)
		}
		var schema string
		if err := repo.pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
			t.Fatal(err)
		}
		role := fmt.Sprintf("gc_reader_%d", time.Now().UnixNano())
		if _, err := repo.pool.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			_, _ = repo.pool.Exec(context.Background(), "DROP OWNED BY "+role)
			_, _ = repo.pool.Exec(context.Background(), "DROP ROLE "+role)
		})
		for _, sql := range []string{
			"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
			"GRANT SELECT ON " + schema + ".workspace_gc_claims TO " + role,
			"GRANT SELECT ON " + schema + ".workspace_gc_observations TO " + role,
		} {
			if _, err := repo.pool.Exec(ctx, sql); err != nil {
				t.Fatal(err)
			}
		}
		tx, err := repo.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(context.Background()) }()
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+role); err != nil {
			t.Fatal(err)
		}
		for _, tc := range []struct {
			tenant, principal string
			want              int
		}{
			{lock.TenantID, lock.PrincipalID, 1},
			{"other", lock.PrincipalID, 0},
			{lock.TenantID, "other", 0},
		} {
			if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true),set_config('app.principal_id',$2,true)", tc.tenant, tc.principal); err != nil {
				t.Fatal(err)
			}
			for _, table := range []string{"workspace_gc_claims", "workspace_gc_observations"} {
				var n int
				if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&n); err != nil || n != tc.want {
					t.Fatalf("%s RLS visible count=%d expected=%d err=%v", table, n, tc.want, err)
				}
			}
		}
	})
}

func TestGCClaimExpiredUploadWithoutVerifiedBytesRemainsUnknown(t *testing.T) {
	repo, asset, lock := gcFixture(t, 150801)
	ctx := context.Background()
	if _, _, err := repo.BeginWorkspaceUpload(ctx, lock, WorkspaceUploadInput{
		IntentID: "expired-ack-loss", Asset: asset, LeaseSeconds: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.pool.Exec(ctx, "SELECT pg_sleep(1.15)"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ClaimWorkspaceBlob(ctx, lock, asset.Digest, "collector", 60); !errors.Is(err, ErrGCNotEligible) {
		t.Fatalf("expired UNKNOWN remote PUT eligible: %v", err)
	}
	var disposition string
	if err := repo.pool.QueryRow(ctx, "SELECT disposition FROM workspace_gc_observations ORDER BY observation_id DESC LIMIT 1").Scan(&disposition); err != nil || disposition != "UNKNOWN" {
		t.Fatalf("expired unresolved upload not recorded as UNKNOWN: %q err=%v", disposition, err)
	}
}
