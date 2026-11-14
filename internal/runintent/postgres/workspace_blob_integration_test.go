package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/workspace"
)

func blobFixture(digestChar string, name string) workspace.Asset {
	return workspace.Asset{Path: name, Digest: "sha256:" + strings.Repeat(digestChar, 64), SizeBytes: 26}
}

func TestBlobStageCommitAtomicRetentionAndReplay(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repository, 120101)
	if _, _, err := repository.OpenWorkspace(ctx, lock); err != nil {
		t.Fatal(err)
	}
	asset := blobFixture("a", "research/report.md")
	stage, created, err := repository.StageWorkspaceAsset(ctx, lock, "stage-report", asset, 300, approveAssets{})
	if err != nil || !created || stage.StageID != "stage-report" || stage.Asset != asset {
		t.Fatalf("stage: %+v inserted=%v err=%v", stage, created, err)
	}
	replayedStage, created, err := New(pool).StageWorkspaceAsset(ctx, lock, "stage-report", asset, 300, approveAssets{})
	if err != nil || created || replayedStage != stage {
		t.Fatalf("idempotent stage: %+v inserted=%v err=%v", replayedStage, created, err)
	}
	changed := asset
	changed.SizeBytes++
	if _, _, err := repository.StageWorkspaceAsset(ctx, lock, "stage-report", changed, 300, approveAssets{}); !errors.Is(err, ErrBlobStageConflict) {
		t.Fatalf("changed staged bytes were accepted: %v", err)
	}
	input := WorkspaceCommitInput{CommitID: "with-refs", ExpectedRevision: 0, Assets: []workspace.Asset{asset}}
	receipt, err := repository.CommitStagedWorkspace(ctx, lock, input, approveAssets{})
	if err != nil || receipt.Revision != 1 {
		t.Fatalf("commit staged: %+v err=%v", receipt, err)
	}
	again, err := New(pool).CommitStagedWorkspace(ctx, lock, input, nil)
	if err != nil || again != receipt {
		t.Fatalf("lost ACK staged replay: %+v err=%v", again, err)
	}
	var count int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_blob_commit_refs WHERE tenant_id=$1 AND workspace_id=$2", lock.TenantID, lock.WorkspaceID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("committed object references=%d err=%v", count, err)
	}
	if _, err := repository.CommitStagedWorkspace(ctx, lock, WorkspaceCommitInput{CommitID: "stale-new", ExpectedRevision: 0, Assets: []workspace.Asset{asset}}, approveAssets{}); !errors.Is(err, ErrWorkspaceRevisionConflict) {
		t.Fatalf("stale CAS unexpectedly succeeded: %v", err)
	}
}

func TestBlobStageRequiredAndExpiredStageRejected(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repository, 120201)
	if _, _, err := repository.OpenWorkspace(ctx, lock); err != nil {
		t.Fatal(err)
	}
	asset := blobFixture("b", "reports/not-staged.md")
	input := WorkspaceCommitInput{CommitID: "unstaged", ExpectedRevision: 0, Assets: []workspace.Asset{asset}}
	if _, err := repository.CommitStagedWorkspace(ctx, lock, input, approveAssets{}); !errors.Is(err, ErrBlobStageMissing) {
		t.Fatalf("unstaged object accepted: %v", err)
	}
	if _, _, err := repository.StageWorkspaceAsset(ctx, lock, "stage-expired", asset, 1, approveAssets{}); err != nil {
		t.Fatal(err)
	}
	// Existing stage rows are immutable; simulate an expired server-clock
	// record by recording the elapsed time instead of rewriting evidence.
	if _, err := pool.Exec(ctx, "SELECT pg_sleep(1.2)"); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CommitStagedWorkspace(ctx, lock, input, approveAssets{}); !errors.Is(err, ErrBlobStageMissing) {
		t.Fatalf("expired stage accepted: %v", err)
	}
	var current int
	if err := pool.QueryRow(ctx, "SELECT manifest_revision FROM research_workspaces WHERE workspace_id=$1", lock.WorkspaceID).Scan(&current); err != nil || current != 0 {
		t.Fatalf("failed commit advanced revision %d err=%v", current, err)
	}
}

func TestBlobStageCrossTenantAndVerifierFailClosed(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repository, 120301)
	if _, _, err := repository.OpenWorkspace(ctx, lock); err != nil {
		t.Fatal(err)
	}
	asset := blobFixture("c", "reports/c.md")
	foreign := lock
	foreign.TenantID = "other-tenant"
	if _, _, err := repository.StageWorkspaceAsset(ctx, foreign, "foreign-stage", asset, 60, approveAssets{}); !errors.Is(err, ErrWorkspaceScope) {
		t.Fatalf("cross-tenant upload claim was accepted: %v", err)
	}
	if _, _, err := repository.StageWorkspaceAsset(ctx, lock, "bad-verifier", asset, 60, &denyAssets{}); !errors.Is(err, ErrWorkspaceUnverifiedAsset) {
		t.Fatalf("failed object verification allowed a stage: %v", err)
	}
	if _, _, err := repository.StageWorkspaceAsset(ctx, lock, "nil-verifier", asset, 60, nil); !errors.Is(err, ErrWorkspaceUnverifiedAsset) {
		t.Fatalf("missing object verifier allowed a stage: %v", err)
	}
	if _, _, err := repository.StageWorkspaceAsset(ctx, lock, "good-stage", asset, 60, approveAssets{}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CommitStagedWorkspace(ctx, foreign, WorkspaceCommitInput{CommitID: "foreign", ExpectedRevision: 0, Assets: []workspace.Asset{asset}}, approveAssets{}); !errors.Is(err, ErrWorkspaceScope) {
		t.Fatalf("cross-tenant commit allowed: %v", err)
	}
	var rows int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_blob_stages").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("unverified stage was written: %d err=%v", rows, err)
	}
}

func TestBlobOrphanCandidateUsesEveryImmutableRevision(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repository, 120401)
	if _, _, err := repository.OpenWorkspace(ctx, lock); err != nil {
		t.Fatal(err)
	}
	referenced := blobFixture("d", "reports/historical.md")
	orphan := blobFixture("e", "reports/uncommitted.md")
	if _, _, err := repository.StageWorkspaceAsset(ctx, lock, "stage-retained", referenced, 1, approveAssets{}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CommitStagedWorkspace(ctx, lock, WorkspaceCommitInput{
		CommitID: "historical", ExpectedRevision: 0, Assets: []workspace.Asset{referenced},
	}, approveAssets{}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CommitWorkspace(ctx, lock, WorkspaceCommitInput{
		CommitID: "now-empty", ExpectedRevision: 1, Assets: nil,
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := repository.StageWorkspaceAsset(ctx, lock, "stage-orphan", orphan, 1, approveAssets{}); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "SELECT pg_sleep(1.2)"); err != nil {
		t.Fatal(err)
	}
	candidates, err := New(pool).ListExpiredBlobCandidates(ctx, lock, 10)
	if err != nil || len(candidates) != 1 || candidates[0].StageID != "stage-orphan" {
		t.Fatalf("GC would delete retained history or miss orphan: %+v err=%v", candidates, err)
	}
	// This is a read-only candidate listing. Deletion is not implemented.
	var stages int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_blob_stages").Scan(&stages); err != nil || stages != 2 {
		t.Fatalf("candidate listing modified stage history: count=%d err=%v", stages, err)
	}
}

func TestBlobStageMigrationDriftAndImmutableReceipts(t *testing.T) {
	t.Run("force RLS", func(t *testing.T) {
		_, pool := testRepository(t)
		if _, err := pool.Exec(context.Background(), "ALTER TABLE workspace_blob_stages NO FORCE ROW LEVEL SECURITY"); err != nil {
			t.Fatal(err)
		}
		if err := Migrate(context.Background(), pool); !errors.Is(err, ErrSchemaDrift) {
			t.Fatalf("weakened stage RLS accepted: %v", err)
		}
	})
	t.Run("immutable stage evidence", func(t *testing.T) {
		repository, pool := testRepository(t)
		ctx := context.Background()
		lock := workspacePinnedFixture(t, repository, 120501)
		if _, _, err := repository.OpenWorkspace(ctx, lock); err != nil {
			t.Fatal(err)
		}
		if _, _, err := repository.StageWorkspaceAsset(ctx, lock, "immutable", blobFixture("f", "data/f.csv"), 60, approveAssets{}); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, "DELETE FROM workspace_blob_stages WHERE stage_id='immutable'"); err == nil {
			t.Fatal("staged evidence deleted")
		}
		if _, err := pool.Exec(ctx, "UPDATE workspace_blob_stages SET lease_seconds=999 WHERE stage_id='immutable'"); err == nil {
			t.Fatal("staged evidence mutated")
		}
	})
}

func TestBlobStageAndRetentionRestrictedRoleRLS(t *testing.T) {
	repository, pool := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repository, 120601)
	if _, _, err := repository.OpenWorkspace(ctx, lock); err != nil {
		t.Fatal(err)
	}
	asset := blobFixture("a", "reports/isolated.md")
	if _, _, err := repository.StageWorkspaceAsset(ctx, lock, "restricted-stage", asset, 120, approveAssets{}); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CommitStagedWorkspace(ctx, lock, WorkspaceCommitInput{
		CommitID: "restricted-commit", ExpectedRevision: 0, Assets: []workspace.Asset{asset},
	}, approveAssets{}); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	role := fmt.Sprintf("blob_reader_%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP OWNED BY "+role)
		_, _ = pool.Exec(context.Background(), "DROP ROLE "+role)
	})
	for _, sql := range []string{
		"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
		"GRANT SELECT ON " + schema + ".workspace_blob_stages TO " + role,
		"GRANT SELECT ON " + schema + ".workspace_blob_commit_refs TO " + role,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	tx, err := pool.Begin(ctx)
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
		{"tenant-other", lock.PrincipalID, 0},
		{lock.TenantID, "principal-other", 0},
	} {
		if _, err := tx.Exec(ctx,
			"SELECT set_config('app.tenant_id',$1,true),set_config('app.principal_id',$2,true)",
			tc.tenant, tc.principal); err != nil {
			t.Fatal(err)
		}
		for _, table := range []string{"workspace_blob_stages", "workspace_blob_commit_refs"} {
			var count int
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != tc.want {
				t.Fatalf("role=%s table=%s count=%d want=%d err=%v", role, table, count, tc.want, err)
			}
		}
	}
}
