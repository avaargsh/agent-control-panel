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

func workspacePinnedFixture(t *testing.T, repo *Repository, n int) researchlock.Lock {
	t.Helper()
	intent := testIntent(n)
	lock := pinnedFixture(intent.ID)
	_, created, err := repo.CreatePinned(context.Background(), intent, testEvent(intent, 1, n+100, eventCreated), lock)
	if err != nil || !created {
		t.Fatalf("create pinned workspace parent: %v created=%v", err, created)
	}
	return lock
}

func TestWorkspaceOpenCommitAndFreshRepositoryRead(t *testing.T) {
	repo, pool := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repo, 9910)
	created, inserted, err := repo.OpenWorkspace(ctx, lock)
	if err != nil || !inserted || created.Revision != 0 || created.WorkspaceID != lock.WorkspaceID {
		t.Fatalf("workspace create: %+v inserted=%v err=%v", created, inserted, err)
	}
	again, inserted, err := repo.OpenWorkspace(ctx, lock)
	if err != nil || inserted || again != created {
		t.Fatalf("workspace replay: %+v inserted=%v err=%v", again, inserted, err)
	}
	first, err := repo.CommitWorkspace(ctx, lock, WorkspaceCommitInput{CommitID: "commit-1", ExpectedRevision: 0}, nil)
	if err != nil || first.Revision != 1 || first.PreviousRevision != 0 || first.ArtifactDigest != lock.ArtifactDigest {
		t.Fatalf("workspace commit: %+v err=%v", first, err)
	}
	fresh := New(pool)
	current, assets, err := fresh.ReadWorkspaceSnapshot(ctx, lock)
	if err != nil || current.Revision != 1 || len(assets) != 0 {
		t.Fatalf("fresh repository reconstruction: workspace=%+v assets=%+v err=%v", current, assets, err)
	}
	replayed, err := fresh.CommitWorkspace(ctx, lock, WorkspaceCommitInput{CommitID: "commit-1", ExpectedRevision: 0}, nil)
	if err != nil || replayed != first {
		t.Fatalf("ACK-loss replay changed receipt: %+v err=%v", replayed, err)
	}
	if _, err := fresh.CommitWorkspace(ctx, lock, WorkspaceCommitInput{CommitID: "commit-2", ExpectedRevision: 0}, nil); !errors.Is(err, ErrWorkspaceRevisionConflict) {
		t.Fatalf("stale CAS accepted: %v", err)
	}
	var commits int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_manifest_commits").Scan(&commits); err != nil || commits != 1 {
		t.Fatalf("replay duplicated commits=%d err=%v", commits, err)
	}
}

func TestWorkspaceRequiresExactPersistedCapabilityScope(t *testing.T) {
	repo, _ := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repo, 9930)
	for _, tc := range []struct {
		name string
		edit func(*researchlock.Lock)
	}{
		{"foreign tenant", func(l *researchlock.Lock) { l.TenantID = "tenant-foreign" }},
		{"foreign user", func(l *researchlock.Lock) { l.PrincipalID = "principal-other" }},
		{"wrong workspace", func(l *researchlock.Lock) { l.WorkspaceID = "workspace-other" }},
		{"wrong session", func(l *researchlock.Lock) { l.SessionID = "session-other" }},
		{"changed DAS digest", func(l *researchlock.Lock) { l.ArtifactDigest = "sha256:" + strings.Repeat("b", 64) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := lock
			tc.edit(&changed)
			if _, _, err := repo.OpenWorkspace(ctx, changed); !errors.Is(err, ErrWorkspaceScope) {
				t.Fatalf("foreign scope allowed: %v", err)
			}
		})
	}
	_, _, err := repo.OpenWorkspace(ctx, pinnedFixture(testIntent(9939).ID))
	if !errors.Is(err, ErrWorkspaceScope) {
		t.Fatalf("missing trusted RunIntent lock accepted: %v", err)
	}
}

func TestWorkspaceCommitConcurrentCASAndReplayConflict(t *testing.T) {
	repo, pool := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repo, 9940)
	if _, _, err := repo.OpenWorkspace(ctx, lock); err != nil {
		t.Fatal(err)
	}
	const workers = 8
	var wg sync.WaitGroup
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := repo.CommitWorkspace(ctx, lock, WorkspaceCommitInput{
				CommitID: fmt.Sprintf("concurrent-%d", n), ExpectedRevision: 0,
			}, nil)
			results <- err
		}(i)
	}
	wg.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrWorkspaceRevisionConflict) {
			t.Errorf("unexpected concurrent error: %v", err)
		}
	}
	if success != 1 {
		t.Fatalf("concurrent CAS successes=%d want=1", success)
	}
	var current, receipts int
	if err := pool.QueryRow(ctx, "SELECT manifest_revision FROM research_workspaces WHERE tenant_id=$1 AND workspace_id=$2", lock.TenantID, lock.WorkspaceID).Scan(&current); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_manifest_commits").Scan(&receipts); err != nil || current != 1 || receipts != 1 {
		t.Fatalf("CAS partial records: revision=%d receipts=%d err=%v", current, receipts, err)
	}
}

type denyAssets struct{ called int }

func (v *denyAssets) VerifyAsset(_ context.Context, _, _ string, _ workspace.Asset) error {
	v.called++
	return errors.New("object not verified")
}

func TestWorkspaceAssetsRequireVerifierAndValidPaths(t *testing.T) {
	repo, _ := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repo, 9960)
	if _, _, err := repo.OpenWorkspace(ctx, lock); err != nil {
		t.Fatal(err)
	}
	valid := workspace.Asset{Path: "reports/valuation.csv", Digest: "sha256:" + strings.Repeat("a", 64), SizeBytes: 24}
	input := WorkspaceCommitInput{CommitID: "commit-assets", ExpectedRevision: 0, Assets: []workspace.Asset{valid}}
	if _, err := repo.CommitWorkspace(ctx, lock, input, nil); !errors.Is(err, ErrWorkspaceUnverifiedAsset) {
		t.Fatalf("unverified blob accepted: %v", err)
	}
	v := &denyAssets{}
	if _, err := repo.CommitWorkspace(ctx, lock, input, v); !errors.Is(err, ErrWorkspaceUnverifiedAsset) || v.called != 1 {
		t.Fatalf("verification failure did not stop commit: %v called=%d", err, v.called)
	}
	input.Assets[0].Path = "../secret"
	if _, err := repo.CommitWorkspace(ctx, lock, input, v); !errors.Is(err, workspace.ErrInvalidManifest) {
		t.Fatalf("path traversal accepted: %v", err)
	}
	state, _, err := repo.ReadWorkspaceSnapshot(ctx, lock)
	if err != nil || state.Revision != 0 {
		t.Fatalf("failed upload changed manifest revision: %+v err=%v", state, err)
	}
}

func TestWorkspaceTenantAndPrincipalRestrictedRLS(t *testing.T) {
	repo, pool := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repo, 9970)
	if _, _, err := repo.OpenWorkspace(ctx, lock); err != nil {
		t.Fatal(err)
	}
	var schema string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	role := fmt.Sprintf("workspace_reader_%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP OWNED BY "+role)
		_, _ = pool.Exec(context.Background(), "DROP ROLE "+role)
	})
	for _, sql := range []string{
		"GRANT USAGE ON SCHEMA " + schema + " TO " + role,
		"GRANT SELECT ON " + schema + ".research_workspaces TO " + role,
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
		if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true), set_config('app.principal_id',$2,true)", tc.tenant, tc.principal); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM research_workspaces").Scan(&count); err != nil || count != tc.want {
			t.Fatalf("tenant=%s principal=%s visible=%d want=%d err=%v", tc.tenant, tc.principal, count, tc.want, err)
		}
	}
}

func TestWorkspaceMigrationRejectsPolicyDrift(t *testing.T) {
	_, pool := testRepository(t)
	if _, err := pool.Exec(context.Background(), "ALTER TABLE research_workspaces NO FORCE ROW LEVEL SECURITY"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(context.Background(), pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("weakened Workspace RLS accepted: %v", err)
	}
}

type approveAssets struct{}

func (approveAssets) VerifyAsset(context.Context, string, string, workspace.Asset) error { return nil }

func TestWorkspaceManifestSnapshotAndConflictingCommitReplay(t *testing.T) {
	repo, pool := testRepository(t)
	ctx := context.Background()
	lock := workspacePinnedFixture(t, repo, 9980)
	if _, _, err := repo.OpenWorkspace(ctx, lock); err != nil {
		t.Fatal(err)
	}
	assets := []workspace.Asset{
		{Path: "reports/research.md", Digest: "sha256:" + strings.Repeat("a", 64), SizeBytes: 111},
		{Path: "data/source.csv", Digest: "sha256:" + strings.Repeat("b", 64), SizeBytes: 222},
	}
	receipt, err := repo.CommitWorkspace(ctx, lock, WorkspaceCommitInput{
		CommitID: "files-1", ExpectedRevision: 0, Assets: assets,
	}, approveAssets{})
	if err != nil || receipt.Revision != 1 {
		t.Fatalf("commit manifest: %+v err=%v", receipt, err)
	}
	state, stored, err := New(pool).ReadWorkspaceSnapshot(ctx, lock)
	if err != nil || state.Revision != 1 || len(stored) != 2 ||
		stored[0].Path != "data/source.csv" || stored[1].Path != "reports/research.md" {
		t.Fatalf("durable file manifest changed: %+v %+v err=%v", state, stored, err)
	}
	modified := append([]workspace.Asset(nil), assets...)
	modified[0].Digest = "sha256:" + strings.Repeat("c", 64)
	if _, err := repo.CommitWorkspace(ctx, lock, WorkspaceCommitInput{
		CommitID: "files-1", ExpectedRevision: 0, Assets: modified,
	}, approveAssets{}); !errors.Is(err, ErrWorkspaceReplayConflict) {
		t.Fatalf("modified manifest replayed: %v", err)
	}
	second := testIntent(9982)
	second.SessionID = "session-2"
	nextLock := pinnedFixture(second.ID)
	nextLock.SessionID = second.SessionID
	if _, created, err := repo.CreatePinned(ctx, second, testEvent(second, 1, 9983, eventCreated), nextLock); err != nil || !created {
		t.Fatalf("create second Thread: %v created=%v", err, created)
	}
	reopened, inserted, err := repo.OpenWorkspace(ctx, nextLock)
	if err != nil || inserted || reopened.Revision != 1 {
		t.Fatalf("second Thread cannot reopen Workspace: %+v %v inserted=%v", reopened, err, inserted)
	}
	// SQL cannot mutate an immutable receipt after it has committed.
	if _, err := pool.Exec(ctx, "UPDATE workspace_manifest_commits SET manifest_digest=$1 WHERE commit_id='files-1'",
		"sha256:"+strings.Repeat("c", 64)); err == nil {
		t.Fatal("committed asset receipt was mutated")
	}
}
