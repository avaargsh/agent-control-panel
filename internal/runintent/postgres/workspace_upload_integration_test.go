package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/researchlock"
	"github.com/avaargsh/agent-control-panel/internal/workspace"
	"github.com/jackc/pgx/v5/pgxpool"
)

type uploadMemoryBlob struct {
	mu      sync.Mutex
	data    map[string][]byte
	loseACK bool
	puts    int
	before  func() error
}

func (b *uploadMemoryBlob) Upload(_ context.Context, tenant, ws, path string, content io.Reader) (workspace.Asset, error) {
	if b.before != nil {
		if err := b.before(); err != nil {
			return workspace.Asset{}, err
		}
	}
	got, err := io.ReadAll(content)
	if err != nil {
		return workspace.Asset{}, err
	}
	digest := sha256HexUploadTest(got)
	asset := workspace.Asset{Path: path, Digest: "sha256:" + digest, SizeBytes: int64(len(got))}
	b.mu.Lock()
	b.puts++
	if b.data == nil {
		b.data = map[string][]byte{}
	}
	b.data[tenant+"/"+ws+"/"+digest] = bytes.Clone(got)
	drop := b.loseACK
	b.mu.Unlock()
	if drop {
		return workspace.Asset{}, errors.New("lost S3 PUT ACK after bytes persisted")
	}
	return asset, nil
}

func sha256HexUploadTest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (b *uploadMemoryBlob) VerifyAsset(_ context.Context, tenant, ws string, a workspace.Asset) error {
	b.mu.Lock()
	data, ok := b.data[tenant+"/"+ws+"/"+strings.TrimPrefix(a.Digest, "sha256:")]
	b.mu.Unlock()
	if !ok {
		return errors.New("not found")
	}
	if int64(len(data)) != a.SizeBytes || sha256HexUploadTest(data) != strings.TrimPrefix(a.Digest, "sha256:") {
		return errors.New("bytes do not match")
	}
	return nil
}

func setupUploadWorkspace(t *testing.T, seed int) (*Repository, *pgxpool.Pool, researchlock.Lock) {
	t.Helper()
	repo, pool := testRepository(t)
	lock := workspacePinnedFixture(t, repo, seed)
	if _, _, err := repo.OpenWorkspace(context.Background(), lock); err != nil {
		t.Fatal(err)
	}
	return repo, pool, lock
}

func TestUploadIntentSurvivesLostPutACKAndFreshProcessReconcile(t *testing.T) {
	repo, pool, lock := setupUploadWorkspace(t, 133001)
	ctx := context.Background()
	payload := []byte("research workspace 2026: irreversible byte evidence")
	asset := workspace.Asset{Path: "reports/research.md", Digest: "sha256:" + sha256HexUploadTest(payload), SizeBytes: int64(len(payload))}
	input := WorkspaceUploadInput{IntentID: "upload-report", Asset: asset, LeaseSeconds: 300}
	blob := &uploadMemoryBlob{loseACK: true}
	_, err := repo.UploadWorkspaceObject(ctx, lock, input, bytes.NewReader(payload), blob)
	if !errors.Is(err, ErrUploadOutcomeUnknown) {
		t.Fatalf("lost ACK must stay UNKNOWN, got: %v", err)
	}
	var n int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_upload_intents").Scan(&n); err != nil || n != 1 {
		t.Fatalf("upload not registered before network side effect: n=%d err=%v", n, err)
	}
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_blob_stages").Scan(&n); err != nil || n != 0 {
		t.Fatalf("network error falsely created verified stage: n=%d err=%v", n, err)
	}
	var unknown int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_upload_observations WHERE disposition='UNKNOWN'").Scan(&unknown); err != nil || unknown != 1 {
		t.Fatalf("missing UNKNOWN journal: count=%d err=%v", unknown, err)
	}
	fresh := New(pool)
	stage, err := fresh.ReconcileWorkspaceUpload(ctx, lock, input.IntentID, blob)
	if err != nil || stage.StageID != input.IntentID || stage.Asset != asset {
		t.Fatalf("reconcile actual stored bytes: %+v %v", stage, err)
	}
	receipt, err := fresh.CommitStagedWorkspace(ctx, lock, WorkspaceCommitInput{CommitID: "report-commit", ExpectedRevision: 0, Assets: []workspace.Asset{asset}}, blob)
	if err != nil || receipt.Revision != 1 {
		t.Fatalf("commit after reconciliation: %+v %v", receipt, err)
	}
	again, err := New(pool).ReconcileWorkspaceUpload(ctx, lock, input.IntentID, blob)
	if err != nil || again != stage {
		t.Fatalf("replay exact stage: %+v err=%v", again, err)
	}
	// A duplicate UploadWorkspaceObject must NEVER issue a second PUT,
	// including after an ACK was lost but the remote bytes exist.
	retried, err := New(pool).UploadWorkspaceObject(ctx, lock, input, bytes.NewReader(payload), blob)
	if err != nil || retried != stage {
		t.Fatalf("duplicate intent not recovered read-only: %+v err=%v", retried, err)
	}
	blob.mu.Lock()
	puts := blob.puts
	blob.mu.Unlock()
	if puts != 1 {
		t.Fatalf("duplicate intent caused remote side effects: puts=%d", puts)
	}
	var verified int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_upload_observations WHERE disposition='VERIFIED'").Scan(&verified); err != nil || verified < 1 {
		t.Fatalf("not reconciled: verified=%d err=%v", verified, err)
	}
}

func TestUploadIntentRejectsScopeAndMutationBeforeNetwork(t *testing.T) {
	repo, pool, lock := setupUploadWorkspace(t, 133101)
	ctx := context.Background()
	data := []byte("immutable")
	asset := workspace.Asset{Path: "reports/a.md", Digest: "sha256:" + sha256HexUploadTest(data), SizeBytes: int64(len(data))}
	input := WorkspaceUploadInput{IntentID: "intent-bound", Asset: asset, LeaseSeconds: 60}
	staged, created, err := repo.BeginWorkspaceUpload(ctx, lock, input)
	if err != nil || !created || staged.Asset != asset {
		t.Fatalf("begin intent: %+v created=%v err=%v", staged, created, err)
	}
	replay, created, err := New(pool).BeginWorkspaceUpload(ctx, lock, input)
	if err != nil || created || replay != staged {
		t.Fatalf("begin idempotency: %+v %v %v", replay, created, err)
	}
	altered := input
	altered.Asset.SizeBytes++
	if _, _, err := repo.BeginWorkspaceUpload(ctx, lock, altered); !errors.Is(err, ErrUploadIntentConflict) {
		t.Fatalf("same intent ID with changed request accepted: %v", err)
	}
	foreign := lock
	foreign.TenantID = "foreign"
	if _, _, err := repo.BeginWorkspaceUpload(ctx, foreign, input); !errors.Is(err, ErrWorkspaceScope) {
		t.Fatalf("unauthenticated foreign tenant accepted: %v", err)
	}
	foreign = lock
	foreign.PrincipalID = "other"
	if _, err := repo.ReconcileWorkspaceUpload(ctx, foreign, input.IntentID, &uploadMemoryBlob{}); !errors.Is(err, ErrWorkspaceScope) {
		t.Fatalf("foreign principal reconciled: %v", err)
	}
	for _, bad := range []WorkspaceUploadInput{{IntentID: "../../evil", Asset: asset, LeaseSeconds: 10}, {IntentID: "valid", Asset: asset, LeaseSeconds: 86401}} {
		if _, _, err := repo.BeginWorkspaceUpload(ctx, lock, bad); !errors.Is(err, workspace.ErrInvalidManifest) {
			t.Fatalf("invalid upload intent accepted: %+v %v", bad, err)
		}
	}
}

func TestUploadIntentFailedBytesNeverBecomeVerified(t *testing.T) {
	repo, pool, lock := setupUploadWorkspace(t, 133201)
	ctx := context.Background()
	declared := workspace.Asset{Path: "data/expected.csv", Digest: "sha256:" + sha256HexUploadTest([]byte("expected")), SizeBytes: 8}
	input := WorkspaceUploadInput{IntentID: "mismatch-upload", Asset: declared, LeaseSeconds: 120}
	blob := &uploadMemoryBlob{}
	if _, err := repo.UploadWorkspaceObject(ctx, lock, input, strings.NewReader("otherbytes"), blob); !errors.Is(err, ErrUploadPayloadMismatch) {
		t.Fatalf("wrong pre-PUT bytes accepted: %v", err)
	}
	blob.mu.Lock()
	puts := blob.puts
	blob.mu.Unlock()
	if puts != 0 {
		t.Fatalf("wrong digest data was PUT to a different content key: puts=%d", puts)
	}
	var intents int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_upload_intents").Scan(&intents); err != nil || intents != 0 {
		t.Fatalf("invalid payload created unusable intent: count=%d err=%v", intents, err)
	}
	var stages int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_blob_stages").Scan(&stages); err != nil || stages != 0 {
		t.Fatalf("mismatched bytes staged: %d %v", stages, err)
	}
}

func TestUploadIntentExpirationAndNonOwnerIsolation(t *testing.T) {
	repo, pool, lock := setupUploadWorkspace(t, 133301)
	ctx := context.Background()
	data := []byte("short lease")
	asset := workspace.Asset{Path: "reports/short.md", Digest: "sha256:" + sha256HexUploadTest(data), SizeBytes: int64(len(data))}
	intent := WorkspaceUploadInput{IntentID: "deadline", Asset: asset, LeaseSeconds: 1}
	if _, _, err := repo.BeginWorkspaceUpload(ctx, lock, intent); err != nil {
		t.Fatal(err)
	}
	// Non-owner role RLS must independently hide records, not just Go filters.
	var schema string
	if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
		t.Fatal(err)
	}
	role := fmt.Sprintf("upload_reader_%d", time.Now().UnixNano())
	if _, err := pool.Exec(ctx, "CREATE ROLE "+role+" NOLOGIN"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "DROP OWNED BY "+role)
		_, _ = pool.Exec(context.Background(), "DROP ROLE "+role)
	})
	for _, stmt := range []string{"GRANT USAGE ON SCHEMA " + schema + " TO " + role, "GRANT SELECT ON " + schema + ".workspace_upload_intents TO " + role} {
		if _, err := pool.Exec(ctx, stmt); err != nil {
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
	}{{lock.TenantID, lock.PrincipalID, 1}, {"foreign", lock.PrincipalID, 0}, {lock.TenantID, "foreign", 0}} {
		if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id',$1,true),set_config('app.principal_id',$2,true)", tc.tenant, tc.principal); err != nil {
			t.Fatal(err)
		}
		var seen int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM workspace_upload_intents").Scan(&seen); err != nil || seen != tc.want {
			t.Fatalf("RLS scope %+v saw %d err=%v", tc, seen, err)
		}
	}
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, "SELECT pg_sleep(1.2)"); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.ReconcileWorkspaceUpload(ctx, lock, intent.IntentID, &uploadMemoryBlob{}); !errors.Is(err, ErrUploadIntentExpired) {
		t.Fatalf("expired intent reconciled: %v", err)
	}
}

func TestUploadIntentSchemaDriftFailClosed(t *testing.T) {
	_, pool := testRepository(t)
	if _, err := pool.Exec(context.Background(), "ALTER TABLE workspace_upload_intents NO FORCE ROW LEVEL SECURITY"); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(context.Background(), pool); !errors.Is(err, ErrSchemaDrift) {
		t.Fatalf("schema drift allowed: %v", err)
	}
}

func TestUploadIntentIsDurableBeforeObjectPut(t *testing.T) {
	repo, pool, lock := setupUploadWorkspace(t, 133401)
	ctx := context.Background()
	payload := []byte("signed object upload")
	asset := workspace.Asset{Path: "research/signed.md", Digest: "sha256:" + sha256HexUploadTest(payload), SizeBytes: int64(len(payload))}
	intent := WorkspaceUploadInput{IntentID: "before-network", Asset: asset, LeaseSeconds: 300}
	checked := false
	blob := &uploadMemoryBlob{before: func() error {
		var count int
		err := pool.QueryRow(ctx, `SELECT count(*) FROM workspace_upload_intents
			WHERE tenant_id=$1 AND workspace_id=$2 AND intent_id=$3 AND artifact_digest=$4`,
			lock.TenantID, lock.WorkspaceID, intent.IntentID, asset.Digest).Scan(&count)
		if err != nil {
			return err
		}
		if count != 1 {
			return fmt.Errorf("remote PUT before committing intent: count=%d", count)
		}
		checked = true
		return nil
	}}
	stage, err := repo.UploadWorkspaceObject(ctx, lock, intent, bytes.NewReader(payload), blob)
	if err != nil || stage.Asset != asset || !checked {
		t.Fatalf("unproven intent-first side effect: %+v checked=%v err=%v", stage, checked, err)
	}
}

func TestWorkspaceUploadConcurrentIdempotentIntentCreation(t *testing.T) {
	repo, pool, lock := setupUploadWorkspace(t, 133501)
	ctx := context.Background()
	asset := workspace.Asset{Path: "research/report.md", Digest: "sha256:" + sha256HexUploadTest([]byte("concurrent")), SizeBytes: 10}
	in := WorkspaceUploadInput{IntentID: "one-intent", Asset: asset, LeaseSeconds: 300}
	var wg sync.WaitGroup
	results := make(chan bool, 8)
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, created, err := repo.BeginWorkspaceUpload(ctx, lock, in)
			if err != nil {
				errs <- err
			} else {
				results <- created
			}
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		t.Errorf("concurrent Begin failed: %v", err)
	}
	created := 0
	observed := 0
	for result := range results {
		observed++
		if result {
			created++
		}
	}
	if observed != 8 || created != 1 {
		t.Fatalf("concurrent upload ID registration: callers=%d creators=%d", observed, created)
	}
	var rows int
	if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_upload_intents").Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("concurrent upload duplicated intent: %d err=%v", rows, err)
	}
}
