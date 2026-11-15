package postgres

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/researchlock"
	"github.com/avaargsh/agent-control-panel/internal/workspace"
	"github.com/avaargsh/agent-control-panel/internal/workspace/s3blob"
	"github.com/jackc/pgx/v5/pgxpool"
)

const minioProcessMarker = "ACP_MINIO_PROCESS_BOUNDARY="

func minioCrashAsset(phase string) (workspace.Asset, []byte) {
	body := []byte("P0-2B5 durable independent-process MinIO report; phase=" + phase + "; mode=" + os.Getenv("ACP_MINIO_PROCESS_MODE"))
	sum := sha256.Sum256(body)
	return workspace.Asset{
		Path:      "reports/process-" + phase + ".md",
		Digest:    "sha256:" + hex.EncodeToString(sum[:]),
		SizeBytes: int64(len(body)),
	}, body
}

func minioCrashIntent(phase string, asset workspace.Asset) WorkspaceUploadInput {
	return WorkspaceUploadInput{IntentID: "process-" + phase, Asset: asset, LeaseSeconds: 300}
}

func minioCrashCommit(phase string, asset workspace.Asset) WorkspaceCommitInput {
	return WorkspaceCommitInput{
		CommitID: "process-commit-" + phase, ExpectedRevision: 0,
		Assets: []workspace.Asset{asset},
	}
}

// minioProcessBackend permits the same real PG+S3 recovery algorithm to be
// tested with either the legacy combined fixture identity or separate IAM
// identities. A read-only worker receives ONLY a GetObject service identity.
type minioProcessBackend interface {
	Upload(context.Context, string, string, string, io.Reader) (workspace.Asset, error)
	VerifyAsset(context.Context, string, string, workspace.Asset) error
	ReadAsset(context.Context, string, string, workspace.Asset) ([]byte, error)
}

func minioProcessReaderOnly(action, phase string) bool {
	return action == "reopen" || (action == "recover" && phase != "before-put")
}

func minioProcessStore(t *testing.T, action, phase string) minioProcessBackend {
	t.Helper()
	if os.Getenv("ACP_MINIO_PROCESS_MODE") == "" {
		store, err := s3blob.New(s3blob.Config{
			Endpoint: os.Getenv("S3BLOB_MINIO_TEST_ENDPOINT"),
			Bucket: "research-artifacts", Region: "us-east-1",
			AccessKey: os.Getenv("S3BLOB_MINIO_TEST_ACCESS_KEY"),
			SecretKey: os.Getenv("S3BLOB_MINIO_TEST_SECRET_KEY"),
			AllowHTTPForTests: true,
		})
		if err != nil {
			t.Fatalf("real MinIO client config: %v", err)
		}
		return store
	}
	if os.Getenv("ACP_MINIO_PROCESS_MODE") != "split" {
		t.Fatal("unrecognized MinIO process IAM mode")
	}
	// A real independent child is NOT allowed to inherit fixture-root or
	// foreign-tenant keys, even when only using a read operation.
	for _, name := range []string{
		"S3BLOB_MINIO_TEST_ACCESS_KEY", "S3BLOB_MINIO_TEST_SECRET_KEY",
		"MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD",
		"S3BLOB_IAM_OTHER_ACCESS_KEY", "S3BLOB_IAM_OTHER_SECRET_KEY",
		"S3BLOB_IAM_DENIED_ACCESS_KEY", "S3BLOB_IAM_DENIED_SECRET_KEY",
	} {
		if os.Getenv(name) != "" {
			t.Fatalf("scoped child inherited privileged or unrelated identity %s", name)
		}
	}
	newRole := func(role string) *s3blob.Store {
		access := os.Getenv("S3BLOB_IAM_" + role + "_ACCESS_KEY")
		secret := os.Getenv("S3BLOB_IAM_" + role + "_SECRET_KEY")
		if access == "" || secret == "" {
			t.Fatalf("missing actual MinIO %s service principal", role)
		}
		store, err := s3blob.New(s3blob.Config{
			Endpoint: os.Getenv("S3BLOB_MINIO_TEST_ENDPOINT"),
			Bucket: "research-artifacts", Region: "us-east-1",
			AccessKey: access, SecretKey: secret, AllowHTTPForTests: true,
		})
		if err != nil {
			t.Fatalf("connect scoped %s service identity: %v", role, err)
		}
		return store
	}
	reader := newRole("READER")
	if minioProcessReaderOnly(action, phase) {
		if os.Getenv("S3BLOB_IAM_WRITER_ACCESS_KEY") != "" ||
			os.Getenv("S3BLOB_IAM_WRITER_SECRET_KEY") != "" {
			t.Fatal("read-only recovery/reopen worker inherited scoped writer key")
		}
		fmt.Println(minioProcessMarker + "IDENTITY:READER_ONLY:" + action + ":" + phase)
		return reader
	}
	writer := newRole("WRITER")
	split, err := s3blob.NewSplitRoleStore(writer, reader)
	if err != nil {
		t.Fatalf("split writer/reader real MinIO IAM client: %v", err)
	}
	fmt.Println(minioProcessMarker + "IDENTITY:WRITE_AND_READ:" + action + ":" + phase)
	return split
}

// TestWorkspaceMinIOCrashWorker is launched as a NEW OS process through the
// current compiled test binary. It is never a production service or Agent.
// The parent owns the disposable schema and intentionally SIGKILLs workers.
func TestWorkspaceMinIOCrashWorker(t *testing.T) {
	action := os.Getenv("ACP_MINIO_CHILD_ACTION")
	if action == "" {
		t.Skip("no independently spawned MinIO crash worker")
	}
	phase := os.Getenv("ACP_MINIO_CHILD_PHASE")
	schema := os.Getenv("ACP_MINIO_CHILD_SCHEMA")
	if schema == "" || (phase != "before-put" && phase != "after-put" &&
		phase != "after-stage" && phase != "after-cas") {
		t.Fatalf("invalid process crash harness scope: action=%q phase=%q", action, phase)
	}
	var lock researchlock.Lock
	if err := json.Unmarshal([]byte(os.Getenv("ACP_MINIO_CHILD_LOCK")), &lock); err != nil {
		t.Fatalf("read pinned scope from parent: %v", err)
	}
	config, err := pgxpool.ParseConfig(os.Getenv("PGTEST_DSN"))
	if err != nil {
		t.Fatalf("PG test config: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("reconnect to retained PostgreSQL schema: %v", err)
	}
	defer pool.Close()
	repo := New(pool)
	store := minioProcessStore(t, action, phase)
	asset, report := minioCrashAsset(phase)
	intent := minioCrashIntent(phase, asset)

	switch action {
	case "crash":
		if _, _, err := repo.BeginWorkspaceUpload(ctx, lock, intent); err != nil {
			t.Fatalf("durable pre-PUT intent: %v", err)
		}
		if phase != "before-put" {
			actual, err := store.Upload(ctx, lock.TenantID, lock.WorkspaceID, asset.Path, bytes.NewReader(report))
			if err != nil || actual != asset {
				t.Fatalf("real MinIO PUT+GET before SIGKILL: %+v err=%v", actual, err)
			}
		}
		if phase == "after-stage" || phase == "after-cas" {
			if stage, err := repo.ReconcileWorkspaceUpload(ctx, lock, intent.IntentID, store); err != nil || stage.Asset != asset {
				t.Fatalf("persist real byte-verified Stage before SIGKILL: %+v err=%v", stage, err)
			}
		}
		if phase == "after-cas" {
			if receipt, err := repo.CommitStagedWorkspace(ctx, lock, minioCrashCommit(phase, asset), store); err != nil || receipt.Revision != 1 {
				t.Fatalf("persist immutable Manifest CAS before SIGKILL: %+v err=%v", receipt, err)
			}
		}
		// The marker is sent AFTER the tested durable boundary and BEFORE
		// ACK/exit. The parent must observe marker and SIGKILL this PID.
		fmt.Println(minioProcessMarker + "CRASH:" + phase)
		_ = os.Stdout.Sync()
		for {
			time.Sleep(time.Hour)
		}
	case "recover":
		if phase == "before-put" {
			// No remote effect was sent. The old intent must be UNKNOWN,
			// not silently successful or blindly re-PUT with its ID.
			if err := store.VerifyAsset(ctx, lock.TenantID, lock.WorkspaceID, asset); !errors.Is(err, s3blob.ErrObjectMissing) {
				t.Fatalf("before-PUT crash unexpectedly stored object: %v", err)
			}
			if _, err := repo.ReconcileWorkspaceUpload(ctx, lock, intent.IntentID, store); !errors.Is(err, ErrUploadOutcomeUnknown) {
				t.Fatalf("missing object was not UNKNOWN: %v", err)
			}
			// An explicit NEW attempt is permitted, unlike blind replay
			// of a transport-ambiguous original intent.
			newIntent := intent
			newIntent.IntentID += "-new-attempt"
			if stage, err := repo.UploadWorkspaceObject(ctx, lock, newIntent, bytes.NewReader(report), store); err != nil || stage.Asset != asset {
				t.Fatalf("authorized new attempt failed: %+v err=%v", stage, err)
			}
		} else {
			if phase == "after-put" {
				// SIGKILL happened before the transport ACK could be
				// journaled. Record UNKNOWN before reading the real bytes.
				if err := repo.appendUploadObservation(ctx, lock, intent.IntentID, "UNKNOWN"); err != nil {
					t.Fatalf("persist external effect uncertainty: %v", err)
				}
			}
			// Strictly GET and hash real bytes. Do not issue any PUT here.
			stage, err := repo.ReconcileWorkspaceUpload(ctx, lock, intent.IntentID, store)
			if err != nil || stage.Asset != asset {
				t.Fatalf("crash recovery failed byte verification: %+v err=%v", stage, err)
			}
		}
		receipt, err := repo.CommitStagedWorkspace(ctx, lock, minioCrashCommit(phase, asset), store)
		if err != nil || receipt.Revision != 1 {
			t.Fatalf("crash recovery CAS/replay failed: %+v err=%v", receipt, err)
		}
		data, err := repo.ReadVerifiedWorkspaceAsset(ctx, lock, asset.Path, store)
		if err != nil || !bytes.Equal(data, report) {
			t.Fatalf("recovery process reopened wrong real MinIO bytes: len=%d err=%v", len(data), err)
		}
		fmt.Println(minioProcessMarker + "RECOVERED:" + phase)
	case "reopen":
		data, err := repo.ReadVerifiedWorkspaceAsset(ctx, lock, asset.Path, store)
		if err != nil || !bytes.Equal(data, report) {
			t.Fatalf("third process failed verified read: len=%d err=%v", len(data), err)
		}
		receipt, err := repo.CommitStagedWorkspace(ctx, lock, minioCrashCommit(phase, asset), nil)
		if err != nil || receipt.Revision != 1 {
			t.Fatalf("third process PG ACK-loss receipt was not immutable: %+v err=%v", receipt, err)
		}
		foreign := lock
		foreign.TenantID = "untrusted-other"
		if _, err := repo.ReadVerifiedWorkspaceAsset(ctx, foreign, asset.Path, store); !errors.Is(err, ErrWorkspaceScope) {
			t.Fatalf("third process accepted forged tenant scope: %v", err)
		}
		fmt.Println(minioProcessMarker + "REOPENED:" + phase)
	default:
		t.Fatalf("unrecognized independent process action %q", action)
	}
}

// minioChildCredentialEnvironment strips every unrelated MinIO/CI IAM
// credential before exec. Following successful provider PUT, recovery and
// reopen workers receive only the read principal, not writer or bootstrap.
// Only a deliberate explicit new attempt after a before-PUT crash may be
// entrusted with a writer principal.
func minioChildCredentialEnvironment(action, phase string) []string {
	base := os.Environ()
	if os.Getenv("ACP_MINIO_PROCESS_MODE") != "split" {
		return base
	}
	env := make([]string, 0, len(base))
	for _, pair := range base {
		name, _, _ := strings.Cut(pair, "=")
		switch {
		case strings.HasPrefix(name, "S3BLOB_IAM_"),
			strings.HasPrefix(name, "S3BLOB_MINIO_TEST_ACCESS_KEY"),
			strings.HasPrefix(name, "S3BLOB_MINIO_TEST_SECRET_KEY"),
			strings.HasPrefix(name, "MINIO_ROOT_"),
			strings.HasPrefix(name, "AWS_"),
			name == "MC_CONFIG_DIR":
			continue
		default:
			env = append(env, pair)
		}
	}
	roles := []string{"READER"}
	if !minioProcessReaderOnly(action, phase) {
		roles = append(roles, "WRITER")
	}
	for _, role := range roles {
		for _, suffix := range []string{"ACCESS_KEY", "SECRET_KEY"} {
			name := "S3BLOB_IAM_" + role + "_" + suffix
			if value := os.Getenv(name); value != "" {
				env = append(env, name+"="+value)
			}
		}
	}
	return env
}

func runMinIOProcessBoundary(t *testing.T, schema, phase, action string, lock researchlock.Lock, kill bool) {
	t.Helper()
	serialized, err := json.Marshal(lock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestWorkspaceMinIOCrashWorker$", "-test.v")
	cmd.Env = append(minioChildCredentialEnvironment(action, phase),
		"ACP_MINIO_CHILD_ACTION="+action,
		"ACP_MINIO_CHILD_PHASE="+phase,
		"ACP_MINIO_CHILD_SCHEMA="+schema,
		"ACP_MINIO_CHILD_LOCK="+string(serialized),
	)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start independent test executable: %v", err)
	}
	defer func() { _ = cmd.Process.Kill() }()
	reader := bufio.NewReader(out)
	want := minioProcessMarker
	if kill {
		want += "CRASH:" + phase
	} else {
		want += map[string]string{"recover": "RECOVERED:", "reopen": "REOPENED:"}[action] + phase
	}
	var trace strings.Builder
	for {
		line, readErr := reader.ReadString('\n')
		trace.WriteString(line)
		if strings.Contains(line, want) {
			break
		}
		if readErr != nil {
			_ = cmd.Wait()
			t.Fatalf("no expected process boundary %q: stdout=%q stderr=%q read=%v", want, trace.String(), stderr.String(), readErr)
		}
		if trace.Len() > 4096 {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("unexpected worker output, missing boundary %q: %.4096s", want, trace.String())
		}
	}
	if kill {
		if err := cmd.Process.Kill(); err != nil {
			t.Fatalf("could not SIGKILL real child PID %d: %v", cmd.Process.Pid, err)
		}
		waitErr := cmd.Wait()
		var exit *exec.ExitError
		if !errors.As(waitErr, &exit) {
			t.Fatalf("child was not killed by OS: %v", waitErr)
		}
		status, ok := exit.Sys().(syscall.WaitStatus)
		if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
			t.Fatalf("child did not exit via SIGKILL: status=%v err=%v", status, waitErr)
		}
		return
	}
	_, _ = io.Copy(io.Discard, reader)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("recovery child exited unsuccessfully: %v, stdout=%q stderr=%q", err, trace.String(), stderr.String())
	}
	if os.Getenv("ACP_MINIO_PROCESS_MODE") == "split" && minioProcessReaderOnly(action, phase) {
		expected := minioProcessMarker + "IDENTITY:READER_ONLY:" + action + ":" + phase
		if !strings.Contains(trace.String(), expected) {
			t.Fatalf("read-only child role evidence missing: role=%q trace=%q", expected, trace.String())
		}
		t.Logf("verified separate OS %s phase=%s contains reader-only MinIO IAM identity; writer and admin credentials redacted", action, phase)
	}
}

// TestWorkspaceRealMinIOProcessSIGKILLRecovery exercises 3 INDEPENDENT OS
// process lifetimes for every crash phase against unchanged real PG+MinIO.
// A separate real MinIO integration test creates the disposable CI bucket.
func TestWorkspaceRealMinIOProcessSIGKILLRecovery(t *testing.T) {
	if os.Getenv("S3BLOB_MINIO_TEST_ENDPOINT") == "" || os.Getenv("PGTEST_DSN") == "" {
		t.Skip("requires separate real MinIO and PostgreSQL 16 services")
	}
	if _, ok := os.LookupEnv("ACP_MINIO_CHILD_ACTION"); ok {
		t.Fatal("parent test unexpectedly running in a crash child process")
	}
	for i, phase := range []string{"before-put", "after-put", "after-stage", "after-cas"} {
		t.Run(phase, func(t *testing.T) {
			repo, pool := testRepository(t)
			ctx := context.Background()
			lock := workspacePinnedFixture(t, repo, 98501+i*10)
			if _, _, err := repo.OpenWorkspace(ctx, lock); err != nil {
				t.Fatal(err)
			}
			var schema string
			if err := pool.QueryRow(ctx, "SELECT current_schema()").Scan(&schema); err != nil {
				t.Fatal(err)
			}
			runMinIOProcessBoundary(t, schema, phase, "crash", lock, true)

			var intents, stages, commits int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_upload_intents").Scan(&intents); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_blob_stages").Scan(&stages); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_manifest_commits").Scan(&commits); err != nil {
				t.Fatal(err)
			}
			expectStage, expectCommit := 0, 0
			if phase == "after-stage" || phase == "after-cas" {
				expectStage = 1
			}
			if phase == "after-cas" {
				expectCommit = 1
			}
			if intents != 1 || stages != expectStage || commits != expectCommit {
				t.Fatalf("post-SIGKILL PG evidence unexpected: intents=%d stages=%d commits=%d", intents, stages, commits)
			}
			// A second *separate OS process* recovers after the first PID
			// was killed; a third independently reopens the durable report.
			runMinIOProcessBoundary(t, schema, phase, "recover", lock, false)
			runMinIOProcessBoundary(t, schema, phase, "reopen", lock, false)

			var refs, revisions, unknown int
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_blob_commit_refs").Scan(&refs); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, "SELECT manifest_revision FROM research_workspaces WHERE tenant_id=$1 AND workspace_id=$2",
				lock.TenantID, lock.WorkspaceID).Scan(&revisions); err != nil {
				t.Fatal(err)
			}
			if err := pool.QueryRow(ctx, "SELECT count(*) FROM workspace_upload_observations WHERE disposition='UNKNOWN'").Scan(&unknown); err != nil {
				t.Fatal(err)
			}
			if refs != 1 || revisions != 1 {
				t.Fatalf("recovery did not commit exactly one real retained report: refs=%d revision=%d", refs, revisions)
			}
			if (phase == "before-put" || phase == "after-put") && unknown < 1 {
				t.Fatalf("transport-ambiguous/missing remote outcome not recorded UNKNOWN in %s", phase)
			}
			t.Logf("real SIGKILL verified for phase=%s; retained PG schema=%s; 3 OS process lifetimes; no provider DELETE", phase, schema)
		})
	}
}
