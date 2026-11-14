package runtimeinspect

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The pinned workflow builds the real agent-runtime API executable. This
// is not evidence of Temporal execution or initiating-principal AuthZ.
func TestCrossServiceLostACKRecoversOneRuntimeRunAfterProcessRestart(t *testing.T) {
	if os.Getenv("ACP_CROSS_SERVICE") != "1" {
		t.Skip("only the two-service mTLS/PostgreSQL job enables this test")
	}
	acpDSN, runtimeDSN, binary := os.Getenv("ACP_DATABASE_URL"), os.Getenv("ACP_RUNTIME_DATABASE_URL"), os.Getenv("ACP_RUNTIME_API_BIN")
	if acpDSN == "" || runtimeDSN == "" || binary == "" {
		t.Fatal("two independent databases and pinned Runtime executable are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, acpDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := runpg.Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	repo := runpg.New(pool)
	// Validate the ACP side of the ACK-loss contract independently from the
	// Runtime-owned RUN_START_REQUESTED Outbox and its single-Run guarantee.
	assertACPOutbox := func(tenantID, runIntentID string, want ...string) {
		t.Helper()
		rows, err := pool.Query(ctx, `
			SELECT aggregate_version, event_type
			FROM outbox_events
			WHERE tenant_id=$1 AND aggregate_type='run_intent' AND aggregate_id=$2
			ORDER BY aggregate_version, event_type
		`, tenantID, runIntentID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		got := make([]string, 0, len(want))
		for rows.Next() {
			var version int64
			var eventType string
			if err := rows.Scan(&version, &eventType); err != nil {
				t.Fatal(err)
			}
			got = append(got, fmt.Sprintf("%d:%s", version, eventType))
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		if strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Fatalf("ACP Outbox changed (including unexpected duplicates): got %v, want %v", got, want)
		}
	}
	intent := runintent.Intent{
		ID: testIntent, TenantID: testTenant, PrincipalID: "principal-1",
		ProjectID: "project-1", AgentID: "agent-1", ReleaseID: "release-1",
		SessionID: "session-1", IdempotencyKey: "replay-1", RequestDigest: testDigest,
		PrincipalSnapshot: runintent.PrincipalSnapshot{
			Version: runintent.PrincipalSnapshotVersion, ProjectID: "project-1",
			SubjectID: "subject-1", ActorID: "actor-1", PolicyRevision: "policy-revision-1",
			ConfigDigest: "sha256:" + strings.Repeat("b", 64),
		},
		Version: 1, Status: runintent.Pending,
	}
	event := func(v uint64, n int, kind string) runpg.Event {
		return runpg.Event{
			ID:       fmt.Sprintf("00000000-0000-4000-8000-%012d", 900+n),
			Producer: "agent-control-panel", Type: kind, SchemaVersion: 1,
			TenantID: intent.TenantID, AggregateType: "run_intent", AggregateID: intent.ID,
			AggregateVersion: v, OccurredAt: time.Now().UTC(), CorrelationID: "cross-service-loss-ack",
			Payload: json.RawMessage("{\"run_intent_id\":\"" + intent.ID + "\"}"),
		}
	}
	created, inserted, err := repo.Create(ctx, intent, event(1, 1, "agent.run-intent.created"))
	if err != nil || !inserted || created.ID != intent.ID {
		t.Fatalf("ACP Create: inserted=%v %+v %v", inserted, created, err)
	}
	assertACPOutbox(intent.TenantID, intent.ID, "1:agent.run-intent.created")

	roots, serverCert, acpCert := testSPIFFECertificates(t)
	dir := t.TempDir()
	certFile, keyFile, caFile := filepath.Join(dir, "runtime.pem"), filepath.Join(dir, "runtime.key"), filepath.Join(dir, "ca.pem")
	writeProcessCertificate(t, certFile, keyFile, serverCert)
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Certificate[1]}), 0600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	origin := "https://" + addr
	inspector, err := NewClient(origin, "spiffe://example.org/runtime", roots, acpCert)
	if err != nil {
		t.Fatal(err)
	}
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots,
		Certificates: []tls.Certificate{acpCert}, ServerName: "127.0.0.1",
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 || len(state.PeerCertificates[0].URIs) != 1 ||
				state.PeerCertificates[0].URIs[0].String() != "spiffe://example.org/runtime" {
				return errors.New("wrong Runtime server identity")
			}
			return nil
		},
	}
	httpClient := &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, Proxy: nil}, Timeout: 10 * time.Second}
	defer httpClient.CloseIdleConnections()
	start := func() *exec.Cmd {
		cmd := exec.Command(binary)
		log, err := os.OpenFile(filepath.Join(dir, "runtime.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = log, log
		cmd.Env = append(os.Environ(),
			"RUNTIME_DATABASE_URL="+runtimeDSN,
			"RUNTIME_TLS_CERT="+certFile,
			"RUNTIME_TLS_KEY="+keyFile,
			"RUNTIME_CLIENT_CA="+caFile,
			"RUNTIME_ACP_SPIFFE_ID=spiffe://example.org/acp",
			"RUNTIME_ACP_LISTEN_ADDR="+addr,
		)
		if err := cmd.Start(); err != nil {
			_ = log.Close()
			t.Fatal(err)
		}
		_ = log.Close()
		t.Cleanup(func() {
			if cmd.ProcessState == nil {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}
		})
		return cmd
	}
	wait := func(want Status) Inspection {
		for deadline := time.Now().Add(25 * time.Second); time.Now().Before(deadline); {
			got, err := inspector.Inspect(ctx, InspectRequest{TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest})
			if err == nil && got.Status == want {
				return got
			}
			time.Sleep(150 * time.Millisecond)
		}
		logs, _ := os.ReadFile(filepath.Join(dir, "runtime.log"))
		t.Fatalf("Runtime did not return %s: %s", want, string(logs))
		return Inspection{}
	}
	proc := start()
	_ = wait(AbsentUncertain)

	payload, err := json.Marshal(map[string]any{
		"tenant_id": intent.TenantID, "run_intent_id": intent.ID,
		"request_digest": intent.RequestDigest, "agent_id": intent.AgentID,
		"agent_release_id": intent.ReleaseID, "session_id": intent.SessionID,
		"input": map[string]string{"message": "replay"},
		"principal_context": map[string]string{
			"version":         intent.PrincipalSnapshot.Version,
			"project_id":      intent.PrincipalSnapshot.ProjectID,
			"subject_id":      intent.PrincipalSnapshot.SubjectID,
			"actor_id":        intent.PrincipalSnapshot.ActorID,
			"policy_revision": intent.PrincipalSnapshot.PolicyRevision,
			"config_digest":   intent.PrincipalSnapshot.ConfigDigest,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	send := func(data []byte) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/internal/v2/run-intents:accept", bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return httpClient.Do(req)
	}
	// Drop the caller-facing ACK only after a real authenticated Runtime
	// API request commits. The ACP dispatcher receives EOF, not a receipt.
	upstream := make(chan error, 1)
	drop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		res, err := send(payload)
		if err == nil {
			_, err = io.Copy(io.Discard, res.Body)
			_ = res.Body.Close()
			if err == nil && res.StatusCode != http.StatusCreated {
				err = fmt.Errorf("first acceptance HTTP %d", res.StatusCode)
			}
		}
		upstream <- err
		conn, _, hErr := w.(http.Hijacker).Hijack()
		if hErr == nil {
			_ = conn.Close()
		}
	}))
	defer drop.Close()
	// The dispatcher is now a separately killable OS process; it uses the
	// real ACP PostgreSQL state and a test-only transport proxy. The proxy
	// drops the ACK only after authenticating and committing at Runtime.
	dispatch := exec.Command(os.Args[0], "-test.run=^TestDispatchLostACKChild$")
	dispatch.Env = append(os.Environ(),
		"ACP_DISPATCH_CHILD=1",
		"ACP_DATABASE_URL="+acpDSN,
		"ACP_DISPATCH_TENANT="+intent.TenantID,
		"ACP_DISPATCH_INTENT="+intent.ID,
		"ACP_DISPATCH_ENDPOINT="+drop.URL,
		"ACP_DISPATCH_PAYLOAD="+base64.StdEncoding.EncodeToString(payload),
	)
	if output, dispatchErr := dispatch.CombinedOutput(); dispatchErr != nil {
		t.Fatalf("separate ACP dispatch process failed: %v: %s", dispatchErr, output)
	}
	unknown, err := repo.Get(ctx, intent.TenantID, intent.ID)
	if err != nil || unknown.Status != runintent.Unknown || unknown.Version != 3 {
		t.Fatalf("separate dispatch process did not persist UNKNOWN: %+v %v", unknown, err)
	}
	if err := <-upstream; err != nil {
		t.Fatalf("Runtime did not commit before ACK loss: %v", err)
	}
	assertACPOutbox(intent.TenantID, intent.ID,
		"1:agent.run-intent.created",
		"2:agent.run-intent.dispatching",
		"3:agent.run-intent.unknown")

	runtimePool, err := pgxpool.New(ctx, runtimeDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer runtimePool.Close()
	assertOne := func() string {
		var id string
		var runs, starts int
		if err := runtimePool.QueryRow(ctx, "SELECT run_id::text FROM runs WHERE run_intent_id=$1::uuid", intent.ID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if err := runtimePool.QueryRow(ctx, "SELECT count(*) FROM runs WHERE run_intent_id=$1::uuid", intent.ID).Scan(&runs); err != nil {
			t.Fatal(err)
		}
		if err := runtimePool.QueryRow(ctx, "SELECT count(*) FROM runtime_outbox WHERE aggregate_id=$1::uuid AND event_type='RUN_START_REQUESTED'", id).Scan(&starts); err != nil {
			t.Fatal(err)
		}
		var snapshots int
		if err := runtimePool.QueryRow(ctx, `
			SELECT count(*) FROM runtime_run_principal_snapshots
			WHERE run_id=$1::uuid AND tenant_id=$2
			  AND issuer_spiffe_id='spiffe://example.org/acp'
			  AND project_id=$3 AND subject_id=$4
			  AND actor_id=$5 AND policy_revision=$6
			  AND config_digest=$7
		`, id, intent.TenantID, intent.PrincipalSnapshot.ProjectID,
			intent.PrincipalSnapshot.SubjectID, intent.PrincipalSnapshot.ActorID,
			intent.PrincipalSnapshot.PolicyRevision, intent.PrincipalSnapshot.ConfigDigest).Scan(&snapshots); err != nil {
			t.Fatal(err)
		}
		if runs != 1 || starts != 1 || snapshots != 1 {
			t.Fatalf("duplicate or unbound Runtime Run/outbox/principal: %d/%d/%d", runs, starts, snapshots)
		}
		return id
	}
	runID := assertOne()
	if err := proc.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = proc.Wait()
	if _, inspectErr := inspector.Inspect(ctx, InspectRequest{TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest}); !errors.Is(inspectErr, ErrUnavailable) {
		t.Fatalf("offline inspect was promoted to an authoritative result: %v", inspectErr)
	}
	_ = start()
	found := wait(Found)
	if found.RunID != runID || found.WorkflowID != "agent-run/v1/"+runID {
		t.Fatalf("restarted Runtime minted another Run: %+v", found)
	}
	// A distinct OS process performs the real PostgreSQL lease claim using
	// ReconcileOnce, then blocks at Inspect. SIGKILL must leave the lease
	// durable so the restarted worker can fence it after database expiry.
	crash := exec.Command(os.Args[0], "-test.run=^TestCrashReconcilerAfterClaimChild$")
	crash.Env = append(os.Environ(),
		"ACP_RECOVERY_CRASH_CHILD=1",
		"ACP_DATABASE_URL="+acpDSN,
		"ACP_RECOVERY_TENANT="+intent.TenantID,
		"ACP_RECOVERY_INTENT="+intent.ID,
	)
	if err := crash.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if crash.ProcessState == nil {
			_ = crash.Process.Kill()
			_ = crash.Wait()
		}
	})
	var abandoned runintent.Intent
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		observed, lookupErr := repo.Get(ctx, intent.TenantID, intent.ID)
		if lookupErr != nil {
			t.Fatal(lookupErr)
		}
		if observed.Status == runintent.Reconciling {
			abandoned = observed
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if abandoned.Status != runintent.Reconciling {
		t.Fatal("separate worker did not commit RECONCILING before SIGKILL")
	}
	if err := crash.Process.Kill(); err != nil {
		t.Fatalf("SIGKILL recovery worker: %v", err)
	}
	_ = crash.Wait()
	stillAbandoned, err := repo.Get(ctx, intent.TenantID, intent.ID)
	if err != nil || stillAbandoned.Status != runintent.Reconciling ||
		stillAbandoned.Version != abandoned.Version || stillAbandoned.FenceToken != abandoned.FenceToken {
		t.Fatalf("crashed worker did not preserve its committed lease: %+v %v", stillAbandoned, err)
	}
	if delay := time.Until(abandoned.LeaseExpiresAt) + 150*time.Millisecond; delay > 0 {
		time.Sleep(delay)
	}
	// Two independently scheduled callers race over the same PostgreSQL row.
	// Only one may advance the version/fence; both share the real Runtime mTLS
	// Inspect boundary and neither has a StartRun capability.
	type reconcileOutcome struct {
		intent runintent.Intent
		err    error
	}
	outcomes := make(chan reconcileOutcome, 2)
	ready := make(chan struct{})
	for i := 0; i < 2; i++ {
		go func(i int) {
			<-ready
			got, reconcileErr := ReconcileOnce(ctx, repo, inspector, intent.TenantID, intent.ID, fmt.Sprintf("restarted-%d", i), 3*time.Minute)
			outcomes <- reconcileOutcome{intent: got, err: reconcileErr}
		}(i)
	}
	close(ready)
	acceptedCount := 0
	for i := 0; i < 2; i++ {
		outcome := <-outcomes
		if outcome.err == nil {
			if outcome.intent.Status != runintent.Accepted || outcome.intent.RunID != runID {
				t.Fatalf("competing reconciler returned incorrect success: %+v", outcome.intent)
			}
			acceptedCount++
		} else if !errors.Is(outcome.err, runpg.ErrStaleVersion) &&
			!errors.Is(outcome.err, runintent.ErrLeaseExpired) &&
			!errors.Is(outcome.err, ErrNotReconcilable) {
			t.Fatalf("unexpected concurrent reconciliation error: %v", outcome.err)
		}
	}
	if acceptedCount < 1 {
		t.Fatal("no reconciler recovered the committed Runtime Run")
	}
	accepted, err := repo.Get(ctx, intent.TenantID, intent.ID)
	if err != nil || accepted.Status != runintent.Accepted || accepted.RunID != runID ||
		accepted.Version != abandoned.Version+3 || accepted.FenceToken != abandoned.FenceToken+2 {
		t.Fatalf("ACP lease takeover did not produce one fenced Run: %+v %v", accepted, err)
	}
	// The old worker cannot persist its receipt using the pre-crash lease.
	stale, err := abandoned.ApplyReconciliationResult(abandoned.Version, abandoned.LeaseOwner,
		abandoned.FenceToken, abandoned.LeaseExpiresAt.Add(-time.Nanosecond), runintent.ReconciliationResult{
			TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest,
			Kind: runintent.RuntimeFound, RunID: found.RunID, WorkflowID: found.WorkflowID,
		})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CompareAndSwap(ctx, intent.TenantID, intent.ID, abandoned.Version, stale,
		event(stale.Version, 8, "agent.run-intent.accepted")); !errors.Is(err, runpg.ErrStaleVersion) {
		t.Fatalf("stale pre-crash reconciler overwrote authoritative state: %v", err)
	}
	assertACPOutbox(intent.TenantID, intent.ID,
		"1:agent.run-intent.created",
		"2:agent.run-intent.dispatching",
		"3:agent.run-intent.unknown",
		"4:agent.run-intent.reconciling",
		"5:agent.run-intent.unknown",
		"6:agent.run-intent.reconciling",
		"7:agent.run-intent.accepted")
	res, err := send(payload)
	if err != nil {
		t.Fatal(err)
	}
	var replay struct {
		Status  string `json:"status"`
		RunID   string `json:"run_id"`
		Created bool   `json:"created"`
	}
	if err := json.NewDecoder(res.Body).Decode(&replay); err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || replay.Status != "FOUND" || replay.RunID != runID || replay.Created {
		t.Fatalf("replay mutated Run: HTTP %d %+v", res.StatusCode, replay)
	}
	changed := bytes.Replace(payload, []byte(intent.RequestDigest), []byte("sha256:"+strings.Repeat("b", 64)), 1)
	conflict, err := send(changed)
	if err != nil {
		t.Fatal(err)
	}
	_ = conflict.Body.Close()
	if conflict.StatusCode != http.StatusConflict {
		t.Fatalf("changed digest not rejected: %d", conflict.StatusCode)
	}
	if id := assertOne(); id != runID {
		t.Fatalf("Runtime Run changed to %s", id)
	}
	assertACPOutbox(intent.TenantID, intent.ID,
		"1:agent.run-intent.created",
		"2:agent.run-intent.dispatching",
		"3:agent.run-intent.unknown",
		"4:agent.run-intent.reconciling",
		"5:agent.run-intent.unknown",
		"6:agent.run-intent.reconciling",
		"7:agent.run-intent.accepted")
	stored, err := repo.Get(ctx, intent.TenantID, intent.ID)
	if err != nil || stored.Status != runintent.Accepted || stored.RunID != runID {
		t.Fatalf("ACP persisted receipt: %+v %v", stored, err)
	}
}

func writeProcessCertificate(t *testing.T, certFile, keyFile string, identity tls.Certificate) {
	t.Helper()
	var encoded []byte
	for _, der := range identity.Certificate {
		encoded = append(encoded, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	key, err := x509.MarshalPKCS8PrivateKey(identity.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certFile, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
}

type blockedReconciliationInspector struct{}

func (blockedReconciliationInspector) Inspect(ctx context.Context, _ InspectRequest) (Inspection, error) {
	<-ctx.Done()
	return Inspection{}, ctx.Err()
}

// This helper is executed only by the parent test as a distinct, killable OS
// process. It claims real PostgreSQL state but cannot call Runtime StartRun.
func TestCrashReconcilerAfterClaimChild(t *testing.T) {
	if os.Getenv("ACP_RECOVERY_CRASH_CHILD") != "1" {
		t.Skip("only the real-process crash test starts this worker")
	}
	dsn := os.Getenv("ACP_DATABASE_URL")
	tenantID := os.Getenv("ACP_RECOVERY_TENANT")
	intentID := os.Getenv("ACP_RECOVERY_INTENT")
	if dsn == "" || tenantID == "" || intentID == "" {
		t.Fatal("child recovery scope is missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	_, err = ReconcileOnce(ctx, runpg.New(pool), blockedReconciliationInspector{},
		tenantID, intentID, "crashed-reconciler", 600*time.Millisecond)
	t.Fatalf("reconciler exited before injected SIGKILL: %v", err)
}

var errInjectedACKDelivered = errors.New("injected lost ACK unexpectedly delivered an HTTP response")

type lostACKDispatchAdapter struct {
	endpoint string
	payload  []byte
	calls    int
}

func (a *lostACKDispatchAdapter) Accept(ctx context.Context, claimed runintent.Intent) (runintent.DispatchOutcome, error) {
	a.calls++
	if claimed.Status != runintent.Dispatching {
		return runintent.DispatchOutcome{}, errors.New("dispatcher called Runtime without a committed lease")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(a.payload))
	if err != nil {
		return runintent.DispatchOutcome{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if res != nil {
		_ = res.Body.Close()
	}
	if err == nil {
		return runintent.DispatchOutcome{}, errInjectedACKDelivered
	}
	return runintent.DispatchOutcome{}, err
}

// Test-only subprocess: no production service entry point or principal issuer.
// It verifies a real ACP process persists UNKNOWN after a lost HTTP ACK.
func TestDispatchLostACKChild(t *testing.T) {
	if os.Getenv("ACP_DISPATCH_CHILD") != "1" {
		t.Skip("only the two-process ACK-loss test starts this helper")
	}
	dsn := os.Getenv("ACP_DATABASE_URL")
	tenantID := os.Getenv("ACP_DISPATCH_TENANT")
	intentID := os.Getenv("ACP_DISPATCH_INTENT")
	endpoint := os.Getenv("ACP_DISPATCH_ENDPOINT")
	encoded := os.Getenv("ACP_DISPATCH_PAYLOAD")
	if dsn == "" || tenantID == "" || intentID == "" || endpoint == "" || encoded == "" {
		t.Fatal("dispatch subprocess requires PostgreSQL, scope and test transport")
	}
	payload, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	adapter := &lostACKDispatchAdapter{endpoint: endpoint, payload: payload}
	got, dispatchErr := DispatchOnce(ctx, runpg.New(pool), adapter, tenantID, intentID, "worker-1", 3*time.Minute)
	if errors.Is(dispatchErr, errInjectedACKDelivered) {
		t.Fatal("the test proxy delivered an ACK instead of losing it")
	}
	if dispatchErr == nil || got.Status != runintent.Unknown || got.Version != 3 || adapter.calls != 1 {
		t.Fatalf("subprocess must persist one ambiguous dispatch: %+v %v calls=%d", got, dispatchErr, adapter.calls)
	}
}
