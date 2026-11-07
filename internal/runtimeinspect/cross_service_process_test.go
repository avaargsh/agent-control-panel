package runtimeinspect

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
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
	intent := runintent.Intent{
		ID: testIntent, TenantID: testTenant, PrincipalID: "principal-1",
		ProjectID: "project-1", AgentID: "agent-1", ReleaseID: "release-1",
		SessionID: "session-1", IdempotencyKey: "replay-1", RequestDigest: testDigest,
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
	leased, err := created.ClaimDispatch(created.Version, "worker-1", time.Now().UTC(), 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	leased, err = repo.CompareAndSwap(ctx, intent.TenantID, intent.ID, created.Version, leased, event(leased.Version, 2, "agent.run-intent.dispatching"))
	if err != nil {
		t.Fatal(err)
	}

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

	payload := []byte("{\"tenant_id\":\"" + intent.TenantID + "\",\"run_intent_id\":\"" + intent.ID + "\",\"request_digest\":\"" + intent.RequestDigest + "\",\"agent_id\":\"" + intent.AgentID + "\",\"agent_release_id\":\"" + intent.ReleaseID + "\",\"session_id\":\"" + intent.SessionID + "\",\"input\":{\"message\":\"replay\"}}")
	send := func(data []byte) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+"/internal/v1/run-intents:accept", bytes.NewReader(data))
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
	lost, err := http.Post(drop.URL, "application/json", bytes.NewReader(payload))
	if lost != nil {
		_ = lost.Body.Close()
	}
	if err == nil {
		t.Fatal("unexpected ACK after injected loss")
	}
	if err := <-upstream; err != nil {
		t.Fatalf("Runtime did not commit before ACK loss: %v", err)
	}

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
		if runs != 1 || starts != 1 {
			t.Fatalf("duplicate Runtime Run/outbox: %d/%d", runs, starts)
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
	unknown, err := leased.RecordDispatchOutcome(leased.Version, leased.LeaseOwner, leased.FenceToken, time.Now().UTC(), runintent.DispatchOutcome{
		TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest, Kind: runintent.DispatchAmbiguous,
	})
	if err != nil {
		t.Fatal(err)
	}
	unknown, err = repo.CompareAndSwap(ctx, intent.TenantID, intent.ID, leased.Version, unknown, event(unknown.Version, 3, "agent.run-intent.unknown"))
	if err != nil || unknown.Status != runintent.Unknown {
		t.Fatalf("lost ACK did not persist UNKNOWN: %+v %v", unknown, err)
	}
	_ = start()
	found := wait(Found)
	if found.RunID != runID || found.WorkflowID != "agent-run/v1/"+runID {
		t.Fatalf("restarted Runtime minted another Run: %+v", found)
	}
	recon, err := unknown.BeginReconciliation(unknown.Version, "reconciler-2", time.Now().UTC(), 3*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	recon, err = repo.CompareAndSwap(ctx, intent.TenantID, intent.ID, unknown.Version, recon, event(recon.Version, 4, "agent.run-intent.reconciling"))
	if err != nil {
		t.Fatal(err)
	}
	accepted, err := recon.ApplyReconciliationResult(recon.Version, recon.LeaseOwner, recon.FenceToken, time.Now().UTC(), runintent.ReconciliationResult{
		TenantID: intent.TenantID, RunIntentID: intent.ID, RequestDigest: intent.RequestDigest,
		Kind: runintent.RuntimeFound, RunID: found.RunID, WorkflowID: found.WorkflowID,
	})
	if err != nil {
		t.Fatal(err)
	}
	accepted, err = repo.CompareAndSwap(ctx, intent.TenantID, intent.ID, recon.Version, accepted, event(accepted.Version, 5, "agent.run-intent.accepted"))
	if err != nil || accepted.Status != runintent.Accepted || accepted.RunID != runID {
		t.Fatalf("ACP reconcile: %+v %v", accepted, err)
	}
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
