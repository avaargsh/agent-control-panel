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
	golden := os.Getenv("ACP_GOLDEN_PATH") == "1"
	timeout := 90 * time.Second
	if golden {
		timeout = 8 * time.Minute
		if os.Getenv("ACP_RUNTIME_TEMPORAL_TEST_BIN") == "" {
			t.Fatal("Golden Path requires the pinned Temporal test binary")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
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
	input := []byte(`{ "message": "replay", "number": 9007199254740993 }`)
	var releaseArtifact []byte
	if golden {
		input = []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`)
		releaseArtifact, intent.PrincipalSnapshot.ConfigDigest = goldenReleaseArtifact(t, intent)
	}
	intent.RequestDigest, err = runintent.ExecutionInputDigest(intent, input)
	if err != nil {
		t.Fatal(err)
	}
	if golden {
		intent = admitGoldenPathWithLiveIssuer(t, ctx, pool, repo, intent, input)
	} else {
		created, inserted, err := repo.CreateWithInput(ctx, intent, event(1, 1, "agent.run-intent.created"), input)
		if err != nil || !inserted || created.ID != intent.ID {
			t.Fatalf("ACP Create: inserted=%v %+v %v", inserted, created, err)
		}
	}
	assertACPOutbox(intent.TenantID, intent.ID, "1:agent.run-intent.created")

	roots, serverCert, acpCert := testSPIFFECertificates(t)
	dir := t.TempDir()
	certFile, keyFile, caFile := filepath.Join(dir, "runtime.pem"), filepath.Join(dir, "runtime.key"), filepath.Join(dir, "ca.pem")
	writeProcessCertificate(t, certFile, keyFile, serverCert)
	acpCertFile, acpKeyFile := filepath.Join(dir, "acp.pem"), filepath.Join(dir, "acp.key")
	writeProcessCertificate(t, acpCertFile, acpKeyFile, acpCert)
	// Guard's Runtime Safety server has a dedicated strict SPIFFE service
	// identity, not ACP Inspect's legacy spiffe://example.org/runtime
	// identity. Keep the latter unchanged for all preexisting clients.
	composed := golden && os.Getenv("ACP_LIVE_GUARD_COMPOSED") == "1"
	guardSafetyCertFile, guardSafetyKeyFile, guardSafetyRootFile := "", "", ""
	safetyServerCertFile, safetyServerKeyFile, guardSafetyCAFile := "", "", ""
	if composed {
		_, safetyServer, safetyClient := testSPIFFECertificatesFor(t,
			"spiffe://example.org/ns/runtime/sa/agent-runtime",
			"spiffe://example.org/ns/guard/sa/engageguard")
		guardSafetyCertFile = filepath.Join(dir, "runtime-guard.pem")
		guardSafetyKeyFile = filepath.Join(dir, "runtime-guard.key")
		guardSafetyRootFile = filepath.Join(dir, "runtime-guard-roots.pem")
		safetyServerCertFile = filepath.Join(dir, "runtime-safety-server.pem")
		safetyServerKeyFile = filepath.Join(dir, "runtime-safety-server.key")
		guardSafetyCAFile = filepath.Join(dir, "runtime-safety-trust.pem")
		writeProcessCertificate(t, guardSafetyCertFile, guardSafetyKeyFile, safetyClient)
		writeProcessCertificate(t, safetyServerCertFile, safetyServerKeyFile, safetyServer)
		rootsPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: safetyServer.Certificate[1]})
		for _, path := range []string{guardSafetyRootFile, guardSafetyCAFile} {
			if err := os.WriteFile(path, rootsPEM, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
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
		cmd.Env = append(goldenPathChildEnvironment(),
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
	safetyOrigin := ""
	if composed {
		// Actual Runtime acp-api implementation, backed by the SAME
		// PostgreSQL Run/Breaker, hosted behind a distinct strict SPIFFE
		// server identity and separate mTLS client CA. Unlike a fake
		// handler, it re-reads current durable breaker state on every GET.
		safetyListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		safetyAddress := safetyListener.Addr().String()
		_ = safetyListener.Close()
		safetyOrigin = "https://" + safetyAddress
		safety := exec.Command(binary)
		safety.Env = append(goldenPathChildEnvironment(),
			"RUNTIME_DATABASE_URL="+runtimeDSN,
			"RUNTIME_TLS_CERT="+safetyServerCertFile,
			"RUNTIME_TLS_KEY="+safetyServerKeyFile,
			"RUNTIME_CLIENT_CA="+guardSafetyCAFile,
			"RUNTIME_ACP_SPIFFE_ID=spiffe://example.org/acp",
			"RUNTIME_ACP_LISTEN_ADDR="+safetyAddress,
			"RUNTIME_SAFETY_SPIFFE_ID=spiffe://example.org/ns/guard/sa/engageguard",
			"RUNTIME_SAFETY_TENANT="+intent.TenantID)
		safetyLog, err := os.OpenFile(filepath.Join(dir, "runtime-safety.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if err != nil {
			t.Fatal(err)
		}
		safety.Stdout, safety.Stderr = safetyLog, safetyLog
		if err := safety.Start(); err != nil {
			_ = safetyLog.Close()
			t.Fatal(err)
		}
		_ = safetyLog.Close()
		t.Cleanup(func() { _ = safety.Process.Kill(); _ = safety.Wait() })
		ready := false
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
			conn, dialErr := net.DialTimeout("tcp", safetyAddress, time.Second)
			if dialErr == nil {
				_ = conn.Close()
				ready = true
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if !ready {
			logs, _ := os.ReadFile(filepath.Join(dir, "runtime-safety.log"))
			t.Fatalf("real independent strict-SPIFFE Runtime Safety API unavailable: %s", logs)
		}
	}

	payload, err := buildAcceptanceBody(intent, input)
	if err != nil {
		t.Fatal(err)
	}
	send := func(data []byte) (*http.Response, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, origin+developmentAcceptPath, bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return httpClient.Do(req)
	}
	// A separately killable ACP process uses the actual DevelopmentAcceptor,
	// PostgreSQL input repository and verified mutual TLS. Its test-only
	// transport discards the response after the real Runtime commits.
	dispatch := exec.Command(os.Args[0], "-test.run=^TestDispatchLostACKChild$")
	dispatch.Env = append(goldenPathChildEnvironment(),
		"ACP_DISPATCH_CHILD=1",
		"ACP_DATABASE_URL="+acpDSN,
		"ACP_DISPATCH_TENANT="+intent.TenantID,
		"ACP_DISPATCH_INTENT="+intent.ID,
		"ACP_DISPATCH_ENDPOINT="+origin,
		"ACP_DISPATCH_CERT="+acpCertFile,
		"ACP_DISPATCH_KEY="+acpKeyFile,
		"ACP_DISPATCH_CA="+caFile,
	)
	if output, dispatchErr := dispatch.CombinedOutput(); dispatchErr != nil {
		t.Fatalf("separate ACP dispatch process failed: %v: %s", dispatchErr, output)
	}
	unknown, err := repo.Get(ctx, intent.TenantID, intent.ID)
	if err != nil || unknown.Status != runintent.Unknown || unknown.Version != 3 {
		t.Fatalf("separate dispatch process did not persist UNKNOWN: %+v %v", unknown, err)
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
		var sameInput bool
		if err := runtimePool.QueryRow(ctx, "SELECT run_id::text FROM runs WHERE run_intent_id=$1::uuid", intent.ID).Scan(&id); err != nil {
			t.Fatal(err)
		}
		if err := runtimePool.QueryRow(ctx, "SELECT count(*) FROM runs WHERE run_intent_id=$1::uuid", intent.ID).Scan(&runs); err != nil {
			t.Fatal(err)
		}
		if err := runtimePool.QueryRow(ctx, "SELECT input=$2::jsonb FROM runs WHERE run_intent_id=$1::uuid", intent.ID, string(input)).Scan(&sameInput); err != nil || !sameInput {
			t.Fatalf("Runtime normalized input differs from ACP persisted input: %v", err)
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
	crash.Env = append(goldenPathChildEnvironment(),
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

	// Exercise the same ACP Run in the actual pinned Runtime Temporal
	// dispatcher. Do this BEFORE the conflicting-binding negative control
	// seeds a second Run. The external driver refuses to create or seed Runs.
	if golden {
		// The Run recovered by the real mTLS reconciliation must still
		// possess its original OAuth client membership, not an arbitrary
		// current role for the same human/workload principal.
		ref := runpg.ExecutionAuthorityRef{TenantID: intent.TenantID, RunIntentID: intent.ID,
			RequestDigest: intent.RequestDigest, RunID: runID}
		authority, err := runpg.New(pool).GetExecutionAuthority(ctx, ref)
		if err != nil || authority.Ref != ref || authority.Snapshot != intent.PrincipalSnapshot {
			t.Fatalf("live OAuth accepted Run lost catalog authority: %+v %v", authority, err)
		}
		readAuthority, liveEnv := newLiveExecutionAuthorityReader(t, pool, acpDSN, runtimeDSN, runpg.New(pool), ref, intent, releaseArtifact)
		if composed {
			liveEnv = append(liveEnv,
				"DECISION_LIVE_GUARD_COMPOSED_RUNTIME_ORIGIN="+safetyOrigin,
				"DECISION_LIVE_GUARD_COMPOSED_RUNTIME_PEER=spiffe://example.org/ns/runtime/sa/agent-runtime",
				"DECISION_LIVE_GUARD_COMPOSED_RUNTIME_ROOTS="+guardSafetyRootFile,
				"DECISION_LIVE_GUARD_COMPOSED_RUNTIME_CERT="+guardSafetyCertFile,
				"DECISION_LIVE_GUARD_COMPOSED_RUNTIME_KEY="+guardSafetyKeyFile)
		}
		readAuthority(http.StatusOK)
		if _, err := pool.Exec(ctx, "INSERT INTO admission_memberships VALUES ($1,$2,$3,'other-ci-client','RUNNER',true)", intent.TenantID, intent.ProjectID, intent.PrincipalID); err != nil {
			t.Fatal(err)
		}
		if _, err := pool.Exec(ctx, "UPDATE admission_memberships SET enabled=false WHERE tenant_id=$1 AND client_id='acp-ci-runner'", intent.TenantID); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.GetExecutionAuthority(ctx, ref); !errors.Is(err, runpg.ErrCatalogDenied) {
			t.Fatalf("revoked original OAuth client obtained continuation: %v", err)
		}
		readAuthority(http.StatusForbidden)
		if _, err := pool.Exec(ctx, "UPDATE admission_memberships SET enabled=true WHERE tenant_id=$1 AND client_id='acp-ci-runner'", intent.TenantID); err != nil {
			t.Fatal(err)
		}
		if _, err := repo.GetExecutionAuthority(ctx, ref); err != nil {
			t.Fatalf("restored catalog authority not observed: %v", err)
		}
		readAuthority(http.StatusOK)
		t.Logf("live OAuth origin bound to recovered Run %s; different active client did not bypass revocation", runID)
		temporal := exec.CommandContext(ctx, os.Getenv("ACP_RUNTIME_TEMPORAL_TEST_BIN"),
			"-test.v", "-test.run=^TestExternalACPAdmissionTemporalRecovery$", "-test.timeout=6m")
		temporal.Env = append(goldenPathChildEnvironment(),
			"RUNTIME_EXTERNAL_ACP_TEST=1",
			"RUNTIME_EXTERNAL_DATABASE_URL="+runtimeDSN,
			"RUNTIME_EXTERNAL_TENANT="+intent.TenantID,
			"RUNTIME_EXTERNAL_INTENT="+intent.ID,
			"RUNTIME_EXTERNAL_DIGEST="+intent.RequestDigest,
			"RUNTIME_EXTERNAL_RUN="+runID,
			"RUNTIME_EXTERNAL_SUBJECT="+intent.PrincipalSnapshot.SubjectID,
			"RUNTIME_EXTERNAL_ACTOR="+intent.PrincipalSnapshot.ActorID,
			"RUNTIME_EXTERNAL_POLICY="+intent.PrincipalSnapshot.PolicyRevision,
		)
		temporal.Env = append(temporal.Env, liveEnv...)
		if os.Getenv("ACP_LIVE_GUARD_CLIENT") == "1" {
			guardBin := os.Getenv("ACP_GUARD_TEST_BIN")
			if guardBin == "" {
				t.Fatal("missing independently compiled EngageGuard client binary")
			}
			temporal.Env = append(temporal.Env, "DECISION_LIVE_GUARD_BIN="+guardBin)
		}
		if os.Getenv("ACP_LIVE_CONTINUATION") == "1" {
			temporal.Env = append(temporal.Env, "RUNTIME_EXTERNAL_LIVE_CONTINUATION=1")
		}
		// A disposable ACP test controller, not Guard or Decision, changes the
		// *actual Runtime PostgreSQL breaker generation* only after both
		// Decision and ACP have positively verified the same Run. The Guard
		// subprocess then makes its final real Runtime safety mTLS read.
		// Restore the synthetic fault before the later source revocation
		// assertions. This is never a production breaker transition API.
		var postflightDone chan error
		if composed {
			syncDir := t.TempDir()
			temporal.Env = append(temporal.Env, "DECISION_LIVE_GUARD_COMPOSED_SYNC_DIR="+syncDir)
			postflightDone = make(chan error, 1)
			go func() {
				waitFile := func(filename string) error {
					deadline := time.Now().Add(3 * time.Minute)
					for time.Now().Before(deadline) {
						raw, err := os.ReadFile(filepath.Join(syncDir, filename))
						if err == nil && string(raw) == runID {
							return nil
						}
						if err != nil && !os.IsNotExist(err) {
							return fmt.Errorf("%s: %w", filename, err)
						}
						select {
						case <-ctx.Done():
							return ctx.Err()
						case <-time.After(40 * time.Millisecond):
						}
					}
					return fmt.Errorf("missing independent Guard postflight marker %s", filename)
				}
				if err := waitFile("postflight-capability-verified"); err != nil {
					postflightDone <- err
					return
				}
				var original int64
				err := runtimePool.QueryRow(ctx, `
					SELECT version FROM runtime_circuit_breakers
					WHERE scope_kind='RUN' AND scope_id=$1
				`, runID).Scan(&original)
				if err != nil || original < 1 {
					postflightDone <- fmt.Errorf("original Runtime breaker unavailable: %w", err)
					return
				}
				change, err := runtimePool.Exec(ctx, `
					UPDATE runtime_circuit_breakers
					SET version=version+1, updated_at=clock_timestamp()
					WHERE scope_kind='RUN' AND scope_id=$1 AND version=$2
				`, runID, original)
				if err != nil || change.RowsAffected() != 1 {
					postflightDone <- fmt.Errorf("failed isolated breaker CAS: %v", err)
					return
				}
				if err := os.WriteFile(filepath.Join(syncDir, "postflight-breaker-changed"), []byte(runID), 0600); err != nil {
					postflightDone <- err
					return
				}
				deniedErr := waitFile("postflight-denied")
				// Even after a test failure, restore only the exact fixture
				// value that this controller changed and never overwrite a
				// concurrent unrelated breaker generation.
				restore, restoreErr := runtimePool.Exec(ctx, `
					UPDATE runtime_circuit_breakers
					SET version=$2,updated_at=clock_timestamp()
					WHERE scope_kind='RUN' AND scope_id=$1 AND version=$3
				`, runID, original, original+1)
				if restoreErr != nil || restore.RowsAffected() != 1 {
					postflightDone <- fmt.Errorf("failed isolated breaker cleanup: %v; postflight: %v", restoreErr, deniedErr)
					return
				}
				if deniedErr != nil {
					postflightDone <- deniedErr
					return
				}
				if err := os.WriteFile(filepath.Join(syncDir, "postflight-restored"), []byte(runID), 0600); err != nil {
					postflightDone <- err
					return
				}
				postflightDone <- nil
			}()
		}
		out, runErr := temporal.CombinedOutput()
		if composed {
			select {
			case err := <-postflightDone:
				if err != nil {
					t.Fatalf("real Guard postflight generation fault injection failed: %v, Temporal output: %s", err, out)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("missing real Guard postflight completion: %v %s", runErr, out)
			}
		}
		if runErr != nil || !bytes.Contains(out, []byte("--- PASS: TestExternalACPAdmissionTemporalRecovery")) {
			t.Fatalf("same-Run Temporal execution/recovery failed: %v %s", runErr, out)
		}
		if os.Getenv("ACP_LIVE_DECISION") == "1" &&
			(!bytes.Contains(out, []byte("--- PASS: TestExternalLiveDecisionCore ")) ||
				!bytes.Contains(out, []byte("actual same-Run DecisionRecord "))) {
			t.Fatal("missing actual independently verified DecisionRecord PASS evidence")
		}
		if os.Getenv("ACP_LIVE_CONTINUATION") == "1" &&
			(!bytes.Contains(out, []byte("actual Runtime continuation SIGKILL recovered Run "+runID)) ||
				!bytes.Contains(out, []byte("DECISION_ACCEPTED; live source revocation denied"))) {
			t.Fatal("missing actual post-acceptance Worker SIGKILL and source revocation evidence")
		}
		if os.Getenv("ACP_LIVE_GUARD_STEP") == "1" &&
			!bytes.Contains(out, []byte("real Guard Plan Step mTLS verified same-Run "+runID+" and source revocation denied")) {
			t.Fatal("missing same-Run independently authenticated Guard Plan/Step and post-revocation evidence")
		}
		if os.Getenv("ACP_LIVE_GUARD_CLIENT") == "1" &&
			(!bytes.Contains(out, []byte("real EngageGuard DecisionPlanClient verified same-Run "+runID)) ||
				!bytes.Contains(out, []byte("real EngageGuard DecisionPlanClient denied revoked same-Run "+runID))) {
			t.Fatal("missing independently compiled EngageGuard client positive and revoked negative evidence")
		}
		if composed &&
			(!bytes.Contains(out, []byte("real ComposedRunVerifier verified three authorities on same-Run "+runID)) ||
				!bytes.Contains(out, []byte("real ComposedRunVerifier denied live postflight breaker drift same-Run "+runID)) ||
				!bytes.Contains(out, []byte("real ComposedRunVerifier denied revoked source same-Run "+runID))) {
			t.Fatal("missing independently authenticated triple-authority and postflight breaker-denial evidence")
		}
		t.Logf("same-Run Temporal evidence:\n%s", out)
		if id := assertOne(); id != runID {
			t.Fatal("Temporal recovered a different Runtime Run")
		}
	}

	// Positive control for the confused-binding gap: a separately committed
	// Runtime Run has the same correlation digest but a different principal.
	// Lose the authoritative 409 response to an actual ACP dispatch. A
	// weaker v1 read would falsely accept the existing Run.
	conflicted := intent
	conflicted.ID = "00000000-0000-4000-8000-000000000991"
	conflicted.IdempotencyKey = "conflicting-principal"
	conflicted.RequestDigest, err = runintent.ExecutionInputDigest(conflicted, input)
	if err != nil {
		t.Fatal(err)
	}
	conflictEvent := event(1, 10, "agent.run-intent.created")
	conflictEvent.AggregateID = conflicted.ID
	conflictEvent.Payload = json.RawMessage(`{"run_intent_id":"` + conflicted.ID + `"}`)
	if _, inserted, err := repo.CreateWithInput(ctx, conflicted, conflictEvent, input); err != nil || !inserted {
		t.Fatalf("conflicted ACP create: %v", err)
	}
	wrongBinding := conflicted
	wrongBinding.PrincipalSnapshot.SubjectID = "different-subject"
	wrongPayload, err := buildAcceptanceBody(wrongBinding, input)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := send(wrongPayload)
	if err != nil {
		t.Fatal(err)
	}
	_ = seed.Body.Close()
	if seed.StatusCode != http.StatusCreated {
		t.Fatalf("conflicting Runtime positive control was not created: %d", seed.StatusCode)
	}
	weak, err := inspector.Inspect(ctx, InspectRequest{
		TenantID: conflicted.TenantID, RunIntentID: conflicted.ID, RequestDigest: conflicted.RequestDigest,
	})
	if err != nil || weak.Status != Found {
		t.Fatalf("v1 positive control did not expose the weak correlation result: %v", err)
	}
	conflictClient, err := NewClient(origin, "spiffe://example.org/runtime", roots, acpCert)
	if err != nil {
		t.Fatal(err)
	}
	droppedConflict := &lostACKTransport{upstream: conflictClient.client.Transport, wantStatus: http.StatusConflict}
	conflictClient.client.Transport = droppedConflict
	conflictAdapter, err := NewDevelopmentAcceptor(conflictClient, repo)
	if err != nil {
		t.Fatal(err)
	}
	ambiguous, err := DispatchOnce(ctx, repo, conflictAdapter, conflicted.TenantID, conflicted.ID, "conflict-dispatcher", time.Minute)
	if !errors.Is(err, ErrUnavailable) || ambiguous.Status != runintent.Unknown ||
		!droppedConflict.dropped || droppedConflict.calls != 1 {
		t.Fatalf("lost conflict ACK did not create UNKNOWN: %+v %v", ambiguous, err)
	}
	quarantined, err := ReconcileOnce(ctx, repo, inspector, conflicted.TenantID, conflicted.ID, "conflict-reconciler", time.Minute)
	if !errors.Is(err, ErrRemoteConflict) || quarantined.Status != runintent.ManualReview ||
		quarantined.RunID != "" || quarantined.ManualReviewCode != "RUNTIME_STATE_CONFLICT" {
		t.Fatalf("conflicting principal was not quarantined: %+v %v", quarantined, err)
	}
	assertACPOutbox(conflicted.TenantID, conflicted.ID,
		"1:agent.run-intent.created",
		"2:agent.run-intent.dispatching",
		"3:agent.run-intent.unknown",
		"4:agent.run-intent.reconciling",
		"5:agent.run-intent.manual-review")
	var conflictingRuns, conflictingStarts int
	if err := runtimePool.QueryRow(ctx, `
		SELECT count(*), (SELECT count(*) FROM runtime_outbox WHERE aggregate_id=$2::uuid AND event_type='RUN_START_REQUESTED')
		FROM runs WHERE run_intent_id=$1::uuid
	`, conflicted.ID, weak.RunID).Scan(&conflictingRuns, &conflictingStarts); err != nil || conflictingRuns != 1 || conflictingStarts != 1 {
		t.Fatalf("conflict recovery duplicated state: %d/%d %v", conflictingRuns, conflictingStarts, err)
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

func (b blockedReconciliationInspector) InspectBound(ctx context.Context, _ runintent.Intent, _ []byte) (Inspection, error) {
	return b.Inspect(ctx, InspectRequest{})
}

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

// lostACKTransport is fault injection only. It sends exactly one real mTLS
// request and checks the create ACK before deliberately losing it. Runtime
// database assertions in the parent independently prove durable acceptance.
type lostACKTransport struct {
	upstream   http.RoundTripper
	calls      int
	dropped    bool
	wantStatus int
}

func (t *lostACKTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.calls++
	res, err := t.upstream.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if _, err := io.Copy(io.Discard, res.Body); err != nil {
		return nil, err
	}
	want := t.wantStatus
	if want == 0 {
		want = http.StatusCreated
	}
	if res.StatusCode != want {
		return nil, fmt.Errorf("Runtime returned HTTP %d, expected %d", res.StatusCode, want)
	}
	t.dropped = true
	return nil, io.ErrUnexpectedEOF
}

// Test-only subprocess uses the candidate adapter, not a hand-built payload.
func TestDispatchLostACKChild(t *testing.T) {
	if os.Getenv("ACP_DISPATCH_CHILD") != "1" {
		t.Skip("only the two-process ACK-loss test starts this helper")
	}
	dsn := os.Getenv("ACP_DATABASE_URL")
	tenantID := os.Getenv("ACP_DISPATCH_TENANT")
	intentID := os.Getenv("ACP_DISPATCH_INTENT")
	endpoint := os.Getenv("ACP_DISPATCH_ENDPOINT")
	if dsn == "" || tenantID == "" || intentID == "" || endpoint == "" {
		t.Fatal("dispatch subprocess requires PostgreSQL, scope and Runtime endpoint")
	}
	cert, err := tls.LoadX509KeyPair(os.Getenv("ACP_DISPATCH_CERT"), os.Getenv("ACP_DISPATCH_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(os.Getenv("ACP_DISPATCH_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid test trust root")
	}
	client, err := NewClient(endpoint, "spiffe://example.org/runtime", roots, cert)
	if err != nil {
		t.Fatal(err)
	}
	drop := &lostACKTransport{upstream: client.client.Transport}
	client.client.Transport = drop
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	repo := runpg.New(pool)
	adapter, err := NewDevelopmentAcceptor(client, repo)
	if err != nil {
		t.Fatal(err)
	}
	got, dispatchErr := DispatchOnce(ctx, repo, adapter, tenantID, intentID, "worker-1", 3*time.Minute)
	if !drop.dropped || !errors.Is(dispatchErr, ErrUnavailable) || got.Status != runintent.Unknown ||
		got.Version != 3 || drop.calls != 1 {
		t.Fatalf("subprocess must persist one committed-but-unacknowledged acceptance: %+v %v calls=%d dropped=%v", got, dispatchErr, drop.calls, drop.dropped)
	}
}

// Child Runtime and recovery processes never receive the disposable OAuth
// client secrets (nor inherited CI credentials). Only explicit runtime
// configuration is appended by the caller.
func goldenPathChildEnvironment() []string {
	var env []string
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "TMP", "TEMP", "USER", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR"} {
		if value, present := os.LookupEnv(key); present {
			env = append(env, key+"="+value)
		}
	}
	return env
}
