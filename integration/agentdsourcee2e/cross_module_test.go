//go:build linux

package agentdsourcee2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/postfault"
	"github.com/avaargsh/agent-control-panel/services/sandbox-journal/agentd"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This integration deliberately uses BOTH real independently version-pinned
// Go modules. It does not authorize or dispatch production commands: a
// disposable PostgreSQL owner seeds a TEST-ONLY attempt for a real child PID.
func testSourceDB(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("AGENTD_CROSS_MODULE_TEST_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL 16 with AgentD source SHA pinned in go.work")
	}
	ctx := context.Background()
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	migrationRoot := os.Getenv("PINNED_AGENTD_MIGRATION_DIR")
	if migrationRoot == "" {
		t.Fatal("missing pinned AgentD source migration directory")
	}
	// go test executes with the package directory as cwd, not the repo
	// workspace root where the pinned independent source checkout lives.
	if !filepath.IsAbs(migrationRoot) {
		migrationRoot = filepath.Join("..", "..", migrationRoot)
	}
	for _, migration := range []string{"0013_agentd_attempt_terminal.sql", "0014_agentd_inspect_events.sql"} {
		raw, err := os.ReadFile(filepath.Join(migrationRoot, migration))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, string(raw)); err != nil {
			t.Fatalf("source migration %s: %v", migration, err)
		}
	}
	if _, err := db.Exec(ctx, "TRUNCATE public.sandbox_agentd_inspect_events,public.sandbox_agentd_terminal_receipts,public.sandbox_agentd_attempts"); err != nil {
		t.Fatal(err)
	}
	return db
}

func realOriginalAttempt(t *testing.T, db *pgxpool.Pool) (*exec.Cmd, agentd.Ref) {
	t.Helper()
	// The only process created is a disposable shell with an actual OS Wait.
	// No Guard Permit is minted or dispatched to a production provider.
	command := exec.Command("/bin/sh", "-c", "sleep 0.3; exit 7")
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if command.ProcessState == nil {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
	})
	boot, ticks, err := agentd.CaptureLinuxProcessIdentity(command.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	ref := agentd.Ref{
		TenantID: "tenant-a", RunID: "11111111-1111-4111-8111-111111111111",
		RuntimeAttemptID: "runtime-attempt-1", SandboxUID: "sandbox-uid-1",
		CommandID: "command-1", AttemptID: "command-attempt-1",
		ProviderCommandUID: "process-uid-1",
		RequestDigest:      "sha256:" + strings.Repeat("a", 64),
		GuardPermitID:      "permit-1", PermitEpoch: 8,
		ProcessPID: command.Process.Pid, ProcessStartTicks: ticks, HostBootID: boot,
	}
	_, err = db.Exec(context.Background(), `INSERT INTO public.sandbox_agentd_attempts
		(tenant_id,run_id,runtime_attempt_id,sandbox_uid,command_id,attempt_id,
		provider_command_uid,request_digest,guard_permit_id,permit_epoch,
		process_pid,process_start_ticks,host_boot_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		ref.TenantID, ref.RunID, ref.RuntimeAttemptID, ref.SandboxUID,
		ref.CommandID, ref.AttemptID, ref.ProviderCommandUID, ref.RequestDigest,
		ref.GuardPermitID, ref.PermitEpoch, ref.ProcessPID, ref.ProcessStartTicks, ref.HostBootID)
	if err != nil {
		t.Fatal(err)
	}
	return command, ref
}

func sourcePublicPrivate(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return public, private
}

type testCA struct {
	root  *x509.Certificate
	raw   []byte
	key   ed25519.PrivateKey
	roots *x509.CertPool
}

func realTestCA(t *testing.T) testCA {
	t.Helper()
	public, private := sourcePublicPrivate(t)
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "temporary-test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(raw)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	return testCA{root: root, raw: raw, key: private, roots: pool}
}

func (ca testCA) issue(t *testing.T, server bool, scope string) tls.Certificate {
	t.Helper()
	public, private := sourcePublicPrivate(t)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<60))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	leaf := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "not-authorization"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	if server {
		leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		uri, err := url.Parse(scope)
		if err != nil {
			t.Fatal(err)
		}
		leaf.URIs = []*url.URL{uri}
	}
	raw, err := x509.CreateCertificate(rand.Reader, leaf, ca.root, public, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{raw, ca.raw}, PrivateKey: private}
}

func realPostfaultBundle(t *testing.T, original agentd.Ref, before, after agentd.JournaledInspection,
	beforeObservation, faultAt, afterObservation, now time.Time,
	agentdSigner ed25519.PrivateKey) (postfault.Bundle, map[string]ed25519.PublicKey, postfault.ExpectedAgentDWait) {
	t.Helper()
	subject := postfault.Subject{
		TenantID: original.TenantID, RunID: original.RunID,
		SessionID: "session-1", WorkflowID: "agent-run/v1/" + original.RunID,
		GuardOperationID: "guard-operation-1",
	}
	bundle := postfault.Bundle{
		Schema:  postfault.BundleVersion,
		Subject: subject,
		Fault:   postfault.Fault{ID: "worker-sigkill-1", Kind: "worker_sigkill", At: faultAt},
	}
	keys := make(map[string]ed25519.PublicKey)
	privateKeys := make(map[string]ed25519.PrivateKey)
	for _, authority := range []string{"runtime", "sandbox", "agentd", "guard"} {
		if authority == "agentd" {
			keys[authority] = agentdSigner.Public().(ed25519.PublicKey)
			privateKeys[authority] = agentdSigner
		} else {
			public, private := sourcePublicPrivate(t)
			keys[authority], privateKeys[authority] = public, private
		}
	}
	for _, authority := range []string{"runtime", "sandbox", "agentd", "guard"} {
		for _, phase := range []string{"before_fault", "after_recovery"} {
			pre := phase == "before_fault"
			at := afterObservation
			if pre {
				at = beforeObservation
			}
			obs := postfault.Observation{
				Schema: postfault.ObservationVersion, Authority: authority,
				Phase: phase, ObservedAt: at, Subject: subject, FaultID: bundle.Fault.ID,
			}
			switch authority {
			case "runtime":
				obs.Runtime = &postfault.RuntimeObservation{
					Status: "RUNNING", HistoryDigest: "sha256:" + strings.Repeat("a", 64),
					CheckpointDigest: "sha256:" + strings.Repeat("b", 64),
					BreakerState:     "CLOSED", BreakerEpoch: 4, BreakerVersion: 7,
					Recovered: !pre,
				}
			case "sandbox":
				obs.Sandbox = &postfault.SandboxObservation{
					LeaseID: "lease-1", SandboxUID: original.SandboxUID,
					WorkspaceID: "workspace-1", Generation: 3,
					RootPath: "/workspace/agent", SentinelPath: ".acp-continuity",
					SentinelDigest:   "sha256:" + strings.Repeat("c", 64),
					ReadbackVerified: true, ProviderState: "ACTIVE",
				}
			case "agentd":
				event := after
				if pre {
					event = before
				}
				obs.Command = &postfault.CommandObservation{
					CommandID: original.CommandID, AttemptID: original.AttemptID,
					ProviderCommandUID: original.ProviderCommandUID,
					JournalVersion:     event.Event.JournalVersion, State: event.Event.State,
					DispatchCount: 1, InspectCount: event.Event.InspectCount,
					Source: "agentd.inspect", ExitReceiptDigest: event.Event.ExitReceiptDigest,
				}
			case "guard":
				obs.Guard = &postfault.GuardObservation{
					PermitID: original.GuardPermitID, PermitEpoch: original.PermitEpoch,
					Status: "VALID", PermitExpiresAt: now.Add(10 * time.Minute),
					ActionDigest: "sha256:" + strings.Repeat("d", 64),
					Revalidated:  !pre,
				}
			}
			raw, err := json.Marshal(obs)
			if err != nil {
				t.Fatal(err)
			}
			signature := ed25519.Sign(privateKeys[authority], append([]byte(postfault.SignatureDomain), raw...))
			bundle.Receipts = append(bundle.Receipts, postfault.Receipt{
				Authority: authority, Phase: phase,
				PayloadB64:   base64.StdEncoding.EncodeToString(raw),
				SignatureB64: base64.StdEncoding.EncodeToString(signature),
			})
		}
	}
	expected := postfault.ExpectedAgentDWait{
		GuardOperationID: subject.GuardOperationID,
		Ref: postfault.AgentDWaitRef{
			TenantID: original.TenantID, RunID: original.RunID,
			RuntimeAttemptID: original.RuntimeAttemptID, SandboxUID: original.SandboxUID,
			CommandID: original.CommandID, AttemptID: original.AttemptID,
			ProviderCommandUID: original.ProviderCommandUID, RequestDigest: original.RequestDigest,
			GuardPermitID: original.GuardPermitID, PermitEpoch: original.PermitEpoch,
			ProcessPID: original.ProcessPID, ProcessStartTicks: original.ProcessStartTicks,
			HostBootID: original.HostBootID,
		},
	}
	return bundle, keys, expected
}

func TestAgentDRealCrossModuleOriginalWaitInspectAndMTLS(t *testing.T) {
	ctx := context.Background()
	db := testSourceDB(t)
	command, original := realOriginalAttempt(t, db)
	sourcePub, sourcePrivate := sourcePublicPrivate(t)

	before, err := agentd.InspectAndJournal(ctx, db, original, sourcePub, sourcePrivate)
	if err != nil || before.Result.State != agentd.Unknown ||
		before.Result.ExitReceiptDigest != "" || before.Result.CanRetry {
		t.Fatalf("initial source Inspect must remain UNKNOWN/HOLD: %+v %v", before, err)
	}
	beforeObservation := time.Now().UTC()
	faultAt := time.Now().UTC()

	// Pinned Head is deliberately maintained OUTSIDE the candidate source
	// database/HTTP response. It is still a TEST callback, not a deployed
	// ACP Head authority.
	pinned := agentd.InspectHead{
		InspectCount:   before.Event.InspectCount,
		JournalVersion: before.Event.JournalVersion,
		Digest:         before.Digest,
	}
	readHead := func(_ context.Context, ref agentd.Ref) (agentd.InspectHead, error) {
		if ref != original {
			return agentd.InspectHead{}, errors.New("foreign original source attempt")
		}
		return pinned, nil
	}
	ca := realTestCA(t)
	srv := httptest.NewUnstartedServer(agentd.NewReadOnlyEvidenceHandler(
		db, sourcePub, "sandbox.test", readHead))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{ca.issue(t, true, "")},
		ClientAuth:   tls.RequireAndVerifyClientCert, ClientCAs: ca.roots,
		MinVersion: tls.VersionTLS13,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	clientScope := "spiffe://sandbox.test/tenant/" + original.TenantID +
		"/run/" + original.RunID + "/role/evidence-reader"
	credentials := &tls.Config{
		RootCAs:      ca.roots,
		Certificates: []tls.Certificate{ca.issue(t, false, clientScope)},
		MinVersion:   tls.VersionTLS13,
	}
	httpClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: credentials.Clone(), Proxy: nil},
		Timeout:   5 * time.Second,
	}
	sourceRequest, err := json.Marshal(agentd.EvidenceReadRequest{Ref: original})
	if err != nil {
		t.Fatal(err)
	}
	readUnknown := func() agentd.EvidenceReadResponse {
		t.Helper()
		response, err := httpClient.Post(srv.URL+agentd.EvidenceReadPath,
			"application/json", bytes.NewReader(sourceRequest))
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("original source evidence read: %d", response.StatusCode)
		}
		var result agentd.EvidenceReadResponse
		if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	unknown := readUnknown()
	if unknown.State != agentd.Unknown || unknown.NextAction != agentd.Hold ||
		unknown.Terminal != nil || unknown.CanRetry || len(unknown.Inspections) != 1 {
		t.Fatalf("source mTLS falsely declared UNKNOWN command completed: %+v", unknown)
	}

	if err := command.Wait(); err == nil || command.ProcessState.ExitCode() != 7 {
		t.Fatalf("must use actual OS Wait, exit 7: %v", err)
	}
	if _, err := agentd.RecordWaitOutcome(ctx, db, original, command.ProcessState, sourcePrivate); err != nil {
		t.Fatalf("actual OS Wait was not committed: %v", err)
	}
	// Even with a terminal OS Wait already committed, the source is still
	// UNKNOWN until a FRESH durable inspection is journaled.
	stillUnknown := readUnknown()
	if stillUnknown.State != agentd.Unknown || stillUnknown.Terminal != nil ||
		stillUnknown.CanRetry || len(stillUnknown.Inspections) != 1 {
		t.Fatalf("Wait alone fabricated postfault source Inspect: %+v", stillUnknown)
	}
	after, err := agentd.InspectAndJournal(ctx, db, original, sourcePub, sourcePrivate)
	if err != nil || after.Result.State != agentd.FailedConfirmed ||
		after.Event.PreviousDigest != before.Digest ||
		after.Event.InspectCount != before.Event.InspectCount+1 ||
		after.Result.CanRetry || after.Result.CanDeclareReleased {
		t.Fatalf("source failed to durably reconcile original OS Wait: %+v %v", after, err)
	}
	pinned = agentd.InspectHead{
		InspectCount:   after.Event.InspectCount,
		JournalVersion: after.Event.JournalVersion, Digest: after.Digest,
	}
	afterObservation := time.Now().UTC()
	now := afterObservation.Add(time.Second)
	bundle, keys, expected := realPostfaultBundle(t, original, before, after,
		beforeObservation, faultAt, afterObservation, now, sourcePrivate)
	if err := postfault.Verify(bundle, keys, now); err != nil {
		t.Fatalf("precondition eight independently signed G05 reports: %v", err)
	}
	// This invokes REAL AgentD PostgreSQL query and mTLS Handler, not a
	// contract mock. ACP independently validates every signed source record.
	if err := postfault.FetchAndVerifyAgentDEvidence(ctx,
		srv.URL+agentd.EvidenceReadPath, credentials,
		bundle, keys, expected,
		postfault.TrustedAgentDInspectHead{
			InspectCount:   pinned.InspectCount,
			JournalVersion: pinned.JournalVersion, Digest: pinned.Digest,
		}, now); err != nil {
		t.Fatalf("actual source PostgreSQL -> real AgentD mTLS -> ACP G05 failed: %v", err)
	}
	var count int
	if err := db.QueryRow(ctx,
		"SELECT count(*) FROM public.sandbox_agentd_inspect_events").Scan(&count); err != nil || count != 2 {
		t.Fatalf("HTTP export created new Inspect or lost original: %d %v", count, err)
	}
	// The authenticated endpoint MUST NOT leak a 'complete' proof when
	// the independent trusted Head is behind a newer source Inspector event.
	stale := pinned
	pinned = agentd.InspectHead{
		InspectCount:   before.Event.InspectCount,
		JournalVersion: before.Event.JournalVersion, Digest: before.Digest,
	}
	if err := postfault.FetchAndVerifyAgentDEvidence(ctx, srv.URL+agentd.EvidenceReadPath,
		credentials, bundle, keys, expected,
		postfault.TrustedAgentDInspectHead{
			InspectCount: stale.InspectCount, JournalVersion: stale.JournalVersion,
			Digest: stale.Digest,
		}, now); err == nil {
		t.Fatal("stale source Head or truncated real Inspector history bypassed fail-closed")
	}
	foreign := expected
	foreign.Ref.AttemptID = "other-original-attempt"
	if err := postfault.FetchAndVerifyAgentDEvidence(ctx, srv.URL+agentd.EvidenceReadPath,
		credentials, bundle, keys, foreign,
		postfault.TrustedAgentDInspectHead{
			InspectCount: stale.InspectCount, JournalVersion: stale.JournalVersion,
			Digest: stale.Digest,
		}, now); err == nil {
		t.Fatal("foreign original AttemptID accessed signed source evidence")
	}
	t.Log("SOURCE_REAL_OS_WAIT_PG16_MTLS_ACP_G05_CONSISTENT; GUARD_ISSUER_PEP_AND_PHYSICAL_RELEASE_NOT_TESTED")
}
