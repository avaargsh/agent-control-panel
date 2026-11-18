package runtimeinspect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5"
)

// Start a real separately compiled Runtime authority binary against the
// already accepted Runtime database, with a dedicated read-only LOGIN. The
// Decision verifier receives no Runtime or ACP database credential.
func startLiveRuntimeDecisionAuthority(t *testing.T, dsn, dir, clientCA string, ref runpg.ExecutionAuthorityRef) (string, []byte) {
	t.Helper()
	binary := os.Getenv("ACP_RUNTIME_DECISION_AUTHORITY_BIN")
	if binary == "" {
		t.Fatal("missing Runtime Decision authority executable")
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal("Runtime isolated authority provisioning failed")
	}
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		t.Fatal(err)
	}
	password := hex.EncodeToString(random[:])
	role := "runtime_decision_read_" + password[:16]
	quoted := pgx.Identifier{role}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE ROLE "+quoted+" LOGIN PASSWORD '"+password+"'"); err != nil {
		t.Fatal("Runtime isolated LOGIN provisioning failed")
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(context.Background(), "DROP OWNED BY "+quoted); err != nil {
			t.Error("Runtime authority role grant cleanup failed")
		}
		if _, err := admin.Exec(context.Background(), "DROP ROLE "+quoted); err != nil {
			t.Error("Runtime authority LOGIN cleanup failed")
		}
	})
	for _, grant := range []string{
		"GRANT USAGE ON SCHEMA public TO " + quoted,
		"GRANT SELECT ON runs,runtime_run_principal_snapshots,runtime_run_attempts,runtime_decision_turns,runtime_decision_checkpoints,runtime_circuit_breakers TO " + quoted,
	} {
		if _, err := admin.Exec(ctx, grant); err != nil {
			t.Fatal("Runtime isolated LOGIN grant failed")
		}
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Host == "" {
		t.Fatal("isolated Runtime PostgreSQL URL required")
	}
	u.User = url.UserPassword(role, password)
	readConn, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal("Runtime isolated read-only LOGIN unavailable")
	}
	if _, err := readConn.Exec(ctx, "UPDATE runs SET updated_at=clock_timestamp() WHERE false"); err == nil {
		_ = readConn.Close(ctx)
		t.Fatal("Runtime authority read-only role obtained write permission")
	}
	_ = readConn.Close(ctx)
	_, cert, _ := testSPIFFECertificatesFor(t, "spiffe://example.org/runtime-decision", "spiffe://example.org/unused-client")
	certFile, keyFile := filepath.Join(dir, "runtime-decision.pem"), filepath.Join(dir, "runtime-decision.key")
	writeProcessCertificate(t, certFile, keyFile, cert)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	_ = listener.Close()
	proc := exec.Command(binary)
	proc.Env = append(goldenPathChildEnvironment(),
		"RUNTIME_DECISION_DATABASE_URL="+u.String(), "RUNTIME_DECISION_TLS_CERT="+certFile,
		"RUNTIME_DECISION_TLS_KEY="+keyFile, "RUNTIME_DECISION_CLIENT_CA="+clientCA,
		"RUNTIME_DECISION_TENANT="+ref.TenantID, "RUNTIME_DECISION_PEER_SPIFFE_ID=spiffe://example.org/decision",
		"RUNTIME_DECISION_LISTEN_ADDR="+addr)
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Process.Kill(); _ = proc.Wait() })
	return "https://" + addr, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[1]})
}
