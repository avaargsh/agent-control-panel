package goalhttp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// This helper intentionally runs two separate release binaries rather than
// invoking the HTTP handler/CLI inside the test runner. All authorities are
// disposable except the read-only public GitHub source.
type liveGoalProcessInput struct {
	DSN string
	Schema string
	Issuer string
	IssuerCA string
	ResourceSecret string
	Bearer string
	Manifest issuegoal.Manifest
	Prepared []byte
	RequestDigest string
	Pool *pgxpool.Pool
}

func runLiveGoalProcessCLI(t *testing.T, ctx context.Context, in liveGoalProcessInput) {
	t.Helper()
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("ACP_REAL_GOAL_E2E") != "1" {
		t.Fatal("operator process acceptance requires the disposable GitHub CI live-provider job")
	}
	apiBin, cliBin := os.Getenv("ACP_REAL_GOAL_API_BIN"), os.Getenv("ACP_REAL_GOAL_CLI_BIN")
	if apiBin == "" || cliBin == "" {
		t.Fatal("operator acceptance requires independently built Goal API and CLI binaries")
	}
	for _, path := range []string{apiBin, cliBin} {
		if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			t.Fatal("operator acceptance binary unavailable or not executable")
		}
	}
	workspace := t.TempDir()
	write := func(name string, data []byte, mode os.FileMode) string {
		t.Helper()
		path := filepath.Join(workspace, name)
		if err := os.WriteFile(path, data, mode); err != nil {
			t.Fatalf("could not prepare disposable operator input %s: %v", name, err)
		}
		return path
	}
	// Self-signed, ephemeral, serverAuth-only TLS identity with the *numeric*
	// listener SAN. Both binaries must verify this certificate normally.
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(9801),
		Subject: pkix.Name{CommonName: "disposable ACP Goal API"},
		NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA: true,
		BasicConstraintsValid: true,
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil { t.Fatal(err) }
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil { t.Fatal(err) }
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	certFile := write("goal-server.pem", certPEM, 0600)
	keyFile := write("goal-server.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0600)
	CAFile := write("goal-server-ca.pem", certPEM, 0600)
	tokenFile := write("goal-token", []byte(in.Bearer+"\n"), 0600)
	secretFile := write("introspection-secret", []byte(in.ResourceSecret+"\n"), 0600)
	proposalFile := write("prepared-goal.json", in.Prepared, 0600)

	// Each live test already migrated and owns exactly this disposable schema.
	// The service process must connect to the same authority, not public.
	parsed, err := url.Parse(in.DSN)
	if err != nil { t.Fatal("disposable PostgreSQL DSN invalid") }
	query := parsed.Query()
	query.Set("search_path", in.Schema)
	parsed.RawQuery = query.Encode()
	processDSN := parsed.String()
	pgConfig, err := pgxpool.ParseConfig(processDSN)
	if err != nil || pgConfig.ConnConfig.RuntimeParams["search_path"] != in.Schema {
		t.Fatal("cannot bind independent Goal API process to the test PostgreSQL schema")
	}
	dsnFile := write("postgres-dsn", []byte(processDSN+"\n"), 0600)

	reserved, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	address := reserved.Addr().String()
	if err := reserved.Close(); err != nil { t.Fatal(err) }
	endpoint := "https://"+address+SubmitPath
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) { t.Fatal("disposable Goal API TLS CA unusable") }

	command := exec.CommandContext(ctx, apiBin)
	var apiStdout, apiStderr bytes.Buffer
	command.Stdout = &apiStdout
	command.Stderr = &apiStderr
	command.Env = append(os.Environ(),
		"ACP_GOAL_ENV=test",
		"ACP_GOAL_ALLOW_UNPROTECTED_TEST_BRANCH=true",
		"ACP_GOAL_LISTEN_ADDR="+address,
		"ACP_GOAL_TLS_CERT_FILE="+certFile,
		"ACP_GOAL_TLS_KEY_FILE="+keyFile,
		"ACP_GOAL_PG_DSN_FILE="+dsnFile,
		"ACP_GOAL_OAUTH_CA_FILE="+in.IssuerCA,
		"ACP_GOAL_OAUTH_ENDPOINT="+in.Issuer+"/protocol/openid-connect/token/introspect",
		"ACP_GOAL_OAUTH_ISSUER="+in.Issuer,
		"ACP_GOAL_OAUTH_AUDIENCE=acp-control-plane",
		"ACP_GOAL_OAUTH_CLIENT_ID=acp-control-plane",
		"ACP_GOAL_OAUTH_CLIENT_SECRET_FILE="+secretFile,
		"ACP_GOAL_TENANT_ID="+in.Manifest.Target.TenantID,
		"ACP_GOAL_PROJECT_ID="+in.Manifest.Target.ProjectID,
		"ACP_GOAL_AGENT_ID="+in.Manifest.Target.AgentID,
		"ACP_GOAL_RELEASE_ID="+in.Manifest.Target.ReleaseID,
		"ACP_GOAL_SESSION_ID="+in.Manifest.Target.SessionID,
		"ACP_GOAL_GITHUB_REPOSITORY=avaargsh/agent-control-panel",
		"ACP_GOAL_TARGET_BRANCH="+in.Manifest.TargetBranch,
		"ACP_GOAL_RULES_DIGEST="+in.Manifest.AcceptanceRulesDigest,
		"ACP_GOAL_MAX_TOKENS="+strconv.FormatInt(in.Manifest.Budget.MaxTokens,10),
		"ACP_GOAL_MAX_RUNTIME_SECONDS="+strconv.FormatInt(in.Manifest.Budget.MaxRuntimeSeconds,10),
		"ACP_GOAL_MAX_SANDBOX_SECONDS="+strconv.FormatInt(in.Manifest.Budget.MaxSandboxSeconds,10),
	)
	if err := command.Start(); err != nil { t.Fatalf("Goal API subprocess did not start: %v", err) }
	processExit := make(chan error, 1)
	go func() { processExit <- command.Wait() }()
	defer func() {
		if command.Process != nil {
			_ = command.Process.Signal(syscall.SIGTERM)
		}
		select {
		case err := <-processExit:
			if err != nil && ctx.Err() == nil { t.Errorf("Goal API process did not shut down cleanly: %v", err) }
		case <-time.After(5*time.Second):
			if command.Process != nil { _ = command.Process.Kill() }
			<-processExit
			t.Error("Goal API process did not terminate within shutdown window")
		}
	}()
	readyDeadline := time.NewTimer(10*time.Second)
	defer readyDeadline.Stop()
	poll := time.NewTicker(100*time.Millisecond)
	defer poll.Stop()
	ready := false
	for !ready {
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 300*time.Millisecond},
			"tcp", address, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots})
		if err == nil {
			_ = conn.Close()
			ready = true
			break
		}
		select {
		case finished := <-processExit:
			t.Fatalf("Goal API binary failed readiness before any request: %v", finished)
		case <-readyDeadline.C:
			t.Fatal("Goal API binary never passed authenticated loopback TLS readiness")
		case <-ctx.Done():
			t.Fatal("Goal API acceptance context expired before readiness")
		case <-poll.C:
		}
	}
	// The CLI is an *independent process* with no direct access to the test
	// pool or IdP internals, and must bind the reply to the prepared digest.
	runCLI := func() (map[string]any, error, string) {
		t.Helper()
		cliCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		cli := exec.CommandContext(cliCtx, cliBin, "submit", "--file", proposalFile,
			"--url", endpoint, "--token-file", tokenFile, "--ca-file", CAFile)
		var output, diagnostics bytes.Buffer
		cli.Stdout, cli.Stderr = &output, &diagnostics
		err := cli.Run()
		if strings.Contains(output.String(), in.Bearer) || strings.Contains(diagnostics.String(), in.Bearer) {
			t.Fatal("operator CLI leaked disposable OAuth bearer")
		}
		if err != nil { return nil, err, output.String() }
		var receipt map[string]any
		if json.Unmarshal(output.Bytes(), &receipt) != nil {
			t.Fatal("operator CLI returned a malformed JSON acceptance receipt")
		}
		return receipt, nil, output.String()
	}
	first, err, _ := runCLI()
	if err != nil || first["schema"] != AcceptanceVersion ||
		first["status"] != "PENDING" || first["created"] != true ||
		first["request_digest"] != in.RequestDigest {
		t.Fatalf("independent Goal API process + CLI did not create verified admission (CLI exit=%v)", err)
	}
	intentID, ok := first["run_intent_id"].(string)
	if !ok || intentID == "" { t.Fatal("independent CLI acceptance missing RunIntent ID") }
	var intents, outbox int64
	counts := func(want int64) {
		t.Helper()
		if err := in.Pool.QueryRow(ctx,
			"SELECT (SELECT count(*) FROM run_intents), (SELECT count(*) FROM outbox_events)").Scan(&intents, &outbox); err != nil {
			t.Fatal(err)
		}
		if intents != want || outbox != want {
			t.Fatalf("independent Goal API violated RunIntent/Outbox cardinality: got %d/%d want %d/%d", intents, outbox, want, want)
		}
	}
	counts(1)
	_, _, exactInput, err := issuegoal.DecodePrepared(in.Prepared)
	if err != nil { t.Fatal(err) }
	stored, err := runpg.New(in.Pool).GetExecutionInput(ctx, in.Manifest.Target.TenantID, intentID)
	if err != nil || !bytes.Equal(stored, exactInput) {
		t.Fatal("independent Goal API process did not durably store the exact authorized execution input")
	}
	// A real external *role revocation* must deny an explicit replay before
	// reaching GitHub and must never produce a second durable effect.
	if _, err := in.Pool.Exec(ctx, "UPDATE admission_memberships SET role='VIEWER' WHERE tenant_id=$1 AND project_id=$2",
		in.Manifest.Target.TenantID, in.Manifest.Target.ProjectID); err != nil {
		t.Fatal(err)
	}
	denied, deniedErr, deniedOut := runCLI()
	if deniedErr == nil || denied != nil || deniedOut != "" {
		t.Fatal("independent GoalSubmit CLI bypassed live database role revocation")
	}
	counts(1)
	t.Logf("independent ACP Goal API and CLI, pinned HTTPS cert, disposable Keycloak, live public GitHub Issue and PostgreSQL: PASS (RunIntent and Outbox only, no dispatch)")
	_ = fmt.Sprintf // keep explicit formatting support for future diagnostics
}
