package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/authorityhttp"
	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

// TestAuthorityHTTPRejectsRuntimeRoleDrift exercises the real TLS1.3/mTLS
// listener and an independently authenticated PostgreSQL LOGIN. The service
// must stop exposing even negative authority lookup results as soon as its
// database role gains extra privileges, without a process restart or a new
// connection. The 403 positive control is a nonexistent, correctly scoped
// RunIntent; the publication endpoint is enabled without any existing
// RunIntent, so neither route can publish an effect or signed receipt.
func TestAuthorityHTTPRejectsRuntimeRoleDrift(t *testing.T) {
	dsn := os.Getenv("PGTEST_DSN")
	if dsn == "" {
		t.Skip("PGTEST_DSN is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	admin, databaseName := isolatedAuthorityRoleTestDatabase(t, ctx, dsn)
	defer admin.Close(context.Background())

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	schema, role := "acp_role_drift_"+suffix, "acp_drift_reader_"+suffix
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(context.Background(), "DROP SCHEMA "+schema+" CASCADE")
	poolConfig, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.Database = databaseName
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	migrator, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := runpg.Migrate(ctx, migrator); err != nil {
		migrator.Close()
		t.Fatal(err)
	}
	migrator.Close()

	passwordBytes := make([]byte, 24)
	if _, err := rand.Read(passwordBytes); err != nil {
		t.Fatal(err)
	}
	password := fmt.Sprintf("%x", passwordBytes)
	if _, err := admin.Exec(ctx, "CREATE ROLE "+role+" LOGIN PASSWORD '"+password+"'"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(context.Background(), "DROP OWNED BY "+role); err != nil {
			t.Errorf("drop role grants: %v", err)
		}
		if _, err := admin.Exec(context.Background(), "DROP ROLE "+role); err != nil {
			t.Errorf("drop test role: %v", err)
		}
	}()

	relations := []string{
		"run_intents", "admission_tenants", "admission_projects",
		"admission_principals", "admission_memberships",
		"admission_releases", "admission_sessions",
	}
	for _, name := range relations {
		if _, err := admin.Exec(ctx, "GRANT SELECT ON "+schema+"."+name+" TO "+role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := admin.Exec(ctx, "GRANT USAGE ON SCHEMA "+schema+" TO "+role); err != nil {
		t.Fatal(err)
	}

	roleURL, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	roleURL.User = url.UserPassword(role, password)
	roleURL.Path = "/" + databaseName
	q := roleURL.Query()
	q.Set("search_path", schema)
	roleURL.RawQuery = q.Encode()

	// Fully verified client-side TLS, with an ephemeral CA and a SPIFFE URI
	// on the client certificate. This is a real network handshake, not an
	// artificially populated http.Request.TLS field.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ACP drift test CA"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	pemCA := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	mint := func(template *x509.Certificate) ([]byte, []byte) {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert}),
			pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	}
	peer := "spiffe://tests.example/authority/reader"
	peerURI, err := url.Parse(peer)
	if err != nil {
		t.Fatal(err)
	}
	serverPEM, serverKey := mint(&x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	clientPEM, clientKey := mint(&x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: "workload"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		URIs: []*url.URL{peerURI}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	tmp := t.TempDir()
	certPath, keyPath, caPath := filepath.Join(tmp, "server.crt"), filepath.Join(tmp, "server.key"), filepath.Join(tmp, "client-ca.crt")
	for _, item := range []struct {
		path string
		data []byte
	}{
		{certPath, serverPEM}, {keyPath, serverKey}, {caPath, pemCA},
	} {
		if err := os.WriteFile(item.path, item.data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// Configure a real publisher as well as the plain Run Authority route.
	// With no accepted RunIntent, neither route can produce a publication.
	releaseDirectory := filepath.Join(tmp, "releases")
	if err := os.Mkdir(releaseDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	publicationKey := filepath.Join(tmp, "publication.seed")
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicationKey, seed, 0600); err != nil {
		t.Fatal(err)
	}
	clientCertificate, err := tls.X509KeyPair(clientPEM, clientKey)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pemCA) {
		t.Fatal("invalid test root CA")
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots,
			Certificates: []tls.Certificate{clientCertificate},
		}},
	}
	defer client.CloseIdleConnections()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(ctx)
	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- serve(serverCtx, config{
			dsn: roleURL.String(), cert: certPath, key: keyPath, ca: caPath,
			peer: peer, tenant: "tenant-drift", address: addr,
			releaseDirectory: releaseDirectory, publicationKey: publicationKey,
		})
	}()
	defer func() {
		stopServer()
		select {
		case err := <-serverErrors:
			if err != nil {
				t.Errorf("shutdown authority listener: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("authority listener did not stop")
		}
	}()

	id := "00000000-0000-4000-8000-000000000001"
	endpoint := "https://" + addr + "/internal/v1/run-authority/" + id +
		"?run_id=" + id + "&request_digest=sha256:" + strings.Repeat("a", 64)
	publicationEndpoint := strings.Replace(endpoint, "/internal/v1/run-authority/",
		"/internal/v1/decision-publication/", 1)
	getStatus := func(target string) (int, error) {
		resp, err := client.Get(target)
		if err != nil {
			return 0, err
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, nil
	}
	// Wait only for the listener to start; never mask unexpected HTTP codes.
	var status int
	for deadline := time.Now().Add(8 * time.Second); ; {
		status, err = getStatus(endpoint)
		if err == nil {
			break
		}
		select {
		case serverErr := <-serverErrors:
			t.Fatalf("authority listener exited: %v", serverErr)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("authority listener failed to start: %v", err)
		}
		time.Sleep(25 * time.Millisecond)
	}
	if status != http.StatusForbidden {
		t.Fatalf("expected valid mTLS and missing RunIntent denial: HTTP %d", status)
	}
	checkBothRoutes := func(phase string, want int) {
		t.Helper()
		for _, route := range []struct {
			name, endpoint string
		}{
			{"run-authority", endpoint},
			{"decision-publication", publicationEndpoint},
		} {
			got, err := getStatus(route.endpoint)
			if err != nil || got != want {
				t.Fatalf("%s %s: HTTP %d, want %d: %v", phase, route.name, got, want, err)
			}
		}
	}
	checkBothRoutes("before-grant", http.StatusForbidden)
	// On the same running process and reused TLS/DB connection pool, make
	// the role overprivileged *after* startup. The next validated request
	// must fail closed, rather than returning the old negative lookup result.
	if _, err := admin.Exec(ctx, "GRANT SELECT ON "+schema+".outbox_events TO "+role); err != nil {
		t.Fatal(err)
	}
	checkBothRoutes("after-grant", http.StatusServiceUnavailable)
	if _, err := admin.Exec(ctx, "REVOKE SELECT ON "+schema+".outbox_events FROM "+role); err != nil {
		t.Fatal(err)
	}
	checkBothRoutes("after-revoke", http.StatusForbidden)

	// Loss of a mandatory catalog SELECT privilege must also be detected
	// before reading the RunIntent: a missing RunIntent must not camouflage
	// a broken authority-service database identity as normal HTTP 403.
	if _, err := admin.Exec(ctx, "REVOKE SELECT ON "+schema+".admission_sessions FROM "+role); err != nil {
		t.Fatal(err)
	}
	checkBothRoutes("after-required-select-revocation", http.StatusServiceUnavailable)
	if _, err := admin.Exec(ctx, "GRANT SELECT ON "+schema+".admission_sessions TO "+role); err != nil {
		t.Fatal(err)
	}
	checkBothRoutes("after-required-select-restore", http.StatusForbidden)

	// NOINHERIT membership with SET ROLE potential is dangerous even if it
	// does not make the reader's present table SELECT result change. Detect
	// privilege escalation of the actual live LOGIN, not only table grants.
	if _, err := admin.Exec(ctx, "GRANT pg_read_all_data TO "+role+" WITH INHERIT FALSE, SET TRUE"); err != nil {
		t.Fatal(err)
	}
	checkBothRoutes("after-role-membership-grant", http.StatusServiceUnavailable)
	if _, err := admin.Exec(ctx, "REVOKE pg_read_all_data FROM "+role); err != nil {
		t.Fatal(err)
	}

	checkBothRoutes("after-role-membership-revoke", http.StatusForbidden)

	// P0 Issue #98: prove that a real ACCEPTED Run and publication can still
	// slip through when privileged DCL commits after preflight but before SQL.
	// This is a deterministic test-only barrier, not a production test hook.
	t.Run("accepted-run-TOCTOU", func(t *testing.T) {
		const tenant = "tenant-drift"
		const id = "11111111-1111-4111-8111-111111111111"
		const runID = "22222222-2222-4222-8222-222222222222"
		rawInput := []byte(`{"objective":"sre_incident_triage","service":"payments","signal":"latency"}`)
		conf := authorityhttp.ReleaseConfig{
			SchemaVersion: "acp.release-publication.v1",
			TenantID:      tenant, ProjectID: "project-drift",
			AgentID: "agent-drift", AgentReleaseID: "release-drift",
			PolicyRevision: "policy-drift", CatalogVersion: "1.0.0",
			IssuedAt:     time.Now().UTC().Add(-time.Minute).Truncate(time.Second),
			ExpiresAt:    time.Now().UTC().Add(time.Hour).Truncate(time.Second),
			Services:     []string{"payments"},
			Capabilities: []authorityhttp.CapabilityContract{},
		}
		configJSON, err := json.Marshal(conf)
		if err != nil {
			t.Fatal(err)
		}
		configSum := sha256.Sum256(configJSON)
		configDigest := fmt.Sprintf("sha256:%x", configSum)
		if err := os.WriteFile(filepath.Join(releaseDirectory, fmt.Sprintf("%x.json", configSum)), configJSON, 0600); err != nil {
			t.Fatal(err)
		}
		intent := runintent.Intent{
			ID: id, TenantID: tenant, PrincipalID: "principal-drift",
			ProjectID: "project-drift", AgentID: "agent-drift",
			ReleaseID: "release-drift", SessionID: "session-drift",
			IdempotencyKey: "accepted-fixture", Version: 1, Status: runintent.Accepted,
			RunID: runID, WorkflowID: "agent-run/v1/" + runID,
			PrincipalSnapshot: runintent.PrincipalSnapshot{
				Version: runintent.PrincipalSnapshotVersion, ProjectID: "project-drift",
				SubjectID: "subject-drift", ActorID: "subject-drift",
				PolicyRevision: "policy-drift", ConfigDigest: configDigest,
			},
		}
		intent.RequestDigest, err = runintent.ExecutionInputDigest(intent, rawInput)
		if err != nil {
			t.Fatal(err)
		}
		if err := intent.Validate(); err != nil {
			t.Fatalf("bad accepted fixture: %v", err)
		}
		for _, statement := range []string{
			"INSERT INTO " + schema + ".admission_tenants VALUES ('tenant-drift',true)",
			"INSERT INTO " + schema + ".admission_projects VALUES ('tenant-drift','project-drift',true,'policy-drift')",
			"INSERT INTO " + schema + ".admission_principals VALUES ('tenant-drift','https://issuer.test','alice','principal-drift','subject-drift',true)",
			"INSERT INTO " + schema + ".admission_memberships VALUES ('tenant-drift','project-drift','principal-drift','client-drift','RUNNER',true)",
			"INSERT INTO " + schema + ".admission_releases VALUES ('tenant-drift','project-drift','agent-drift','release-drift','" + configDigest + "',true)",
			"INSERT INTO " + schema + ".admission_sessions VALUES ('tenant-drift','project-drift','session-drift','agent-drift','release-drift','principal-drift',true)",
		} {
			if _, err := admin.Exec(ctx, statement); err != nil {
				t.Fatal(err)
			}
		}
		insert := "INSERT INTO " + schema + ".run_intents (" +
			"id,tenant_id,principal_id,project_id,agent_id,release_id,session_id," +
			"idempotency_key,request_digest,status,version,runtime_run_id,workflow_id," +
			"principal_snapshot_version,principal_subject_id,principal_actor_id," +
			"principal_policy_revision,principal_config_digest,execution_input," +
			"admission_issuer,admission_external_subject,admission_client_id) VALUES (" +
			"'11111111-1111-4111-8111-111111111111','tenant-drift','principal-drift'," +
			"'project-drift','agent-drift','release-drift','session-drift'," +
			"'accepted-fixture',$1,'ACCEPTED',1," +
			"'22222222-2222-4222-8222-222222222222','agent-run/v1/22222222-2222-4222-8222-222222222222'," +
			"'acp-principal/v1','subject-drift','subject-drift','policy-drift',$2,$3," +
			"'https://issuer.test','alice','client-drift')"
		if _, err := admin.Exec(ctx, insert, intent.RequestDigest, configDigest, rawInput); err != nil {
			t.Fatal(err)
		}
		readerConfig, err := pgxpool.ParseConfig(roleURL.String())
		if err != nil {
			t.Fatal(err)
		}
		reader, err := pgxpool.NewWithConfig(ctx, readerConfig)
		if err != nil {
			t.Fatal(err)
		}
		defer reader.Close()
		if err := verifyAuthorityDatabaseRole(ctx, reader); err != nil {
			t.Fatalf("reader positive control: %v", err)
		}
		repo := runpg.New(reader)
		ref := runpg.ExecutionAuthorityRef{TenantID: tenant, RunIntentID: id, RunID: runID, RequestDigest: intent.RequestDigest}
		current, err := repo.GetExecutionAuthority(ctx, ref)
		if err != nil || current.Ref != ref || current.PrincipalID != intent.PrincipalID {
			t.Fatalf("actual accepted Run absent: authority=%+v err=%v", current, err)
		}
		publisher, err := authorityhttp.NewPublisher(releaseDirectory, ed25519.NewKeyFromSeed(seed))
		if err != nil {
			t.Fatal(err)
		}
		defer publisher.Close()
		trust := x509.NewCertPool()
		if !trust.AppendCertsFromPEM(pemCA) {
			t.Fatal("bad test CA")
		}
		certificate, err := tls.X509KeyPair(serverPEM, serverKey)
		if err != nil {
			t.Fatal(err)
		}
		for _, publication := range []bool{false, true} {
			name := "run-authority"
			pathPrefix := "/internal/v1/run-authority/"
			if publication {
				name = "decision-publication"
				pathPrefix = "/internal/v1/decision-publication/"
			}
			t.Run(name, func(t *testing.T) {
				defer func() {
					if _, err := admin.Exec(context.Background(), "REVOKE SELECT ON "+schema+".outbox_events FROM "+role); err != nil {
						t.Errorf("revoke injected grant: %v", err)
					}
				}()
				var armed, triggered atomic.Bool
				guard := func(requestCtx context.Context) error {
					if err := verifyAuthorityDatabaseRole(requestCtx, reader); err != nil {
						return err
					}
					if armed.Load() && triggered.CompareAndSwap(false, true) {
						_, err := admin.Exec(requestCtx, "GRANT SELECT ON "+schema+".outbox_events TO "+role)
						return err
					}
					return nil
				}
				var handler http.Handler
				var handlerErr error
				if publication {
					handler, handlerErr = authorityhttp.NewGuardedPublicationHandler(repo, publisher, peer, tenant, guard)
				} else {
					handler, handlerErr = authorityhttp.NewGuardedHandler(repo, peer, tenant, guard)
				}
				if handlerErr != nil {
					t.Fatal(handlerErr)
				}
				server := httptest.NewUnstartedServer(handler)
				server.TLS = &tls.Config{
					MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
					ClientCAs: trust, Certificates: []tls.Certificate{certificate},
				}
				server.StartTLS()
				defer server.Close()
				url := server.URL + pathPrefix + id + "?run_id=" + runID + "&request_digest=" + intent.RequestDigest
				request := func() (int, []byte) {
					t.Helper()
					response, err := client.Get(url)
					if err != nil {
						t.Fatal(err)
					}
					defer response.Body.Close()
					body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
					if err != nil {
						t.Fatal(err)
					}
					return response.StatusCode, body
				}
				baselineStatus, baselineBody := request()
				if baselineStatus != http.StatusOK || len(baselineBody) < 30 {
					t.Fatalf("valid accepted Run %s baseline: HTTP %d body=%s", name, baselineStatus, baselineBody)
				}
				if publication {
					// Require a real cryptographically valid signed publication as
					// positive control; a generic HTTP 200 is insufficient evidence.
					var signed authorityhttp.SignedPublication
					if err := json.Unmarshal(baselineBody, &signed); err != nil {
						t.Fatalf("decode positive signed publication: %v", err)
					}
					publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
					if len(signed.Payload) == 0 || !ed25519.Verify(publicKey, signed.Payload, signed.Signature) {
						t.Fatal("baseline Decision Publication signature is not authentic")
					}
				}
				// Issue #98: even a missing/denied Run must not turn a committed
				// privilege escalation between preflight and catalog lookup
				// into a misleading clean HTTP 403. Use the same independently
				// authenticated PostgreSQL LOGIN and real mTLS transport.
				missingURL := strings.Replace(url, id, "33333333-3333-4333-8333-333333333333", 1)
				armed.Store(true)
				missingResponse, err := client.Get(missingURL)
				if err != nil {
					t.Fatal(err)
				}
				missingBody, err := io.ReadAll(io.LimitReader(missingResponse.Body, 1<<20))
				_ = missingResponse.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if !triggered.Load() {
					t.Fatal("denied-Run DCL race was never injected")
				}
				if missingResponse.StatusCode != http.StatusServiceUnavailable {
					t.Fatalf("P0 denied-Run TOCTOU %s: expected 503, got HTTP %d with %d bytes after privilege grant", name, missingResponse.StatusCode, len(missingBody))
				}
				if strings.Contains(string(missingBody), "\"signature\"") || strings.Contains(string(missingBody), "\"payload\"") {
					t.Fatal("denied-Run DCL race leaked signed publication fields")
				}
				if _, err := admin.Exec(ctx, "REVOKE SELECT ON "+schema+".outbox_events FROM "+role); err != nil {
					t.Fatal(err)
				}
				triggered.Store(false)
				armed.Store(false)
				recoveredStatus, _ := request()
				if recoveredStatus != http.StatusOK {
					t.Fatalf("authority reader did not recover after denied-Run DCL revocation: HTTP %d", recoveredStatus)
				}

				armed.Store(true)
				status, body := request()
				if !triggered.Load() {
					t.Fatal("DCL race never injected")
				}
				if status != http.StatusServiceUnavailable {
					t.Fatalf("P0 TOCTOU %s: expected 503, got HTTP %d with %d response bytes after committed GRANT between attestation and read", name, status, len(body))
				}
				if strings.Contains(string(body), "\"signature\"") || strings.Contains(string(body), "\"payload\"") {
					t.Fatal("denied DCL-race request leaked signed publication fields")
				}
			})
		}
	})
}
