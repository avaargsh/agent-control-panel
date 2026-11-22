package agentd

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
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type ephemeralClientCA struct {
	cert  *x509.Certificate
	key   ed25519.PrivateKey
	der   []byte
	roots *x509.CertPool
}

func newEphemeralClientCA(t *testing.T) ephemeralClientCA {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-only-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	return ephemeralClientCA{cert: parsed, key: private, der: der, roots: roots}
}

func (ca ephemeralClientCA) issue(t *testing.T, uri string) tls.Certificate {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	randomSerial, err := rand.Int(rand.Reader, big.NewInt(1<<60))
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: randomSerial, Subject: pkix.Name{CommonName: "untrusted-subject"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		URIs: []*url.URL{target}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca.cert, key.Public(), ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der, ca.der}, PrivateKey: key}
}

func newAuthenticTLSFixture(t *testing.T, db *pgxpool.Pool, sourceKey ed25519.PublicKey,
	lookup PinnedHeadLookup) (*httptest.Server, ephemeralClientCA) {
	t.Helper()
	ca := newEphemeralClientCA(t)
	server := httptest.NewUnstartedServer(NewReadOnlyEvidenceHandler(db, sourceKey, "sandbox.test", lookup))
	server.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  ca.roots,
		MinVersion: tls.VersionTLS13,
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, ca
}

func clientWithRunIdentity(t *testing.T, server *httptest.Server,
	ca ephemeralClientCA, tenant, run string) *http.Client {
	t.Helper()
	cert := ca.issue(t, "spiffe://sandbox.test/tenant/"+url.PathEscape(tenant)+
		"/run/"+url.PathEscape(run)+"/role/evidence-reader")
	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.Certificates = []tls.Certificate{cert}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 5 * time.Second}
}

func fetchOriginalEvidence(t *testing.T, client *http.Client, server *httptest.Server,
	ref Ref) (int, EvidenceReadResponse) {
	t.Helper()
	payload, err := json.Marshal(EvidenceReadRequest{Ref: ref})
	if err != nil {
		t.Fatal(err)
	}
	res, err := client.Post(server.URL+EvidenceReadPath, "application/json", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var exported EvidenceReadResponse
	if res.StatusCode == http.StatusOK {
		if err := json.NewDecoder(res.Body).Decode(&exported); err != nil {
			t.Fatal(err)
		}
		if res.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("signed evidence served cacheable")
		}
	}
	return res.StatusCode, exported
}

func TestEvidenceMTLSReadOnlyUnknownHoldRequiresPinnedHeadAndSameRun(t *testing.T) {
	db := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	seedAlreadyAuthorizedAttempt(t, db, ref)
	public, private := testSourceInspectKey(t)
	first, err := InspectAndJournal(context.Background(), db, ref, public, private)
	if err != nil {
		t.Fatal(err)
	}
	last, err := InspectAndJournal(context.Background(), db, ref, public, private)
	if err != nil {
		t.Fatal(err)
	}
	pinned := InspectHead{InspectCount: 2, JournalVersion: 2, Digest: last.Digest}
	lookup := func(_ context.Context, actual Ref) (InspectHead, error) {
		if actual != ref {
			return InspectHead{}, ErrMismatch
		}
		return pinned, nil
	}
	server, ca := newAuthenticTLSFixture(t, db, public, lookup)
	client := clientWithRunIdentity(t, server, ca, ref.TenantID, ref.RunID)
	status, response := fetchOriginalEvidence(t, client, server, ref)
	if status != 200 || response.Schema != EvidenceReadSchema || response.State != Unknown ||
		response.NextAction != Hold || response.Ref != ref ||
		response.CanRetry || response.Terminal != nil ||
		response.Head.InspectCount != 2 || response.Head.Digest != last.Digest ||
		len(response.Inspections) != 2 {
		t.Fatalf("genuine client did not read original signed UNKNOWN/HOLD journal: %d %+v", status, response)
	}
	for i, signed := range response.Inspections {
		raw, e := base64.StdEncoding.Strict().DecodeString(signed.PayloadB64)
		if e != nil {
			t.Fatal(e)
		}
		signature, e := base64.StdEncoding.Strict().DecodeString(signed.SignatureB64)
		if e != nil || !ed25519.Verify(public, append([]byte(InspectDomain), raw...), signature) {
			t.Fatalf("source event %d did not carry independently verifiable signed bytes", i)
		}
	}
	var count int
	if err := db.QueryRow(context.Background(), "SELECT count(*) FROM public.sandbox_agentd_inspect_events").Scan(&count); err != nil || count != 2 {
		t.Fatalf("read-only evidence exporter minted new Inspect event: %d %v", count, err)
	}
	if first.Digest == last.Digest {
		t.Fatal("source count did not advance")
	}
}

func TestEvidenceMTLSRejectsCrossTenantCrossRunAndMissingPeer(t *testing.T) {
	db := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	seedAlreadyAuthorizedAttempt(t, db, ref)
	public, private := testSourceInspectKey(t)
	ev, err := InspectAndJournal(context.Background(), db, ref, public, private)
	if err != nil {
		t.Fatal(err)
	}
	head := InspectHead{InspectCount: 1, JournalVersion: 1, Digest: ev.Digest}
	server, ca := newAuthenticTLSFixture(t, db, public, func(_ context.Context, _ Ref) (InspectHead, error) { return head, nil })
	for _, tc := range []struct{ name, tenant, run string }{
		{"wrong_tenant", "agentd-tenant-b", ref.RunID},
		{"wrong_run", ref.TenantID, "22222222-2222-4222-8222-222222222222"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := clientWithRunIdentity(t, server, ca, tc.tenant, tc.run)
			status, _ := fetchOriginalEvidence(t, c, server, ref)
			if status != http.StatusForbidden {
				t.Fatalf("cross-scope signed export leaked: HTTP %d", status)
			}
		})
	}
	// A valid TLS client CA is not enough: the URI SAN role and trust
	// domain are bound to this exact evidence-reader authorization scope.
	for _, identity := range []string{
		"spiffe://sandbox.test/tenant/" + ref.TenantID + "/run/" + ref.RunID + "/role/command-executor",
		"spiffe://foreign.test/tenant/" + ref.TenantID + "/run/" + ref.RunID + "/role/evidence-reader",
	} {
		cert := ca.issue(t, identity)
		tr := server.Client().Transport.(*http.Transport).Clone()
		tr.TLSClientConfig = tr.TLSClientConfig.Clone()
		tr.TLSClientConfig.Certificates = []tls.Certificate{cert}
		t.Cleanup(tr.CloseIdleConnections)
		client := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		status, _ := fetchOriginalEvidence(t, client, server, ref)
		if status != http.StatusForbidden {
			t.Fatalf("wrong mTLS role/trust-domain received source evidence: %s HTTP %d", identity, status)
		}
	}
	noCert := server.Client()
	raw, _ := json.Marshal(EvidenceReadRequest{Ref: ref})
	_, err = noCert.Post(server.URL+EvidenceReadPath, "application/json", bytes.NewReader(raw))
	if err == nil {
		t.Fatal("mTLS accepted a TLS peer without a client certificate")
	}
	// A forged HTTP header is irrelevant: authorization is TLS SAN, not
	// X-Tenant / X-Run or any other caller-provided identity.
	request, _ := http.NewRequest(http.MethodPost, server.URL+EvidenceReadPath, bytes.NewReader(raw))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Tenant-ID", ref.TenantID)
	request.Header.Set("X-Run-ID", ref.RunID)
	if _, err := noCert.Do(request); err == nil {
		t.Fatal("forged headers bypassed mTLS peer authentication")
	}
}

func TestEvidenceMTLSTerminalOnlyFromCommittedWaitAndFreshSourceInspect(t *testing.T) {
	db := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "0.2")
	seedAlreadyAuthorizedAttempt(t, db, ref)
	pub, private := testSourceInspectKey(t)
	if err := cmd.Wait(); err == nil {
		t.Fatal("expected original nonzero exit")
	}
	if _, err := RecordWaitOutcome(context.Background(), db, ref, cmd.ProcessState, private); err != nil {
		t.Fatal(err)
	}
	ev, err := InspectAndJournal(context.Background(), db, ref, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	head := InspectHead{InspectCount: 1, JournalVersion: 1, Digest: ev.Digest}
	server, ca := newAuthenticTLSFixture(t, db, pub, func(_ context.Context, _ Ref) (InspectHead, error) { return head, nil })
	client := clientWithRunIdentity(t, server, ca, ref.TenantID, ref.RunID)
	status, response := fetchOriginalEvidence(t, client, server, ref)
	if status != 200 || response.State != FailedConfirmed || response.NextAction != Hold ||
		response.CanRetry || response.Terminal == nil ||
		response.Terminal.Digest != ev.Result.ExitReceiptDigest ||
		response.Inspections[0].Digest != ev.Digest {
		t.Fatalf("mTLS reader accepted false terminal or dropped actual source Wait: %d %+v", status, response)
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(response.Terminal.PayloadB64)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(response.Terminal.SignatureB64)
	if err != nil || !ed25519.Verify(pub, append([]byte(TerminalDomain), raw...), sig) {
		t.Fatal("terminal raw bytes/signature not independently verifiable")
	}
}

func TestEvidenceMTLSRejectsStaleTrustedHeadWrongSignerAndUnknownAttempt(t *testing.T) {
	db := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	seedAlreadyAuthorizedAttempt(t, db, ref)
	pub, priv := testSourceInspectKey(t)
	first, err := InspectAndJournal(context.Background(), db, ref, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InspectAndJournal(context.Background(), db, ref, pub, priv); err != nil {
		t.Fatal(err)
	}
	stale := InspectHead{InspectCount: 1, JournalVersion: 1, Digest: first.Digest}
	server, ca := newAuthenticTLSFixture(t, db, pub, func(_ context.Context, _ Ref) (InspectHead, error) { return stale, nil })
	client := clientWithRunIdentity(t, server, ca, ref.TenantID, ref.RunID)
	status, _ := fetchOriginalEvidence(t, client, server, ref)
	if status == 200 {
		t.Fatal("stale pinned Head accepted a later source Inspect event")
	}
	foreign, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSigner, ca2 := newAuthenticTLSFixture(t, db, foreign, func(_ context.Context, _ Ref) (InspectHead, error) { return stale, nil })
	client2 := clientWithRunIdentity(t, wrongSigner, ca2, ref.TenantID, ref.RunID)
	status, _ = fetchOriginalEvidence(t, client2, wrongSigner, ref)
	if status == 200 {
		t.Fatal("wrong AgentD authority key returned verified source events")
	}
	bad := ref
	bad.AttemptID = "different-attempt"
	status, _ = fetchOriginalEvidence(t, client, server, bad)
	if status == 200 {
		t.Fatal("different original AttemptID accessed source evidence")
	}
}

func TestEvidenceMTLSFailClosedWithoutIndependentTrustedHead(t *testing.T) {
	db := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	seedAlreadyAuthorizedAttempt(t, db, ref)
	pub, private := testSourceInspectKey(t)
	if _, err := InspectAndJournal(context.Background(), db, ref, pub, private); err != nil {
		t.Fatal(err)
	}
	server, ca := newAuthenticTLSFixture(t, db, pub, nil)
	client := clientWithRunIdentity(t, server, ca, ref.TenantID, ref.RunID)
	status, _ := fetchOriginalEvidence(t, client, server, ref)
	if status == 200 {
		t.Fatal("export silently trusted the source DB as its independent Head pin")
	}
}

func TestEvidenceMTLSRejectsNonCanonicalAndOversizedRequests(t *testing.T) {
	db := testDatabase(t)
	cmd, ref := startOwnedTestProcess(t, "10")
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	seedAlreadyAuthorizedAttempt(t, db, ref)
	pub, private := testSourceInspectKey(t)
	ev, err := InspectAndJournal(context.Background(), db, ref, pub, private)
	if err != nil {
		t.Fatal(err)
	}
	server, ca := newAuthenticTLSFixture(t, db, pub, func(_ context.Context, _ Ref) (InspectHead, error) {
		return InspectHead{InspectCount: 1, JournalVersion: 1, Digest: ev.Digest}, nil
	})
	client := clientWithRunIdentity(t, server, ca, ref.TenantID, ref.RunID)
	payload, _ := json.Marshal(EvidenceReadRequest{Ref: ref})
	refJSON, _ := json.Marshal(ref)
	// A duplicate with the SAME valid value must be rejected deliberately,
	// not only because the later value happened to be invalid.
	validDuplicate := []byte(`{"ref":` + string(refJSON) + `,"ref":` + string(refJSON) + `}`)
	for _, raw := range [][]byte{
		validDuplicate,
		append(payload, []byte(" {}")...),
		[]byte(strings.Repeat("X", 9000)),
	} {
		res, err := client.Post(server.URL+EvidenceReadPath, "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
		if res.StatusCode == 200 {
			t.Fatalf("malformed or oversized evidence request succeeded: %d", res.StatusCode)
		}
	}
}
