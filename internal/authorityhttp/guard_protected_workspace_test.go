package authorityhttp

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
)

const protectedTestPeer = "spiffe://example.org/ns/guard/sa/engageguard"

type protectedRunReaderFixture struct {
	authority Snapshot
	input     []byte
	revoked   atomic.Bool
}

func (f *protectedRunReaderFixture) GetGuardRunAuthority(
	_ context.Context, tenant, run string,
) (runpg.ExecutionAuthority, []byte, error) {
	if f.revoked.Load() || tenant != f.authority.TenantID || run != f.authority.RunID {
		return runpg.ExecutionAuthority{}, nil, runpg.ErrCatalogDenied
	}
	a := f.authority
	return runpg.ExecutionAuthority{
		Ref: runpg.ExecutionAuthorityRef{
			TenantID: a.TenantID, RunIntentID: a.RunIntentID, RunID: a.RunID,
			RequestDigest: a.RequestDigest,
		},
		PrincipalID: a.PrincipalID, AgentID: a.AgentID, ReleaseID: a.AgentReleaseID,
		SessionID: a.SessionID,
		Snapshot: runintent.PrincipalSnapshot{
			Version:   runintent.PrincipalSnapshotVersion,
			ProjectID: a.ProjectID, SubjectID: a.SubjectID, ActorID: a.ActorID,
			PolicyRevision: a.PolicyRevision, ConfigDigest: a.ConfigDigest,
		},
	}, append([]byte(nil), f.input...), nil
}

func testProtectedTLS(t *testing.T, peer string) (tls.Certificate, tls.Certificate, *x509.CertPool) {
	t.Helper()
	now := time.Now().UTC()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Guard test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	makeCert := func(serial int64, eku x509.ExtKeyUsage, uri string) tls.Certificate {
		t.Helper()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "isolated"},
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
			BasicConstraintsValid: true,
		}
		if eku == x509.ExtKeyUsageServerAuth {
			leaf.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		}
		if uri != "" {
			u, err := url.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			leaf.URIs = []*url.URL{u}
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, caDER}, PrivateKey: key, Leaf: parsed}
	}
	return makeCert(2, x509.ExtKeyUsageServerAuth, ""),
		makeCert(3, x509.ExtKeyUsageClientAuth, peer), roots
}

func TestGuardProtectedWorkspaceHandlerUsesRealMTLSAndFreshRevocation(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	a, input, raw, q := protectedFixture(t, now)
	var release ProtectedWorkspaceRelease
	if err := json.Unmarshal(raw, &release); err != nil {
		t.Fatal(err)
	}
	release.ExpiresAt = now.Add(5 * time.Minute)
	raw, err := json.Marshal(release)
	if err != nil {
		t.Fatal(err)
	}
	a.ConfigDigest = "sha256:" + sha256Hex(raw)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, sha256Hex(raw)+".json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := NewPublisher(dir, signer)
	if err != nil {
		t.Fatal(err)
	}
	defer publisher.Close()
	reader := &protectedRunReaderFixture{authority: a, input: input}
	h, err := NewGuardProtectedWorkspaceHandler(reader, publisher, protectedTestPeer, a.TenantID)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, clientCert, roots := testProtectedTLS(t, protectedTestPeer)
	server := httptest.NewUnstartedServer(h)
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs: roots, Certificates: []tls.Certificate{serverCert},
	}
	server.StartTLS()
	defer server.Close()
	client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, RootCAs: roots,
			Certificates: []tls.Certificate{clientCert},
		},
	}}
	requestBody, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	send := func(body []byte) (int, []byte) {
		t.Helper()
		req, err := http.NewRequest(http.MethodPost, server.URL+GuardProtectedWorkspacePath, bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Forwarded-Client-Cert", "spiffe://attacker/ns/guard/sa/engageguard")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		if response.Header.Get("Cache-Control") != "no-store" {
			t.Fatal("protected observation cached")
		}
		body, err = io.ReadAll(io.LimitReader(response.Body, 4096))
		if err != nil {
			t.Fatal(err)
		}
		return response.StatusCode, body
	}
	status, wire := send(requestBody)
	if status != http.StatusOK {
		t.Fatalf("valid pinned mTLS Guard denied: %d %s", status, wire)
	}
	var receipt GuardProtectedWorkspaceReceipt
	if err := json.Unmarshal(bytes.TrimSpace(wire), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Status != "VERIFIED" || receipt.ConfigDigest != a.ConfigDigest ||
		receipt.WorkspaceID != q.WorkspaceID || receipt.PolicyRevision != q.PolicyRevision {
		t.Fatalf("reply not bound to current original Run: %+v", receipt)
	}
	// Different resource is never made valid by the previous successful response.
	forged := q
	forged.WorkspaceID = "workspace-other"
	changed, _ := json.Marshal(forged)
	if code, _ := send(changed); code != http.StatusForbidden {
		t.Fatalf("cross-workspace capability accepted: %d", code)
	}
	reader.revoked.Store(true)
	if code, _ := send(requestBody); code != http.StatusForbidden {
		t.Fatalf("revoked source yielded stale release: %d", code)
	}
	reader.revoked.Store(false)
	if err := os.WriteFile(filepath.Join(dir, sha256Hex(raw)+".json"), append(raw, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if code, _ := send(requestBody); code != http.StatusServiceUnavailable {
		t.Fatalf("tampered immutable release accepted: %d", code)
	}
	// Without a client certificate, the actual TLS server handshake must fail.
	unauthenticated := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS13, RootCAs: roots,
	}}}
	req, err := http.NewRequest(http.MethodPost, server.URL+GuardProtectedWorkspacePath, bytes.NewReader(requestBody))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Forwarded-Client-Cert", protectedTestPeer)
	resp, err := unauthenticated.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("unverified client certificate reached protected catalog")
	}
}

func TestGuardProtectedWorkspaceHandlerRejectsMissingAuthorityAndHeaderIdentity(t *testing.T) {
	if _, err := NewGuardProtectedWorkspaceHandler(nil, nil, protectedTestPeer, "tenant-1"); err == nil {
		t.Fatal("unconfigured protected workspace authority started")
	}
	// The Guard-only route must never trust a reverse proxy identity header.
	req := httptest.NewRequest(http.MethodPost, GuardProtectedWorkspacePath, nil)
	req.Header.Set("X-Forwarded-Client-Cert", protectedTestPeer)
	if verifiedPeer(req.TLS, protectedTestPeer) {
		t.Fatal("forwarded peer became trusted without mTLS")
	}
}
