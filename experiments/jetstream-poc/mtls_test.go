package jetstreampoc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// This digest is the multi-platform manifest for the official NATS 2.15.2
// image. The test never resolves a mutable tag at execution time.
const jetStreamMTLSImage = "nats:2.15.2@sha256:b6c40dcfe5ae9174dcafa9c43f800afb93b8b0ffcde02ac00efc6b66031d9a50"

func TestRealJetStreamMTLSAndTenantIsolation(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("Docker is required for the real NATS mTLS integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
	defer cancel()

	dir := t.TempDir()
	caPath, caKey, err := writeTestCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	serverCert, serverKey, err := writeTestLeaf(dir, "server", caPath, caKey, pkix.Name{CommonName: "localhost", Organization: []string{"ACP"}}, true)
	if err != nil {
		t.Fatal(err)
	}
	tenantACert, tenantAKey, err := writeTestLeaf(dir, "tenant-a", caPath, caKey, pkix.Name{CommonName: "tenant-a-receiver", Organization: []string{"ACP"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	tenantBCert, tenantBKey, err := writeTestLeaf(dir, "tenant-b", caPath, caKey, pkix.Name{CommonName: "tenant-b-receiver", Organization: []string{"ACP"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	unknownCert, unknownKey, err := writeTestLeaf(dir, "unknown", caPath, caKey, pkix.Name{CommonName: "unregistered-receiver", Organization: []string{"ACP"}}, false)
	if err != nil {
		t.Fatal(err)
	}

	config := fmt.Sprintf(`port: 4222
server_name: "acp-jetstream-mtls-poc"
jetstream {
  store_dir: "/data"
}
tls {
  cert_file: "/certs/%s"
  key_file: "/certs/%s"
  ca_file: "/certs/%s"
  verify_and_map: true
}
accounts {
  ACP_TENANT_A {
    jetstream: enabled
    users: [
      {
        user: %q
        permissions: {
          publish: { allow: ["tenant.a.>", "$JS.API.>", "$JS.ACK.>"] }
          subscribe: { allow: ["tenant.a.>", "_INBOX.>"] }
        }
      }
    ]
  }
  ACP_TENANT_B {
    jetstream: enabled
    users: [
      {
        user: %q
        permissions: {
          publish: { allow: ["tenant.b.>", "$JS.API.>", "$JS.ACK.>"] }
          subscribe: { allow: ["tenant.b.>", "_INBOX.>"] }
        }
      }
    ]
  }
}
`, filepath.Base(serverCert), filepath.Base(serverKey), filepath.Base(caPath),
		pkixNameRFC2253("tenant-a-receiver", "ACP"), pkixNameRFC2253("tenant-b-receiver", "ACP"))
	configPath := filepath.Join(dir, "nats.conf")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}

	port, err := unusedLoopbackPort()
	if err != nil {
		t.Fatal(err)
	}
	containerName := fmt.Sprintf("acp-js-mtls-%d", time.Now().UnixNano())
	volumeName := containerName + "-data"
	if output, err := exec.CommandContext(ctx, "docker", "volume", "create", volumeName).CombinedOutput(); err != nil {
		t.Fatalf("create disposable JetStream volume: %v: %s", err, output)
	}
	t.Cleanup(func() {
		cleanupCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		_ = exec.CommandContext(cleanupCtx, "docker", "rm", "-f", containerName).Run()
		_ = exec.CommandContext(cleanupCtx, "docker", "volume", "rm", "-f", volumeName).Run()
	})

	run := exec.CommandContext(ctx, "docker", "run", "--pull=always", "-d",
		"--name", containerName,
		"-p", fmt.Sprintf("127.0.0.1:%d:4222", port),
		"-v", dir+":/certs:ro",
		"-v", volumeName+":/data",
		jetStreamMTLSImage,
		"-c", "/certs/nats.conf")
	if output, err := run.CombinedOutput(); err != nil {
		t.Fatalf("start real mTLS JetStream server: %v: %s", err, output)
	}
	url := fmt.Sprintf("tls://127.0.0.1:%d", port)

	ncA := waitForMTLSConnection(t, ctx, url, caPath, tenantACert, tenantAKey)
	defer ncA.Close()
	ncB := connectMTLS(t, url, caPath, tenantBCert, tenantBKey)
	defer ncB.Close()

	// TLS without a client certificate must fail: server-side encryption alone
	// is not accepted as workload authentication.
	if anonymous, err := nats.Connect(url, nats.RootCAs(caPath), nats.Timeout(time.Second)); err == nil {
		anonymous.Close()
		t.Fatal("NATS accepted a TLS client without a client certificate")
	}
	// A CA-trusted certificate that is not mapped to an allowlisted NATS user
	// must fail authentication even though its TLS chain is valid.
	if unknown, err := nats.Connect(url, nats.RootCAs(caPath), nats.ClientCert(unknownCert, unknownKey), nats.Timeout(time.Second)); err == nil {
		unknown.Close()
		t.Fatal("NATS accepted an unregistered client-certificate identity")
	}
	// The TLS listener must not silently accept a plaintext NATS connection.
	if plaintext, err := nats.Connect(strings.Replace(url, "tls://", "nats://", 1), nats.Timeout(time.Second)); err == nil {
		plaintext.Close()
		t.Fatal("NATS accepted a plaintext connection on the mTLS listener")
	}

	jsA, err := jetstream.New(ncA)
	if err != nil {
		t.Fatalf("create tenant A JetStream client: %v", err)
	}
	jsB, err := jetstream.New(ncB)
	if err != nil {
		t.Fatalf("create tenant B JetStream client: %v", err)
	}
	ctxA, stopA := context.WithTimeout(ctx, 5*time.Second)
	defer stopA()
	ctxB, stopB := context.WithTimeout(ctx, 5*time.Second)
	defer stopB()

	streamA, err := jsA.CreateStream(ctxA, jetstream.StreamConfig{
		Name: "TENANT_A_EVENTS", Subjects: []string{"tenant.a.events"},
		Storage: jetstream.FileStorage, Retention: jetstream.LimitsPolicy,
	})
	if err != nil {
		t.Fatalf("tenant A could not create its own durable stream: %v", err)
	}
	streamB, err := jsB.CreateStream(ctxB, jetstream.StreamConfig{
		Name: "TENANT_B_EVENTS", Subjects: []string{"tenant.b.events"},
		Storage: jetstream.FileStorage, Retention: jetstream.LimitsPolicy,
	})
	if err != nil {
		t.Fatalf("tenant B could not create its own durable stream: %v", err)
	}
	infoA, err := streamA.Info(ctxA)
	if err != nil || len(infoA.Config.Subjects) != 1 || infoA.Config.Subjects[0] != "tenant.a.events" {
		t.Fatalf("tenant A stream is not bound to its subject: info=%+v err=%v", infoA, err)
	}
	infoB, err := streamB.Info(ctxB)
	if err != nil || len(infoB.Config.Subjects) != 1 || infoB.Config.Subjects[0] != "tenant.b.events" {
		t.Fatalf("tenant B stream is not bound to its subject: info=%+v err=%v", infoB, err)
	}

	if _, err := jsA.Publish(ctxA, "tenant.a.events", []byte("tenant-a")); err != nil {
		t.Fatalf("tenant A could not publish to its own stream: %v", err)
	}
	if _, err := jsB.Publish(ctxB, "tenant.b.events", []byte("tenant-b")); err != nil {
		t.Fatalf("tenant B could not publish to its own stream: %v", err)
	}
	if _, err := jsA.Stream(ctxA, "TENANT_B_EVENTS"); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("tenant A lookup for tenant B's stream: want stream not found, got %v", err)
	}
	if _, err := jsB.Stream(ctxB, "TENANT_A_EVENTS"); !errors.Is(err, jetstream.ErrStreamNotFound) {
		t.Fatalf("tenant B lookup for tenant A's stream: want stream not found, got %v", err)
	}
	t.Run("tenant A cannot access tenant B's subject", func(t *testing.T) {
		assertTenantSubjectDenied(t, ncA, "tenant.b.events")
	})
	t.Run("tenant B cannot access tenant A's subject", func(t *testing.T) {
		assertTenantSubjectDenied(t, ncB, "tenant.a.events")
	})
}

func assertTenantSubjectDenied(t *testing.T, nc *nats.Conn, subject string) {
	t.Helper()

	// Publish via Core NATS so an absent JetStream stream cannot satisfy the ACL assertion.
	publishErrors := make(chan error, 1)
	nc.SetErrorHandler(func(_ *nats.Conn, _ *nats.Subscription, err error) {
		select {
		case publishErrors <- err:
		default:
		}
	})
	if err := nc.Publish(subject, []byte("cross-tenant")); err != nil {
		t.Fatalf("send publish request to %q: %v", subject, err)
	}
	select {
	case err := <-publishErrors:
		if !errors.Is(err, nats.ErrPermissionViolation) || !strings.Contains(err.Error(), fmt.Sprintf("Permissions Violation for Publish to %q", subject)) {
			t.Fatalf("publish to %q: want server permissions violation, got %v", subject, err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("publish to %q: broker did not report a permissions violation", subject)
	}

	sub, err := nc.SubscribeSync(subject)
	if err != nil {
		t.Fatalf("send subscribe request to %q: %v", subject, err)
	}
	defer sub.Unsubscribe()
	if _, err := sub.NextMsg(2 * time.Second); !errors.Is(err, nats.ErrPermissionViolation) {
		t.Fatalf("subscribe to %q: want subscription permissions violation, got %v", subject, err)
	}
}

func connectMTLS(t *testing.T, url, caPath, certPath, keyPath string) *nats.Conn {
	t.Helper()
	nc, err := nats.Connect(url,
		nats.RootCAs(caPath),
		nats.ClientCert(certPath, keyPath),
		nats.PermissionErrOnSubscribe(true),
		nats.Timeout(2*time.Second),
		nats.Name("acp-jetstream-mtls-poc"))
	if err != nil {
		t.Fatalf("connect authenticated JetStream workload: %v", err)
	}
	return nc
}

func waitForMTLSConnection(t *testing.T, ctx context.Context, url, caPath, certPath, keyPath string) *nats.Conn {
	t.Helper()
	var last error
	for ctx.Err() == nil {
		nc, err := nats.Connect(url,
			nats.RootCAs(caPath),
			nats.ClientCert(certPath, keyPath),
			nats.PermissionErrOnSubscribe(true),
			nats.Timeout(time.Second),
			nats.Name("acp-jetstream-mtls-poc"))
		if err == nil {
			return nc
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("mTLS JetStream server did not become ready: %v", last)
	return nil
}

func writeTestCA(dir string) (string, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", nil, err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ACP JetStream POC CA"},
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return "", nil, err
	}
	path := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return "", nil, err
	}
	return path, key, nil
}

func writeTestLeaf(dir, name, caPath string, caKey *ecdsa.PrivateKey, subject pkix.Name, server bool) (string, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(int64(len(name)) + now.UnixNano()%1000000 + 1),
		Subject:      subject,
		NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.DNSNames = []string{"localhost"}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	} else {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return "", "", err
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return "", "", errors.New("invalid test CA PEM")
	}
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	certPath := filepath.Join(dir, name+"-cert.pem")
	keyPath := filepath.Join(dir, name+"-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0644); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

func pkixNameRFC2253(commonName, organization string) string {
	return fmt.Sprintf("CN=%s,O=%s", commonName, organization)
}

func unusedLoopbackPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port, nil
}
