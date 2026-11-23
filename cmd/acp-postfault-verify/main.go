// Command acp-postfault-verify enforces the non-production full Golden Path
// proof boundary. It is read-only and never issues a Guard Permit, executes
// a command, starts a Workflow or writes a RunIntent.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/postfault"
)

const maxBundleBytes = 128 << 10

const expectedBindingVersion = "acp.postfault-expected/v2"

// The expected binding must be read independently from the actual ACP/Runtime
// authority and fault injector, not copied from the submitted bundle.
type agentDHeadBinding struct {
	InspectCount   uint64 `json:"inspect_count"`
	JournalVersion uint64 `json:"journal_version"`
	Digest         string `json:"digest"`
}

type expectedBinding struct {
	Schema                 string                   `json:"schema"`
	Subject                postfault.Subject        `json:"subject"`
	FaultID                string                   `json:"fault_id"`
	FaultAt                time.Time                `json:"fault_at"`
	AgentDRef              *postfault.AgentDWaitRef `json:"agentd_ref"`
	AgentDGuardOperationID string                   `json:"agentd_guard_operation_id"`
	AgentDHead             *agentDHeadBinding       `json:"agentd_trusted_head"`
}

func matchesExpected(bundle postfault.Bundle, expected expectedBinding) error {
	if bundle.Subject != expected.Subject || bundle.Fault.ID != expected.FaultID ||
		!bundle.Fault.At.Equal(expected.FaultAt) {
		return errors.New("postfault bundle does not match independently accepted Run and injected fault")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		// Never print raw payloads, keys, bearer tokens or provider errors.
		fmt.Fprintln(os.Stderr, "POSTFAULT RECOVERY BLOCKED:", err)
		os.Exit(1)
	}
	fmt.Println("POSTFAULT RECOVERY VERIFIED: signed cross-authority continuity and original AgentD source chain satisfied")
}

func run(args []string) error {
	flags := flag.NewFlagSet("acp-postfault-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "", "externally signed recovery bundle")
	expectedPath := flags.String("expected", "", "independent ACP/Runtime/AgentD same-Run binding and trusted Inspect Head")
	trustDir := flags.String("trust-dir", "", "out-of-band trusted authority public keys")
	agentDEndpoint := flags.String("agentd-evidence-endpoint", "", "trusted HTTPS AgentD evidence endpoint")
	agentDClientCert := flags.String("agentd-client-cert", "", "per-tenant mTLS client certificate PEM")
	agentDClientKey := flags.String("agentd-client-key", "", "per-tenant mTLS client private key PEM (0600)")
	agentDServerCA := flags.String("agentd-server-ca", "", "trusted AgentD HTTPS server CA PEM")
	agentDServerName := flags.String("agentd-server-name", "", "expected AgentD HTTPS server certificate name")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 ||
		*bundlePath == "" || *expectedPath == "" || *trustDir == "" ||
		*agentDEndpoint == "" || *agentDClientCert == "" || *agentDClientKey == "" ||
		*agentDServerCA == "" || *agentDServerName == "" {
		return errors.New("requires bundle, expected binding, trust keys and AgentD mTLS endpoint/certificate/CA/server-name; absence is not a PASS")
	}
	data, err := privateBoundedInput(*bundlePath)
	if err != nil || len(data) > maxBundleBytes {
		return errors.New("no bounded external postfault bundle available")
	}
	var bundle postfault.Bundle
	if !postfault.StrictDecode(data, &bundle) {
		return errors.New("postfault bundle is invalid")
	}
	bindingBytes, err := privateBoundedInput(*expectedPath)
	if err != nil || len(bindingBytes) > 4096 {
		return errors.New("independent authoritative Run/fault binding unavailable")
	}
	var expected expectedBinding
	if !postfault.StrictDecode(bindingBytes, &expected) ||
		expected.Schema != expectedBindingVersion || expected.FaultID == "" || expected.FaultAt.IsZero() ||
		expected.AgentDRef == nil || expected.AgentDGuardOperationID == "" ||
		expected.AgentDHead == nil || expected.AgentDHead.InspectCount == 0 ||
		expected.AgentDHead.JournalVersion != expected.AgentDHead.InspectCount ||
		expected.AgentDHead.Digest == "" ||
		expected.AgentDRef.TenantID != expected.Subject.TenantID ||
		expected.AgentDRef.RunID != expected.Subject.RunID ||
		expected.AgentDGuardOperationID != expected.Subject.GuardOperationID {
		return errors.New("independent authoritative Run/fault/AgentD source binding is invalid")
	}
	if err := matchesExpected(bundle, expected); err != nil {
		return err
	}
	keys := make(map[string]ed25519.PublicKey, 4)
	for _, authority := range []string{"runtime", "sandbox", "agentd", "guard"} {
		path := filepath.Join(*trustDir, authority+".pub")
		publicKey, err := privateBoundedInput(path)
		if err != nil || len(publicKey) > 128 {
			return fmt.Errorf("missing independently configured %s trust key", authority)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(publicKey)))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid independently configured %s trust key", authority)
		}
		keys[authority] = ed25519.PublicKey(raw)
	}
	now := time.Now().UTC()
	if err := postfault.Verify(bundle, keys, now); err != nil {
		return err
	}
	credentials, err := newAgentDEvidenceTLSConfig(*agentDClientCert, *agentDClientKey,
		*agentDServerCA, *agentDServerName)
	if err != nil {
		return errors.New("per-tenant AgentD mTLS client configuration unavailable")
	}
	expectedWait := postfault.ExpectedAgentDWait{
		Ref: *expected.AgentDRef, GuardOperationID: expected.AgentDGuardOperationID,
	}
	trustedHead := postfault.TrustedAgentDInspectHead{
		InspectCount:   expected.AgentDHead.InspectCount,
		JournalVersion: expected.AgentDHead.JournalVersion,
		Digest:         expected.AgentDHead.Digest,
	}
	return verifyBoundAgentDEvidence(context.Background(), *agentDEndpoint,
		credentials, bundle, keys, expectedWait, trustedHead, now)
}

// verifyBoundAgentDEvidence preserves the original CLI base-URL contract,
// while enforcing the SAME mandatory mTLS identity boundary as the G05
// verifier library. Never fall back to the raw AgentDEvidenceClient transport.
func verifyBoundAgentDEvidence(ctx context.Context, endpoint string, credentials *tls.Config,
	bundle postfault.Bundle, keys map[string]ed25519.PublicKey,
	expected postfault.ExpectedAgentDWait, head postfault.TrustedAgentDInspectHead,
	now time.Time) error {
	uri, err := url.Parse(endpoint)
	if err != nil || uri.Scheme != "https" || uri.Host == "" || uri.Hostname() == "" ||
		uri.User != nil || uri.RawQuery != "" || uri.ForceQuery ||
		uri.Fragment != "" || uri.Opaque != "" || uri.RawPath != "" ||
		(uri.Path != "" && uri.Path != "/" && uri.Path != postfault.AgentDEvidenceReadPath) {
		return errors.New("untrusted AgentD evidence endpoint")
	}
	uri.Path = postfault.AgentDEvidenceReadPath
	return postfault.FetchAndVerifyAgentDEvidence(ctx, uri.String(), credentials,
		bundle, keys, expected, head, now)
}

func newAgentDEvidenceTLSConfig(certPath, keyPath, caPath, serverName string) (*tls.Config, error) {
	if strings.TrimSpace(serverName) == "" || strings.TrimSpace(serverName) != serverName {
		return nil, errors.New("invalid AgentD TLS server name")
	}
	certPEM, err := privateBoundedInput(certPath)
	if err != nil {
		return nil, errors.New("AgentD client certificate unavailable")
	}
	keyPEM, err := privateSecretInput(keyPath)
	if err != nil {
		return nil, errors.New("AgentD client private key unavailable")
	}
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, errors.New("AgentD mTLS client certificate/key invalid")
	}
	caPEM, err := privateBoundedInput(caPath)
	if err != nil {
		return nil, errors.New("AgentD server CA unavailable")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("AgentD server CA invalid")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS13,
		RootCAs:      roots,
		Certificates: []tls.Certificate{certificate},
		ServerName:   serverName,
	}, nil
}

func privateSecretInput(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Size() <= 0 || info.Size() > maxBundleBytes {
		return nil, errors.New("private key file unavailable or permissions too broad")
	}
	return privateBoundedInput(path)
}

func privateBoundedInput(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 ||
		info.Size() > maxBundleBytes {
		return nil, errors.New("required input file unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("required input file unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("required input file changed or is unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBundleBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxBundleBytes {
		return nil, errors.New("required input file invalid")
	}
	return raw, nil
}
