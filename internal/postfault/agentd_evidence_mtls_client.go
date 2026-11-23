package postfault

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/url"
	"time"
)

// validEvidenceTLSIdentity ensures a single, explicitly provided evidence
// reader certificate is bound to the original Tenant and Run. The identity
// is checked before any HTTP request; the source independently authenticates
// this client certificate and enforces tenant-scoped read-only database RLS.
func validEvidenceTLSIdentity(cfg *tls.Config, expected AgentDWaitRef) bool {
	if cfg == nil || cfg.InsecureSkipVerify || cfg.RootCAs == nil ||
		len(cfg.Certificates) != 1 || len(cfg.Certificates[0].Certificate) == 0 ||
		cfg.Certificates[0].PrivateKey == nil || cfg.MinVersion < tls.VersionTLS13 {
		return false
	}
	leaf, err := x509.ParseCertificate(cfg.Certificates[0].Certificate[0])
	if err != nil || len(leaf.URIs) != 1 {
		return false
	}
	identity := leaf.URIs[0]
	if identity.Scheme != "spiffe" || identity.Host == "" ||
		identity.User != nil || identity.RawQuery != "" || identity.ForceQuery ||
		identity.Fragment != "" || identity.Opaque != "" || identity.RawPath != "" ||
		identity.Port() != "" || identity.Host != identity.Hostname() {
		return false
	}
	wantPath := "/tenant/" + url.PathEscape(expected.TenantID) +
		"/run/" + url.PathEscape(expected.RunID) + "/role/evidence-reader"
	return identity.EscapedPath() == wantPath &&
		identity.String() == "spiffe://"+identity.Host+wantPath
}

// FetchAndVerifyAgentDEvidence is an mTLS identity/transport adapter for the
// SINGLE canonical AgentDEvidenceClient.Read/Verify implementation.
//
// The out-of-band endpoint, certificate/CA, original Run/Attempt/Guard tuple,
// independent source verification keys and pinned Head must be supplied by the
// trusted control plane, never by a model or the evidence response itself.
// Do not add a second JSON wire parser or separate signature validation here.
func FetchAndVerifyAgentDEvidence(ctx context.Context, endpoint string, credentials *tls.Config,
	b Bundle, keys map[string]ed25519.PublicKey, expected ExpectedAgentDWait,
	head TrustedAgentDInspectHead, now time.Time) error {
	uri, err := url.Parse(endpoint)
	if err != nil || uri.Scheme != "https" || uri.Host == "" ||
		uri.User != nil || uri.RawQuery != "" || uri.Fragment != "" ||
		uri.Opaque != "" || uri.RawPath != "" ||
		uri.Path != AgentDEvidenceReadPath ||
		!validEvidenceTLSIdentity(credentials, expected.Ref) ||
		!validAgentDEvidenceRef(expected.Ref) ||
		!validDigest(head.Digest) || head.InspectCount == 0 ||
		head.JournalVersion != head.InspectCount ||
		len(keys["agentd"]) != ed25519.PublicKeySize ||
		b.Subject.TenantID != expected.Ref.TenantID ||
		b.Subject.RunID != expected.Ref.RunID ||
		b.Subject.GuardOperationID != expected.GuardOperationID {
		return failure("untrusted AgentD mTLS target or independent Run/Head binding")
	}
	// Bind the server's leaf identity to the same out-of-band trust domain
	// as the exact Tenant/Run evidence-reader certificate. A certificate
	// signed by the configured CA and valid for the HTTPS DNS name is NOT
	// sufficient if it belongs to a different workload in that domain.
	// This candidate SPIFFE service role must be provisioned independently
	// by the source owner; it is never taken from an HTTP response or model.
	readerCert, err := x509.ParseCertificate(credentials.Certificates[0].Certificate[0])
	if err != nil || len(readerCert.URIs) != 1 {
		return failure("invalid AgentD evidence-reader identity")
	}
	wantServer := "spiffe://" + readerCert.URIs[0].Host + "/role/agentd-evidence-server"
	tlsCredentials := credentials.Clone()
	priorVerify := tlsCredentials.VerifyConnection
	tlsCredentials.VerifyConnection = func(state tls.ConnectionState) error {
		if priorVerify != nil {
			if err := priorVerify(state); err != nil {
				return err
			}
		}
		// Go's ordinary certificate-chain/DNS/EKU checks still run because
		// InsecureSkipVerify is prohibited. This additional URI-SAN match
		// denies a differently scoped but CA-trusted TLS server BEFORE an
		// original Run/Guard/Attempt request can reach its HTTP handler.
		if state.Version < tls.VersionTLS13 ||
			len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 ||
			len(state.PeerCertificates[0].URIs) != 1 ||
			state.PeerCertificates[0].URIs[0] == nil ||
			state.PeerCertificates[0].URIs[0].String() != wantServer {
			return failure("untrusted AgentD evidence server workload identity")
		}
		return nil
	}
	transport := &http.Transport{
		TLSClientConfig:     tlsCredentials,
		Proxy:               nil,
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: 5 * time.Second,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	// The canonical reader owns strict source JSON/schema/record validation,
	// bounded bytes, UNKNOWN/HOLD and same-Run signed journal/Wait verification.
	// This adapter cannot sign, retry, dispatch, release or issue a Permit.
	canonical := AgentDEvidenceClient{
		Endpoint:   uri.Scheme + "://" + uri.Host,
		HTTPClient: client,
	}
	return canonical.Verify(ctx, b, keys, expected, head, now)
}
