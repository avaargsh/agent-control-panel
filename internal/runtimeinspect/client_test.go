package runtimeinspect

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
)

const (
	testTenant = "tenant-1"
	testIntent = "00000000-0000-4000-8000-000000000111"
	testDigest = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testRunID = "00000000-0000-4000-8000-000000000222"
)

func TestInspectResponseBindsRuntimeIdentityAndScope(t *testing.T) {
	request := InspectRequest{TenantID: testTenant, RunIntentID: testIntent, RequestDigest: testDigest}
	good := `{"status":"FOUND","tenant_id":"tenant-1","run_intent_id":"00000000-0000-4000-8000-000000000111","request_digest":"` + testDigest + `","run_id":"` + testRunID + `","workflow_id":"agent-run/v1/` + testRunID + `","created":false}`
	result, err := parseInspectResponse([]byte(good), request)
	if err != nil || result.Status != Found || result.RunID != testRunID || result.WorkflowID != "agent-run/v1/"+testRunID {
		t.Fatalf("valid Runtime identity rejected: %+v, %v", result, err)
	}
}

func TestInspectOnlyReportsUncertainAbsence(t *testing.T) {
	request := InspectRequest{TenantID: testTenant, RunIntentID: testIntent, RequestDigest: testDigest}
	result, err := parseInspectResponse([]byte(`{"status":"ABSENT_UNCERTAIN"}`), request)
	if err != nil || result.Status != AbsentUncertain || result.RunID != "" {
		t.Fatalf("uncertain absence promoted or rejected: %+v, %v", result, err)
	}
	for _, payload := range []string{
		`{"status":"NOT_FOUND_FINAL"}`,
		`{"status":"NOT_FOUND"}`,
		`{"status":"ABSENT_UNCERTAIN","run_id":"forged"}`,
		`{"status":"ABSENT_UNCERTAIN","status":"FOUND"}`,
		`{"status":"ABSENT_UNCERTAIN","created":false}`,
	} {
		t.Run(payload, func(t *testing.T) {
			if _, err := parseInspectResponse([]byte(payload), request); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("unverified absence or duplicate JSON accepted: %s: %v", payload, err)
			}
		})
	}
}

func TestInspectRejectsForgedOrMalformedFoundReceipts(t *testing.T) {
	request := InspectRequest{TenantID: testTenant, RunIntentID: testIntent, RequestDigest: testDigest}
	good := `{"status":"FOUND","tenant_id":"tenant-1","run_intent_id":"` + testIntent + `","request_digest":"` + testDigest + `","run_id":"` + testRunID + `","workflow_id":"agent-run/v1/` + testRunID + `","created":false}`
	cases := map[string]string{
		"wrong tenant": strings.Replace(good, "tenant-1", "tenant-2", 1),
		"wrong intent": strings.Replace(good, testIntent, "00000000-0000-4000-8000-000000000999", 1),
		"wrong digest": strings.Replace(good, testDigest, "sha256:"+strings.Repeat("b", 64), 1),
		"wrong workflow": strings.Replace(good, "agent-run/v1/", "agent-run/v0/", 1),
		"invalid run id": strings.Replace(good, testRunID, "run/forged", 2),
		"extra token": good + `{}`,
		"extra field": strings.Replace(good, `"created":false`, `"created":false,"policy_revision":"forged"`, 1),
		"duplicate tenant": strings.Replace(good, `"tenant_id":"tenant-1"`, `"tenant_id":"tenant-1","tenant_id":"tenant-1"`, 1),
		"missing created": strings.Replace(good, `,"created":false`, "", 1),
		"wrong created type": strings.Replace(good, `"created":false`, `"created":"false"`, 1),
	}
	for name, payload := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseInspectResponse([]byte(payload), request); !errors.Is(err, ErrInvalidResponse) {
				t.Fatalf("invalid Runtime receipt accepted: %v, payload=%s", err, payload)
			}
		})
	}
}

func TestInspectClientRequiresHTTPSAndMutualTLSConfiguration(t *testing.T) {
	roots := x509.NewCertPool()
	clientIdentity := tls.Certificate{Certificate: [][]byte{[]byte("cert")}, PrivateKey: struct{}{}}
	for _, tc := range []struct {
		origin string
		id     string
		roots  *x509.CertPool
		cert   tls.Certificate
	}{
		{"http://runtime.local", "spiffe://example.org/runtime", roots, clientIdentity},
		{"https://user:pass@runtime.local", "spiffe://example.org/runtime", roots, clientIdentity},
		{"https://runtime.local/internal/v1", "spiffe://example.org/runtime", roots, clientIdentity},
		{"https://runtime.local?x=1", "spiffe://example.org/runtime", roots, clientIdentity},
		{"https://runtime.local", "spiffe://example.org/runtime", nil, clientIdentity},
		{"https://runtime.local", "spiffe://example.org/runtime", roots, tls.Certificate{}},
		{"https://runtime.local", "spiffe://example.org/", roots, clientIdentity},
		{"https://runtime.local", "https://runtime.local", roots, clientIdentity},
	} {
		if _, err := NewClient(tc.origin, tc.id, tc.roots, tc.cert); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("unsafe Runtime config accepted: origin=%q id=%q err=%v", tc.origin, tc.id, err)
		}
	}
	if _, err := NewClient("https://runtime.local:8443", "spiffe://example.org/runtime", roots, clientIdentity); err != nil {
		t.Fatalf("valid client config rejected: %v", err)
	}
}

func TestInspectRejectsMalformedLookupIdentifiers(t *testing.T) {
	for _, request := range []InspectRequest{
		{TenantID: testTenant, RunIntentID: "not-a-uuid", RequestDigest: testDigest},
		{TenantID: "tenant/\nother", RunIntentID: testIntent, RequestDigest: testDigest},
		{TenantID: testTenant, RunIntentID: testIntent, RequestDigest: strings.Repeat("a", 64)},
		{TenantID: testTenant, RunIntentID: testIntent, RequestDigest: "sha256:"+strings.Repeat("A", 64)},
		{TenantID: "", RunIntentID: testIntent, RequestDigest: testDigest},
	} {
		if err := request.Validate(); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("malformed lookup accepted: %+v err=%v", request, err)
		}
	}
}
