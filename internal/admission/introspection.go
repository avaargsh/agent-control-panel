package admission

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrUnauthenticated     = errors.New("access token is not valid for ACP")
	ErrIdentityUnavailable = errors.New("identity authority unavailable")
	ErrIdentityConfig      = errors.New("invalid introspection configuration")
)

const maxIntrospectionBytes = 64 << 10

// Identity is external identity evidence, not a canonical ACP principal or
// an authorization grant. The configured policy authority maps issuer+subject.
type Identity struct {
	Issuer    string
	Subject   string
	ClientID  string
	Scope     string
	ExpiresAt time.Time
}

type IntrospectionConfig struct {
	Endpoint     string
	Issuer       string
	Audience     string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client // optional trusted transport/CA configuration
}

type Introspector struct {
	endpoint string
	issuer   string
	audience string
	id       string
	secret   string
	client   *http.Client
}

func validHTTPS(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" &&
		u.User == nil && u.Opaque == "" && u.RawQuery == "" &&
		!u.ForceQuery && u.Fragment == "" && u.String() == raw
}

func NewIntrospector(cfg IntrospectionConfig) (*Introspector, error) {
	if !validHTTPS(cfg.Endpoint) || !validHTTPS(cfg.Issuer) ||
		!validIdentityValue(cfg.Audience) || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, ErrIdentityConfig
	}
	// Only a standard TLS-verifying transport is supported. Clone it to
	// avoid mutating caller configuration or inheriting redirect/cookie state.
	rt := http.DefaultTransport
	if cfg.HTTPClient != nil && cfg.HTTPClient.Transport != nil {
		rt = cfg.HTTPClient.Transport
	}
	base, ok := rt.(*http.Transport)
	if !ok || base == nil || base.DialTLSContext != nil || base.DialTLS != nil {
		return nil, ErrIdentityConfig
	}
	transport := base.Clone()
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{}
	}
	if transport.TLSClientConfig.InsecureSkipVerify {
		return nil, ErrIdentityConfig
	}
	if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		transport.TLSClientConfig.MinVersion = tls.VersionTLS12
	}
	client := &http.Client{
		Transport: transport, Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &Introspector{
		endpoint: cfg.Endpoint, issuer: cfg.Issuer, audience: cfg.Audience,
		id: cfg.ClientID, secret: cfg.ClientSecret, client: client,
	}, nil
}

func validIdentityValue(v string) bool {
	if v == "" || len(v) > 256 || !utf8.ValidString(v) || strings.TrimSpace(v) != v {
		return false
	}
	return strings.IndexFunc(v, unicode.IsControl) < 0
}

func validBearer(v string) bool {
	if v == "" || len(v) > 8192 {
		return false
	}
	for _, c := range []byte(v) {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}

// Authenticate invokes the configured RFC 7662 endpoint with service client
// authentication. Require explicit resource-server binding and bearer type;
// deployments whose IdP omits these claims are intentionally unsupported.
// Never cache token status or return raw tokens, response bodies or URLs.
func (a *Introspector) Authenticate(ctx context.Context, token string) (Identity, error) {
	if a == nil || a.client == nil {
		return Identity{}, ErrIdentityConfig
	}
	if !validBearer(token) {
		return Identity{}, ErrUnauthenticated
	}
	form := url.Values{"token": {token}, "token_type_hint": {"access_token"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Identity{}, ErrIdentityUnavailable
	}
	req.SetBasicAuth(url.QueryEscape(a.id), url.QueryEscape(a.secret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return Identity{}, ErrIdentityUnavailable
	}
	defer resp.Body.Close()
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode != http.StatusOK || err != nil || media != "application/json" {
		return Identity{}, ErrIdentityUnavailable
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIntrospectionBytes+1))
	if err != nil || len(body) > maxIntrospectionBytes {
		return Identity{}, ErrIdentityUnavailable
	}
	claims, err := uniqueClaims(body)
	if err != nil {
		return Identity{}, ErrUnauthenticated
	}
	var active bool
	var issuer, subject, kind string
	var expiry int64
	if json.Unmarshal(claims["active"], &active) != nil || !active ||
		json.Unmarshal(claims["iss"], &issuer) != nil || issuer != a.issuer ||
		!containsAudience(claims["aud"], a.audience) ||
		json.Unmarshal(claims["sub"], &subject) != nil || !validIdentityValue(subject) ||
		json.Unmarshal(claims["token_type"], &kind) != nil || !strings.EqualFold(kind, "Bearer") ||
		json.Unmarshal(claims["exp"], &expiry) != nil || expiry <= time.Now().Unix() {
		return Identity{}, ErrUnauthenticated
	}
	if raw, ok := claims["nbf"]; ok {
		var nbf *int64
		if json.Unmarshal(raw, &nbf) != nil || nbf == nil || *nbf > time.Now().Unix() {
			return Identity{}, ErrUnauthenticated
		}
	}
	// Direct bearer admission cannot interpret token-exchange actors or
	// proof-of-possession credentials. Reject rather than flattening them.
	for _, name := range []string{"act", "may_act", "cnf"} {
		if _, present := claims[name]; present {
			return Identity{}, ErrUnauthenticated
		}
	}
	var clientID, scope string
	if raw, present := claims["client_id"]; present {
		if json.Unmarshal(raw, &clientID) != nil || !validIdentityValue(clientID) {
			return Identity{}, ErrUnauthenticated
		}
	}
	if raw, present := claims["scope"]; present {
		if json.Unmarshal(raw, &scope) != nil || !validOAuthScope(scope) {
			return Identity{}, ErrUnauthenticated
		}
	}
	return Identity{Issuer: issuer, Subject: subject, ClientID: clientID, Scope: scope, ExpiresAt: time.Unix(expiry, 0).UTC()}, nil
}

func containsAudience(raw json.RawMessage, want string) bool {
	var single string
	if json.Unmarshal(raw, &single) == nil && single != "" {
		return single == want
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		return false
	}
	for _, value := range many {
		if value == want {
			return true
		}
	}
	return false
}

// Only exact top-level claims are consumed; duplicate fields and trailing
// JSON are rejected, rather than accepting last-value-wins ambiguity.
func uniqueClaims(body []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	if !utf8.Valid(body) {
		return nil, ErrUnauthenticated
	}
	open, err := decoder.Token()
	if err != nil || open != json.Delim('{') {
		return nil, ErrUnauthenticated
	}
	claims := make(map[string]json.RawMessage)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok {
			return nil, ErrUnauthenticated
		}
		if _, exists := claims[name]; exists {
			return nil, ErrUnauthenticated
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return nil, ErrUnauthenticated
		}
		claims[name] = raw
	}
	closeToken, err := decoder.Token()
	if err != nil || closeToken != json.Delim('}') {
		return nil, ErrUnauthenticated
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrUnauthenticated
	}
	return claims, nil
}

// IdentityAuthenticator and PolicyAuthority are separate authorities.
// The latter MUST authorize the authenticated external issuer+subject,
// resolve immutable request/config digests and map canonical ACP identities.
type IdentityAuthenticator interface {
	Authenticate(context.Context, string) (Identity, error)
}

type PolicyAuthority interface {
	Authorize(context.Context, Identity, Request) (Grant, error)
}

type bearerResolver struct {
	auth   IdentityAuthenticator
	policy PolicyAuthority
	token  string
}

// NewBearerResolver is request-scoped; do not retain it across user requests.
// No credential is forwarded to the policy resolver or persisted in a Grant.
func NewBearerResolver(auth IdentityAuthenticator, policy PolicyAuthority, token string) Resolver {
	return &bearerResolver{auth: auth, policy: policy, token: token}
}

func (r *bearerResolver) Resolve(ctx context.Context, req Request) (Grant, error) {
	if r == nil || r.auth == nil || r.policy == nil {
		return Grant{}, ErrInvalidConfig
	}
	id, err := r.auth.Authenticate(ctx, r.token)
	if err != nil {
		return Grant{}, err
	}
	if !validHTTPS(id.Issuer) || !validIdentityValue(id.Subject) || !id.ExpiresAt.After(time.Now()) {
		return Grant{}, ErrUnauthenticated
	}
	if err := ctx.Err(); err != nil {
		return Grant{}, err
	}
	grant, err := r.policy.Authorize(ctx, id, req)
	if err != nil {
		return Grant{}, err
	}
	if !id.ExpiresAt.After(time.Now()) {
		return Grant{}, ErrUnauthenticated
	}
	return grant, ctx.Err()
}
