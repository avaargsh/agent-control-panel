package authorityhttp

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

const maxReleaseBytes = 128 * 1024
const maxReleaseLifetime = 24 * time.Hour
const publicationSchema = "acp.decision-publication.v1"

var (
	ErrPublicationDenied      = errors.New("release publication denied")
	ErrPublicationUnavailable = errors.New("release publication unavailable")
	publicationID             = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)
	publicationVersion        = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

// ReleaseConfig is an operator-provisioned, canonical JSON artifact. Its
// exact SHA256 must match the admitted Release's immutable config digest.
// No credentials, endpoint, tools or executable configuration belong here.
type ReleaseConfig struct {
	SchemaVersion  string               `json:"schema_version"`
	TenantID       string               `json:"tenant_id"`
	ProjectID      string               `json:"project_id"`
	AgentID        string               `json:"agent_id"`
	AgentReleaseID string               `json:"agent_release_id"`
	PolicyRevision string               `json:"policy_revision"`
	CatalogVersion string               `json:"catalog_version"`
	IssuedAt       time.Time            `json:"issued_at"`
	ExpiresAt      time.Time            `json:"expires_at"`
	Services       []string             `json:"services"`
	Capabilities   []CapabilityContract `json:"capabilities"`
}

type CapabilityContract struct {
	ID           string          `json:"id"`
	Version      string          `json:"version"`
	InputSchema  json.RawMessage `json:"input_schema"`
	OutputSchema json.RawMessage `json:"output_schema"`
	EffectClass  string          `json:"effect_class"`
	Idempotency  string          `json:"idempotency"`
	TenantScoped bool            `json:"tenant_scoped"`
}

type CapabilityRef struct {
	ID              string `json:"id"`
	Version         string `json:"version"`
	ContractSHA256  string `json:"contract_sha256"`
	InputSchemaRef  string `json:"input_schema_ref"`
	OutputSchemaRef string `json:"output_schema_ref"`
	EffectClass     string `json:"effect_class"`
	Idempotency     string `json:"idempotency"`
	TenantScoped    bool   `json:"tenant_scoped"`
}

type SnapshotRef struct {
	ID             string    `json:"id"`
	Version        string    `json:"version"`
	SHA256         string    `json:"sha256"`
	Source         string    `json:"source"`
	AttestationRef string    `json:"attestation_ref"`
	TrustLevel     string    `json:"trust_level"`
	IssuedAt       time.Time `json:"issued_at"`
	ExpiresAt      time.Time `json:"expires_at"`
}

type DecisionContext struct {
	Authority Snapshot `json:"authority"`
	Objective string   `json:"objective"`
	Service   string   `json:"service"`
	Signal    string   `json:"signal"`
}

type Publication struct {
	SchemaVersion      string          `json:"schema_version"`
	Authority          Snapshot        `json:"authority"`
	Context            DecisionContext `json:"context"`
	ContextSnapshot    SnapshotRef     `json:"context_snapshot"`
	CapabilitySnapshot SnapshotRef     `json:"capability_snapshot"`
	Capabilities       []CapabilityRef `json:"capabilities"`
	ContextContent     []byte          `json:"context_content"`
	CapabilityContent  []byte          `json:"capability_content"`
}

// Payload contains exact signed bytes, not a marshal/re-marshal signature
// convention. KeyID is a SHA256 fingerprint of the externally pinned public
// key. The verifier must not trust a key supplied by an Agent or response.
type SignedPublication struct {
	KeyID     string `json:"key_id"`
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type Publisher struct {
	root  *os.Root
	key   ed25519.PrivateKey
	keyID string
}

func NewPublisher(directory string, key ed25519.PrivateKey) (*Publisher, error) {
	if directory == "" || len(key) != ed25519.PrivateKeySize {
		return nil, ErrPublicationUnavailable
	}
	// Reject malformed private keys whose public half does not match seed.
	if !bytes.Equal(key, ed25519.NewKeyFromSeed(key.Seed())) {
		return nil, ErrPublicationUnavailable
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, ErrPublicationUnavailable
	}
	return &Publisher{root: root, key: bytes.Clone(key), keyID: sha256Hex(key.Public().(ed25519.PublicKey))}, nil
}

func (p *Publisher) Close() error {
	return p.root.Close()
}

func sha256Hex(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func canonicalObject(raw []byte) bool {
	if len(raw) < 2 || len(raw) > maxReleaseBytes || !utf8.Valid(raw) {
		return false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(json.Token, int) bool
	walk = func(token json.Token, depth int) bool {
		delim, ok := token.(json.Delim)
		if !ok {
			return true
		}
		if depth > 32 || (delim != '{' && delim != '[') {
			return false
		}
		seen := map[string]bool{}
		for d.More() {
			if delim == '{' {
				t, err := d.Token()
				key, ok := t.(string)
				if err != nil || !ok || seen[key] {
					return false
				}
				seen[key] = true
			}
			child, err := d.Token()
			if err != nil || !walk(child, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && (delim == '{' && end == json.Delim('}') || delim == '[' && end == json.Delim(']'))
	}
	token, err := d.Token()
	if err != nil || token != json.Delim('{') || !walk(token, 1) {
		return false
	}
	_, err = d.Token()
	return err == io.EOF
}

func decodeRelease(raw []byte) (ReleaseConfig, error) {
	var c ReleaseConfig
	if !canonicalObject(raw) {
		return c, ErrPublicationUnavailable
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		return c, ErrPublicationUnavailable
	}
	canonical, err := json.Marshal(c)
	if err != nil || !bytes.Equal(canonical, raw) {
		return c, ErrPublicationUnavailable
	}
	return c, nil
}

func validateRelease(c ReleaseConfig, a Snapshot, now time.Time) error {
	if c.SchemaVersion != "acp.release-publication.v1" ||
		c.TenantID != a.TenantID || c.ProjectID != a.ProjectID || c.AgentID != a.AgentID ||
		c.AgentReleaseID != a.AgentReleaseID || c.PolicyRevision != a.PolicyRevision ||
		!publicationVersion.MatchString(c.CatalogVersion) || now.Before(c.IssuedAt) || !now.Before(c.ExpiresAt) ||
		c.IssuedAt.IsZero() || !c.ExpiresAt.After(c.IssuedAt) || c.ExpiresAt.Sub(c.IssuedAt) > maxReleaseLifetime ||
		len(c.Services) == 0 || len(c.Services) > 32 || c.Capabilities == nil || len(c.Capabilities) > 3 {
		return ErrPublicationDenied
	}
	for i, service := range c.Services {
		if !publicationID.MatchString(service) || (i > 0 && c.Services[i-1] >= service) {
			return ErrPublicationDenied
		}
	}
	for i, cap := range c.Capabilities {
		if (cap.ID != "sre.metrics.read" && cap.ID != "sre.logs.read" && cap.ID != "sre.changes.read") ||
			!publicationVersion.MatchString(cap.Version) || cap.EffectClass != "read_only" ||
			cap.Idempotency != "safe" || !cap.TenantScoped ||
			len(cap.InputSchema) > 16384 || len(cap.OutputSchema) > 16384 ||
			!canonicalObject(cap.InputSchema) || !canonicalObject(cap.OutputSchema) ||
			(i > 0 && c.Capabilities[i-1].ID >= cap.ID) {
			return ErrPublicationDenied
		}
	}
	return nil
}

func decodeContext(a Snapshot, raw []byte) (DecisionContext, error) {
	c := DecisionContext{Authority: a}
	if !canonicalObject(raw) {
		return c, ErrPublicationDenied
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || len(obj) != 3 {
		return c, ErrPublicationDenied
	}
	for key, dest := range map[string]*string{"objective": &c.Objective, "service": &c.Service, "signal": &c.Signal} {
		if err := json.Unmarshal(obj[key], dest); err != nil || *dest == "" {
			return c, ErrPublicationDenied
		}
	}
	if c.Objective != "sre_incident_triage" || !publicationID.MatchString(c.Service) ||
		(c.Signal != "latency" && c.Signal != "errors" && c.Signal != "saturation") {
		return c, ErrPublicationDenied
	}
	return c, nil
}

// Publish is a trusted internal operation; the HTTP host first rechecks the
// exact current catalog binding and obtains immutable input in the same query.
// It never accepts caller-provided capability, context, signature or evidence.
func (p *Publisher) Publish(a Snapshot, input []byte, now time.Time) (SignedPublication, error) {
	var empty SignedPublication
	if p == nil || p.root == nil || a.SchemaVersion != "acp.run-authority.v1" ||
		!idPattern.MatchString(a.RunID) || !idPattern.MatchString(a.RunIntentID) ||
		!digestPattern.MatchString(a.ConfigDigest) || !digestPattern.MatchString(a.RequestDigest) {
		return empty, ErrPublicationUnavailable
	}
	for _, id := range []string{a.TenantID, a.ProjectID, a.AgentID, a.AgentReleaseID, a.SessionID,
		a.PrincipalID, a.SubjectID, a.ActorID, a.PolicyRevision} {
		if !publicationID.MatchString(id) {
			return empty, ErrPublicationDenied
		}
	}
	if a.ActorID != a.SubjectID {
		return empty, ErrPublicationDenied
	}
	file, err := p.root.Open(strings.TrimPrefix(a.ConfigDigest, "sha256:") + ".json")
	if err != nil {
		return empty, ErrPublicationUnavailable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxReleaseBytes {
		return empty, ErrPublicationUnavailable
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxReleaseBytes+1))
	if err != nil || len(raw) > maxReleaseBytes || "sha256:"+sha256Hex(raw) != a.ConfigDigest {
		return empty, ErrPublicationUnavailable
	}
	c, err := decodeRelease(raw)
	if err != nil {
		return empty, err
	}
	if err := validateRelease(c, a, now); err != nil {
		return empty, err
	}
	context, err := decodeContext(a, input)
	if err != nil || !slices.Contains(c.Services, context.Service) {
		return empty, ErrPublicationDenied
	}
	refs := make([]CapabilityRef, 0, len(c.Capabilities))
	for _, cap := range c.Capabilities {
		contract, err := json.Marshal(cap)
		if err != nil {
			return empty, ErrPublicationUnavailable
		}
		refs = append(refs, CapabilityRef{
			ID: cap.ID, Version: cap.Version, ContractSHA256: sha256Hex(contract),
			InputSchemaRef: "sha256:" + sha256Hex(cap.InputSchema), OutputSchemaRef: "sha256:" + sha256Hex(cap.OutputSchema),
			EffectClass: cap.EffectClass, Idempotency: cap.Idempotency, TenantScoped: cap.TenantScoped,
		})
	}
	contextBytes, err := json.Marshal(context)
	if err != nil {
		return empty, ErrPublicationUnavailable
	}
	snapshot := func(kind, version string, content []byte) SnapshotRef {
		digest := sha256Hex(content)
		return SnapshotRef{
			ID: kind + "-" + digest, Version: version, SHA256: digest,
			Source: "agent-control-panel", AttestationRef: "acp:publication:" + p.keyID + ":" + a.RunID,
			TrustLevel: "attested", IssuedAt: c.IssuedAt, ExpiresAt: c.ExpiresAt,
		}
	}
	result := Publication{
		SchemaVersion: publicationSchema, Authority: a, Context: context,
		ContextSnapshot: snapshot("ctx", "acp-context-v1", contextBytes),
		CapabilitySnapshot: snapshot("cap", c.CatalogVersion, raw),
		Capabilities: refs, ContextContent: contextBytes, CapabilityContent: raw,
	}
	payload, err := json.Marshal(result)
	if err != nil {
		return empty, ErrPublicationUnavailable
	}
	return SignedPublication{KeyID: p.keyID, Payload: payload, Signature: ed25519.Sign(p.key, payload)}, nil
}
