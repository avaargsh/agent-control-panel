package runintent

import (
	"errors"
	"strings"
	"testing"
)

func inputBindingIntent() Intent {
	return Intent{
		TenantID: "tenant-a", ProjectID: "project-a", AgentID: "agent-a",
		ReleaseID: "release-a", SessionID: "session-a", IdempotencyKey: "request-a",
	}
}

func TestExecutionInputDigestBindsExactBytesAndScope(t *testing.T) {
	base := inputBindingIntent()
	raw := []byte(`{"prompt":"test","number":9007199254740993}`)
	digest, err := ExecutionInputDigest(base, raw)
	if err != nil || !validDigest(digest) {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
	base.RequestDigest = digest
	if err := VerifyExecutionInput(base, raw); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*Intent)
	}{
		{"tenant", func(i *Intent) { i.TenantID = "tenant-b" }},
		{"project", func(i *Intent) { i.ProjectID = "project-b" }},
		{"agent", func(i *Intent) { i.AgentID = "agent-b" }},
		{"release", func(i *Intent) { i.ReleaseID = "release-b" }},
		{"session", func(i *Intent) { i.SessionID = "session-b" }},
		{"idempotency key", func(i *Intent) { i.IdempotencyKey = "request-b" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := base
			tc.edit(&changed)
			if err := VerifyExecutionInput(changed, raw); !errors.Is(err, ErrExecutionInputMismatch) {
				t.Fatalf("scope substitution accepted: %v", err)
			}
		})
	}
	for _, changed := range []string{
		`{"prompt":"different","number":9007199254740993}`,
		`{"number":9007199254740993,"prompt":"test"}`,
		`{"prompt": "test","number":9007199254740993}`,
		`{"prompt":"test","number":9007199254740992}`,
	} {
		if err := VerifyExecutionInput(base, []byte(changed)); !errors.Is(err, ErrExecutionInputMismatch) {
			t.Fatalf("input substitution accepted: %v", err)
		}
	}
	base.ID = "server-generated"
	base.RunID = "runtime-generated"
	if err := VerifyExecutionInput(base, raw); err != nil {
		t.Fatalf("server-assigned IDs changed request binding: %v", err)
	}
}

func TestExecutionInputRejectsAmbiguousOrUnboundedJSON(t *testing.T) {
	for _, raw := range [][]byte{
		nil, []byte("null"), []byte("[]"), []byte("1"), []byte("{} {}"),
		[]byte(`{"key":1,"key":2}`),
		[]byte(`{"nested":[{"key":1,"\u006bey":2}]}`),
		[]byte(`{"key":}`), []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'},
		[]byte(`{"x":` + strings.Repeat("[", 65) + "0" + strings.Repeat("]", 65) + "}"),
		[]byte(`{"x":"` + strings.Repeat("a", MaxExecutionInputBytes) + `"}`),
	} {
		if _, err := ExecutionInputDigest(inputBindingIntent(), raw); !errors.Is(err, ErrInvalidExecutionInput) {
			t.Fatalf("ambiguous/invalid input accepted (length %d): %v", len(raw), err)
		}
	}
	base := inputBindingIntent()
	base.ProjectID = ""
	if _, err := ExecutionInputDigest(base, []byte("{}")); !errors.Is(err, ErrInvalidExecutionInput) {
		t.Fatalf("missing scope accepted: %v", err)
	}
}

func TestExecutionInputDigestLengthFramingAndGoldenVector(t *testing.T) {
	base := inputBindingIntent()
	digest, err := ExecutionInputDigest(base, []byte("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if digest != "sha256:e36779ca83a5458c52e3959b1dafbd11ff54d434a5be6d1cedc6ada685f1b454" {
		t.Fatalf("digest framing changed: %s", digest)
	}
	a, b := base, base
	a.TenantID, a.ProjectID = "ab", "c"
	b.TenantID, b.ProjectID = "a", "bc"
	da, ea := ExecutionInputDigest(a, []byte("{}"))
	db, eb := ExecutionInputDigest(b, []byte("{}"))
	if ea != nil || eb != nil || da == db {
		t.Fatalf("length framing did not distinguish boundaries: %s %s %v %v", da, db, ea, eb)
	}
}
