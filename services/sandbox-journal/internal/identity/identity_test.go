package identity

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func sample() Intent {
	return Intent{TenantID: "tenant-1", RunID: "11111111-1111-4111-8111-111111111111", RuntimeAttemptID: "attempt-1", SandboxUID: "sandbox-uid-1", CommandID: "command-1", RequestDigest: "sha256:" + strings.Repeat("a", 64)}
}
func TestValidIdentity(t *testing.T) {
	if err := sample().Validate(); err != nil {
		t.Fatal(err)
	}
}
func TestFailsClosedOnMissingOrMalformedIdentity(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Intent)
	}{
		{"empty tenant", func(i *Intent) { i.TenantID = "" }},
		{"cross-domain whitespace", func(i *Intent) { i.RunID = "run 1" }},
		{"embedded control", func(i *Intent) { i.CommandID = "command\n1" }},
		{"long sandbox UID", func(i *Intent) { i.SandboxUID = strings.Repeat("a", 129) }},
		{"unknown digest algorithm", func(i *Intent) { i.RequestDigest = "md5:" + strings.Repeat("a", 32) }},
		{"uppercase sha", func(i *Intent) { i.RequestDigest = "sha256:" + strings.Repeat("A", 64) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := sample()
			c.mut(&x)
			if !errors.Is(x.Validate(), ErrInvalid) {
				t.Fatal("invalid identity accepted")
			}
		})
	}
}

func TestPermitUnavailableDoesNotInventExecutorAttempt(t *testing.T) {
	if _, exists := reflect.TypeOf(Intent{}).FieldByName("ExecutorAttemptID"); exists {
		t.Fatal("pre-Permit identity must not claim an executor attempt exists")
	}
}
