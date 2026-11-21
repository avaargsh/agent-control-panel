// Package identity validates immutable references in a sandbox-owned journal.
// Identifiers are references only; they never grant execution authorization.
package identity

import (
	"errors"
	"regexp"
)

var ErrInvalid = errors.New("invalid sandbox command identity")
var ref = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
var digest = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type Intent struct {
	TenantID         string
	RunID            string
	RuntimeAttemptID string
	SandboxUID       string
	CommandID        string
	RequestDigest    string
}

func (i Intent) Validate() error {
	for _, s := range []string{i.TenantID, i.RunID, i.RuntimeAttemptID, i.SandboxUID, i.CommandID} {
		if !ref.MatchString(s) {
			return ErrInvalid
		}
	}
	if !digest.MatchString(i.RequestDigest) {
		return ErrInvalid
	}
	return nil
}
