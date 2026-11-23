package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

const goalSubmitHoldVersion = "acp.goal-submit-hold/v1"

// persistGoalHoldRecord writes a conservative, non-authoritative pointer to
// the exact immutable request BEFORE any network effect. A missing/unsafe
// record blocks the POST. Even a successful HTTP receipt must not remove this
// attempt evidence: the record is not proof of admission or Runtime execution.
//
// Use a new absolute path in a private directory for each operator-approved
// attempt. O_EXCL prevents accidental replay through the same record path.
func persistGoalHoldRecord(path string, proposal issuegoal.Prepared) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("hold record requires a clean absolute file path")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("hold record requires an existing private directory")
	}
	record := struct {
		Schema         string           `json:"schema"`
		Disposition    string           `json:"disposition"`
		Target         issuegoal.Target `json:"target"`
		IdempotencyKey string           `json:"idempotency_key"`
		RequestDigest  string           `json:"request_digest"`
	}{
		Schema: goalSubmitHoldVersion, Disposition: "UNKNOWN/HOLD",
		Target: proposal.Target, IdempotencyKey: proposal.IdempotencyKey,
		RequestDigest: proposal.RequestDigest,
	}
	payload, err := json.Marshal(record)
	if err != nil {
		return errors.New("hold record cannot be encoded")
	}
	payload = append(payload, byte(10))
	// Exclusive create rejects existing files and symlinks. Do not overwrite
	// an earlier unknown attempt or depend on a caller-readable audit path.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("hold record unavailable or already exists; no request sent")
	}
	committed := false
	defer func() {
		_ = file.Close()
		if !committed {
			_ = os.Remove(path)
		}
	}()
	n, err := file.Write(payload)
	if err != nil || n != len(payload) {
		return errors.New("hold record write failed; no request sent")
	}
	if err := file.Sync(); err != nil {
		return errors.New("hold record sync failed; no request sent")
	}
	if err := file.Close(); err != nil {
		return errors.New("hold record close failed; no request sent")
	}
	// Ensure the new directory entry itself is persisted before POST.
	dir, err := os.Open(parent)
	if err != nil {
		return errors.New("hold record directory unavailable; no request sent")
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return errors.New("hold record directory sync failed; no request sent")
	}
	committed = true
	return nil
}
