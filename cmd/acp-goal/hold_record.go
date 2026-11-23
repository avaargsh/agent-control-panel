package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

const (
	goalSubmitHoldVersion = "acp.goal-submit-hold/v1"
	maxGoalHoldBytes      = 4096
)

type goalHoldRecord struct {
	Schema         string           `json:"schema"`
	Disposition    string           `json:"disposition"`
	Target         issuegoal.Target `json:"target"`
	IdempotencyKey string           `json:"idempotency_key"`
	RequestDigest  string           `json:"request_digest"`
}

// verifyGoalHoldRecord binds an operator-owned pre-POST attempt to the exact
// original Prepared proposal BEFORE querying ACP. It only validates the
// local marker; neither it nor an ACP PENDING record can certify Runtime Run
// execution or authorize a retry. Even a successful query must not clear it.
func verifyGoalHoldRecord(path string, proposal issuegoal.Prepared) error {
	const untrusted = "local Goal HOLD record unavailable or does not match the original request; UNKNOWN/HOLD, no status query sent"
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New(untrusted)
	}
	parent := filepath.Dir(path)
	dirInfo, err := os.Lstat(parent)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode().Perm()&0077 != 0 {
		return errors.New(untrusted)
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode().Perm()&0077 != 0 ||
		before.Size() == 0 || before.Size() > maxGoalHoldBytes {
		return errors.New(untrusted)
	}
	file, err := os.Open(path)
	if err != nil {
		return errors.New(untrusted)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 ||
		opened.Size() == 0 || opened.Size() > maxGoalHoldBytes || !os.SameFile(before, opened) {
		return errors.New(untrusted)
	}
	// Ensure the containing directory did not change while opening the file.
	dir, err := os.Open(parent)
	if err != nil {
		return errors.New(untrusted)
	}
	defer dir.Close()
	openedDir, err := dir.Stat()
	if err != nil || !os.SameFile(dirInfo, openedDir) || openedDir.Mode().Perm()&0077 != 0 {
		return errors.New(untrusted)
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxGoalHoldBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxGoalHoldBytes ||
		issuegoal.ValidateUniqueJSONKeys(raw) != nil {
		return errors.New(untrusted)
	}
	var held goalHoldRecord
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&held) != nil || decoder.Decode(new(any)) != io.EOF ||
		held.Schema != goalSubmitHoldVersion || held.Disposition != "UNKNOWN/HOLD" ||
		held.Target != proposal.Target || held.IdempotencyKey != proposal.IdempotencyKey ||
		held.RequestDigest != proposal.RequestDigest {
		return errors.New(untrusted)
	}
	return nil
}

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
	record := goalHoldRecord{
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
