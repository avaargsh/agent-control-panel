package runintent

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"unicode"
	"unicode/utf8"
)

// ExecutionInputVersion describes the exact-byte preimage, not a JSON
// canonicalization standard or a ratified Runtime wire protocol.
const ExecutionInputVersion = "acp-execution-input/v1"
const MaxExecutionInputBytes = 256 * 1024

var (
	ErrInvalidExecutionInput  = errors.New("invalid immutable execution input")
	ErrExecutionInputMismatch = errors.New("execution input does not match request digest")
)

// ExecutionInputDigest is computed by ACP from actual input, never from a
// client-supplied hash. Every component is framed as uint32 big-endian byte
// length followed by its bytes. Keep the field order and version immutable.
// Policy and principal identity remain independently bound to the Intent.
func ExecutionInputDigest(intent Intent, raw []byte) (string, error) {
	scope := []string{ExecutionInputVersion, intent.TenantID, intent.ProjectID,
		intent.AgentID, intent.ReleaseID, intent.SessionID, intent.IdempotencyKey}
	for _, field := range scope[1:] {
		if !validOpaqueID(field) || !utf8.ValidString(field) ||
			bytes.IndexFunc([]byte(field), unicode.IsControl) >= 0 {
			return "", ErrInvalidExecutionInput
		}
	}
	if err := validateExecutionJSON(raw); err != nil {
		return "", err
	}
	h := sha256.New()
	writeField := func(field []byte) {
		var size [4]byte
		binary.BigEndian.PutUint32(size[:], uint32(len(field)))
		_, _ = h.Write(size[:])
		_, _ = h.Write(field)
	}
	for _, field := range scope {
		writeField([]byte(field))
	}
	writeField(raw)
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// VerifyExecutionInput recomputes the digest from exact persisted bytes
// before they can be used to construct an execution request. This does not
// authorize a dispatch or replace principal/policy verification.
func VerifyExecutionInput(intent Intent, raw []byte) error {
	digest, err := ExecutionInputDigest(intent, raw)
	if err != nil {
		return err
	}
	if digest != intent.RequestDigest {
		return ErrExecutionInputMismatch
	}
	return nil
}

func validateExecutionJSON(raw []byte) error {
	if len(raw) < 2 || len(raw) > MaxExecutionInputBytes || !utf8.Valid(raw) {
		return ErrInvalidExecutionInput
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	root, err := dec.Token()
	if err != nil || root != json.Delim('{') {
		return ErrInvalidExecutionInput
	}
	if err := walkExecutionJSON(dec, root, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrInvalidExecutionInput
	}
	return nil
}

// Reject duplicate object keys at every depth, including equivalent escaped
// key spellings. Decoder.UseNumber avoids floating-point coercion.
func walkExecutionJSON(dec *json.Decoder, token json.Token, depth int) error {
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth > 64 {
		return ErrInvalidExecutionInput
	}
	var end json.Delim
	switch delimiter {
	case '{':
		end = '}'
		seen := make(map[string]struct{})
		for dec.More() {
			key, err := dec.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return ErrInvalidExecutionInput
			}
			if _, exists := seen[name]; exists {
				return ErrInvalidExecutionInput
			}
			seen[name] = struct{}{}
			value, err := dec.Token()
			if err != nil {
				return ErrInvalidExecutionInput
			}
			if err := walkExecutionJSON(dec, value, depth+1); err != nil {
				return err
			}
		}
	case '[':
		end = ']'
		for dec.More() {
			value, err := dec.Token()
			if err != nil {
				return ErrInvalidExecutionInput
			}
			if err := walkExecutionJSON(dec, value, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrInvalidExecutionInput
	}
	closeToken, err := dec.Token()
	if err != nil || closeToken != end {
		return ErrInvalidExecutionInput
	}
	return nil
}
