package issuegoal

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode"
)

// ValidateUniqueJSONKeys closes a mismatch between Go's case-insensitive
// struct field matching and the exact-key duplicate detection in the ACP
// immutable JSON walker. A second spelling must never override a field.
func ValidateUniqueJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	root, err := dec.Token()
	if err != nil || root != json.Delim('{') {
		return ErrInvalidGoal
	}
	if err := walkFoldedKeys(dec, root, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrInvalidGoal
	}
	return nil
}

func walkFoldedKeys(dec *json.Decoder, token json.Token, depth int) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth > 64 {
		return ErrInvalidGoal
	}
	var end json.Delim
	switch delim {
	case '{':
		end = '}'
		seen := map[string]struct{}{}
		for dec.More() {
			key, err := dec.Token()
			name, ok := key.(string)
			if err != nil || !ok {
				return ErrInvalidGoal
			}
			folded := strings.Map(func(r rune) rune {
				// Match the full Unicode folding used by encoding/json.
				for next := unicode.SimpleFold(r); next > r; next = unicode.SimpleFold(r) {
					r = next
				}
				return unicode.SimpleFold(r)
			}, name)
			if _, exists := seen[folded]; exists {
				return ErrInvalidGoal
			}
			seen[folded] = struct{}{}
			value, err := dec.Token()
			if err != nil {
				return ErrInvalidGoal
			}
			if err := walkFoldedKeys(dec, value, depth+1); err != nil {
				return err
			}
		}
	case '[':
		end = ']'
		for dec.More() {
			value, err := dec.Token()
			if err != nil {
				return ErrInvalidGoal
			}
			if err := walkFoldedKeys(dec, value, depth+1); err != nil {
				return err
			}
		}
	default:
		return ErrInvalidGoal
	}
	last, err := dec.Token()
	if err != nil || last != end {
		return ErrInvalidGoal
	}
	return nil
}
