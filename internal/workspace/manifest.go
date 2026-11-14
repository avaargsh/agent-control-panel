// Package workspace validates full-snapshot immutable object references.
// It does not authenticate clients or upload, read or verify any object bytes.
package workspace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"sort"
	"strings"
)

var ErrInvalidManifest = errors.New("invalid workspace manifest")

const maxAssets = 1024
const maxManifestBytes = 1024 * 1024
const maxObjectBytes int64 = 1 << 40

type Asset struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	SizeBytes int64  `json:"size_bytes"`
}

// ValidID enforces bounded, unambiguous application identifiers. An ID is not
// an authorization token or filesystem path.
func ValidID(s string) bool {
	if len(s) == 0 || len(s) > 128 || s[0] == '.' || s[0] == '-' || strings.Contains(s, "..") {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func ValidDigest(d string) bool {
	if len(d) != 71 || !strings.HasPrefix(d, "sha256:") {
		return false
	}
	hexPart := strings.TrimPrefix(d, "sha256:")
	if strings.ToLower(hexPart) != hexPart {
		return false
	}
	_, err := hex.DecodeString(hexPart)
	return err == nil
}

func validPath(p string) bool {
	if len(p) == 0 || len(p) > 512 || strings.HasPrefix(p, "/") ||
		strings.ContainsAny(p, "\\:\x00\r\n\t") || strings.HasPrefix(p, ".") {
		return false
	}
	for _, segment := range strings.Split(p, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return path.Clean(p) == p
}

// CanonicalManifest returns stable JSON and a content digest independent of
// input order. No object-store existence or access is asserted by this digest.
func CanonicalManifest(assets []Asset) ([]byte, string, error) {
	if len(assets) > maxAssets {
		return nil, "", ErrInvalidManifest
	}
	sorted := append([]Asset{}, assets...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	for i, a := range sorted {
		if !validPath(a.Path) || !ValidDigest(a.Digest) || a.SizeBytes < 0 || a.SizeBytes > maxObjectBytes {
			return nil, "", ErrInvalidManifest
		}
		if i > 0 && sorted[i-1].Path == a.Path {
			return nil, "", ErrInvalidManifest
		}
	}
	if sorted == nil {
		sorted = []Asset{}
	}
	payload, err := json.Marshal(sorted)
	if err != nil || len(payload) > maxManifestBytes {
		return nil, "", ErrInvalidManifest
	}
	sum := sha256.Sum256(append([]byte("workspace-manifest/v1\n"), payload...))
	return payload, "sha256:" + hex.EncodeToString(sum[:]), nil
}
