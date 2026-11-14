package workspace

import (
	"errors"
	"strings"
	"testing"
)

func TestCanonicalManifestStableUnderOrder(t *testing.T) {
	a := Asset{Path: "data/a.csv", Digest: "sha256:" + strings.Repeat("a", 64), SizeBytes: 10}
	b := Asset{Path: "reports/b.md", Digest: "sha256:" + strings.Repeat("b", 64), SizeBytes: 22}
	j1, h1, err := CanonicalManifest([]Asset{b, a})
	if err != nil {
		t.Fatal(err)
	}
	j2, h2, err := CanonicalManifest([]Asset{a, b})
	if err != nil || h1 != h2 || string(j1) != string(j2) {
		t.Fatalf("order drift: %q %q err=%v", h1, h2, err)
	}
	_, changed, err := CanonicalManifest([]Asset{a})
	if err != nil || changed == h1 {
		t.Fatalf("manifest change did not change digest: %v", err)
	}
}

func TestCanonicalManifestRejectsTraversalAndMalformedArtifacts(t *testing.T) {
	base := Asset{Path: "reports/result.md", Digest: "sha256:" + strings.Repeat("a", 64), SizeBytes: 100}
	for _, bad := range []string{"../secret", "/etc/passwd", "./result.md", "reports//result.md", "reports/../data", "reports\\item", "a/./b", "", "reports\nother"} {
		a := base
		a.Path = bad
		if _, _, err := CanonicalManifest([]Asset{a}); !errors.Is(err, ErrInvalidManifest) {
			t.Errorf("invalid path %q accepted: %v", bad, err)
		}
	}
	for _, bad := range []Asset{
		{Path: base.Path, Digest: "sha256:" + strings.Repeat("G", 64), SizeBytes: 100},
		{Path: base.Path, Digest: base.Digest, SizeBytes: -1},
	} {
		if _, _, err := CanonicalManifest([]Asset{bad}); !errors.Is(err, ErrInvalidManifest) {
			t.Errorf("invalid asset accepted: %+v %v", bad, err)
		}
	}
	if _, _, err := CanonicalManifest([]Asset{base, base}); !errors.Is(err, ErrInvalidManifest) {
		t.Fatalf("duplicate path accepted: %v", err)
	}
}

func TestValidIDRejectsUnsafeIdentifiers(t *testing.T) {
	for _, bad := range []string{"", "../work", "-bad", ".hidden", "a/b", "a b", "name\n", strings.Repeat("a", 129)} {
		if ValidID(bad) {
			t.Errorf("unsafe id %q allowed", bad)
		}
	}
	if !ValidID("workspace-1") || !ValidID("commit.2026_1") {
		t.Fatal("valid id rejected")
	}
}
