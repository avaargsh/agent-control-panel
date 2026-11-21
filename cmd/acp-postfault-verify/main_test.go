package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPostfaultCLIFailsClosedWhenAuthoritativeInputsMissing(t *testing.T) {
	root := t.TempDir()
	existing := filepath.Join(root, "partial.json")
	if err := os.WriteFile(existing, []byte(`{"schema":"acp.postfault-bundle/v1","receipts":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		nil,
		{"--bundle", filepath.Join(root, "missing.json"), "--trust-dir", root},
		{"--bundle", existing, "--trust-dir", root},
		{"--bundle", existing, "--trust-dir", filepath.Join(root, "missing")},
	} {
		if err := run(args); err == nil {
			t.Fatalf("missing or self-asserted Golden Path recovery evidence accepted: %v", args)
		}
	}
}

func TestPostfaultCLIDoesNotFollowSymlinkToInjectedBundle(t *testing.T) {
	root := t.TempDir()
	realPath := filepath.Join(root, "recovery.json")
	if err := os.WriteFile(realPath, []byte(`{"schema":"acp.postfault-bundle/v1"}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "latest")
	if err := os.Symlink(realPath, link); err != nil {
		t.Fatal(err)
	}
	if _, err := privateBoundedInput(link); err == nil {
		t.Fatal("untrusted evidence symlink accepted")
	}
}

func TestPostfaultCLIRefusesMalformedPayloadWithoutLeakingBytes(t *testing.T) {
	root := t.TempDir()
	p := filepath.Join(root, "sensitive.json")
	if err := os.WriteFile(p, []byte(`{"schema":"SECRET-NOT-FOR-LOGGING","extra":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	err := run([]string{"--bundle", p, "--trust-dir", root})
	if err == nil || strings.Contains(err.Error(), "SECRET-NOT-FOR-LOGGING") {
		t.Fatalf("unsafe malformed bundle error: %v", err)
	}
}
