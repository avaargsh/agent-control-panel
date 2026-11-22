package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIRequiresIndependentSources(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("missing package and trust roots must block")
	}
	if err := run([]string{"--package", "missing", "--expected", "missing", "--trust-dir", "missing"}); err == nil {
		t.Fatal("nonexistent independent inputs must block")
	}
}

func TestReadRegularRejectsSymlinkAndEmptyReceipt(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "original.json")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegular(target, 32); err != nil {
		t.Fatalf("valid bounded fixture file rejected: %v", err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegular(link, 32); err == nil {
		t.Fatal("symlink substitution accepted")
	}
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegular(empty, 32); err == nil {
		t.Fatal("empty authoritative input accepted")
	}
}

func TestCLIRequiresPairedIndependentArchiveInputs(t *testing.T) {
	for _, addition := range [][]string{
		{"--archive-seal", "some-seal.json"},
		{"--archive-pub", "some-archive.pub"},
	} {
		args := append([]string{
			"--package", "missing.json",
			"--expected", "missing.json",
			"--trust-dir", "missing-trust",
		}, addition...)
		err := run(args)
		if err == nil || !strings.Contains(err.Error(), "must be provided together") {
			t.Fatalf("partial archive flag was accepted or not explicitly blocked: %v", err)
		}
	}
}


func TestCLIRequireLinkedOptInDoesNotSilentlyFallBackOrTrustArchive(t *testing.T) {
	base := []string{
		"--package", "missing.json",
		"--expected", "missing.json",
		"--trust-dir", "missing-trust",
		"--require-linked",
	}
	if err := run(base); err == nil || !strings.Contains(err.Error(), "signed evidence package unavailable") {
		t.Fatalf("linked flag must be parsed and fail closed on absent owner evidence: %v", err)
	}
	withArchive := append(append([]string(nil), base...),
		"--archive-seal", "seal.json", "--archive-pub", "archiver.pub")
	if err := run(withArchive); err == nil || !strings.Contains(err.Error(), "live-only") {
		t.Fatalf("linked gate must not silently bypass itself under historical archive mode: %v", err)
	}
}
