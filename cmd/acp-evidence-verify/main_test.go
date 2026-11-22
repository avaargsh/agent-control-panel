package main

import (
	"os"
	"path/filepath"
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
