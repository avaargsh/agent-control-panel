package journal

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The standalone Sandbox database has a single ordered migration history.
// Duplicate version numbers are ambiguous for deployment tooling, while a
// disposable demo that skips a migration can silently omit security controls.
func TestSandboxMigrationVersionsAndDisposableDemoAreComplete(t *testing.T) {
	paths, err := filepath.Glob("../migrations/[0-9][0-9][0-9][0-9]_*.sql")
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("no Sandbox SQL migrations found")
	}

	versionByName := make(map[string]int, len(paths))
	nameByVersion := make(map[int]string, len(paths))
	versions := make([]int, 0, len(paths))
	for _, path := range paths {
		name := filepath.Base(path)
		version, err := strconv.Atoi(name[:4])
		if err != nil {
			t.Fatalf("invalid migration filename %q: %v", name, err)
		}
		if prior, exists := nameByVersion[version]; exists {
			t.Errorf("duplicate Sandbox migration version %04d: %s and %s", version, prior, name)
		}
		nameByVersion[version] = name
		versionByName[name] = version
		versions = append(versions, version)
	}
	sort.Ints(versions)
	for i, version := range versions {
		if version != i+1 {
			t.Errorf("migration versions must be contiguous from 0001: position %d has %04d", i+1, version)
		}
	}

	raw, err := os.ReadFile("../compose.demo.yaml")
	if err != nil {
		t.Fatal(err)
	}
	loaded := make(map[string]bool, len(paths))
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "- ./migrations/") || !strings.Contains(line, "/docker-entrypoint-initdb.d/") {
			continue
		}
		mount := strings.TrimPrefix(line, "- ./migrations/")
		parts := strings.Split(mount, ":")
		if len(parts) != 3 || parts[2] != "ro" {
			t.Errorf("invalid read-only migration mount %q", line)
			continue
		}
		name := parts[0]
		version, exists := versionByName[name]
		if !exists {
			// The disposable fixture files live under migrations/tests and
			// intentionally are not part of the schema migration sequence.
			if !strings.HasPrefix(name, "tests/") {
				t.Errorf("compose references an unknown migration %q", name)
			}
			continue
		}
		target := filepath.Base(parts[1])
		if !strings.HasPrefix(target, fmt.Sprintf("%02d_", version)) {
			t.Errorf("migration %s has out-of-order init filename %s", name, target)
		}
		if loaded[name] {
			t.Errorf("compose loads migration %s more than once", name)
		}
		loaded[name] = true
	}
	for name := range versionByName {
		if !loaded[name] {
			t.Errorf("disposable demo skips migration %s", name)
		}
	}
}
