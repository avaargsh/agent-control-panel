//go:build linux

package postfault

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

func TestLocalWorkspaceRejectsAbsoluteParentAndTraversalReads(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.WriteFile(outside, []byte("external-secret"), 0600); err != nil {
		t.Fatal(err)
	}
	fd, _, err := openLocalWorkspaceRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	for _, name := range []string{
		"../outside", outside, "./outside", "nested/../../outside",
		"..", ".", "", "some/child", "some\\child",
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := readLocalWorkspaceFile(fd, name, 4096); err == nil {
				t.Fatalf("unsafe path read: %q => %q", name, got)
			}
		})
	}
}

func TestLocalWorkspaceRejectsParentSymlinkAndNonCanonicalRoot(t *testing.T) {
	base := t.TempDir()
	realParent := filepath.Join(base, "real")
	if err := os.Mkdir(realParent, 0700); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(realParent, "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "alias")
	if err := os.Symlink(realParent, link); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{
		filepath.Join(link, "workspace"), root + "/../workspace",
	} {
		if fd, _, err := openLocalWorkspaceRoot(candidate); err == nil {
			syscall.Close(fd)
			t.Fatalf("unsafe root component accepted: %s", candidate)
		}
	}
}

func TestLocalWorkspaceReadRejectsConcurrentSymlinkReplacement(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(base, "outside")
	if err := os.WriteFile(outside, []byte("outside-private"), 0600); err != nil {
		t.Fatal(err)
	}
	name := "sentinel"
	path := filepath.Join(root, name)
	if err := os.WriteFile(path, []byte("inside"), 0600); err != nil {
		t.Fatal(err)
	}
	fd, _, err := openLocalWorkspaceRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			_ = os.Remove(path)
			_ = os.Symlink(outside, path)
			_ = os.Remove(path)
			_ = os.WriteFile(path, []byte("inside"), 0600)
		}
	}()
	for i := 0; i < 500; i++ {
		b, err := readLocalWorkspaceFile(fd, name, 4096)
		if err == nil && !bytes.Equal(b, []byte("inside")) {
			t.Errorf("read escaped workspace root: %q", b)
			break
		}
	}
	wg.Wait()
	b, err := os.ReadFile(outside)
	if err != nil || !bytes.Equal(b, []byte("outside-private")) {
		t.Fatalf("external file changed: %q %v", b, err)
	}
}

// Hard links are not symlinks: O_NOFOLLOW still opens a regular inode shared
// with a sibling tenant's path. The local continuity reader must not accept
// that inode as an isolated workspace file, even if both paths are owner-owned.
func TestLocalWorkspaceRejectsHardLinkedSiblingTenantFile(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "tenant-a-workspace")
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(base, "tenant-b-private")
	if err := os.WriteFile(sibling, []byte("tenant-b-confidential-bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(sibling, filepath.Join(root, localSentinelFile)); err != nil {
		t.Fatal(err)
	}
	fd, _, err := openLocalWorkspaceRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Close(fd)
	if data, err := readLocalWorkspaceFile(fd, localSentinelFile, 4096); err == nil {
		t.Fatalf("hard-linked sibling tenant bytes escaped isolation: %q", data)
	}
}
