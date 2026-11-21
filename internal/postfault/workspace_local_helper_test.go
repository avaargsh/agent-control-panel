//go:build linux

package postfault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

const (
	localSentinelFile = ".acp-continuity"
	localMetadataFile = ".acp-workspace.json"
)

// These helpers exist only in the disposable test binary. They are NOT
// an authenticated SandboxService, provider binding, or AgentD command.
func prepareLocalWorkspace(root string, content []byte) (localWorkspaceSnapshot, error) {
	if len(content) == 0 || len(content) > 4096 {
		return localWorkspaceSnapshot{}, errors.New("invalid disposable content")
	}
	dirfd, stat, err := openLocalWorkspaceRoot(root)
	if err != nil {
		return localWorkspaceSnapshot{}, err
	}
	defer syscall.Close(dirfd)
	sentinel, err := syscall.Openat(dirfd, localSentinelFile,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return localWorkspaceSnapshot{}, errors.New("physical sentinel already exists or is unsafe")
	}
	if err := writeAndSyncLocalFD(sentinel, content); err != nil {
		return localWorkspaceSnapshot{}, err
	}
	// Read the actual file bytes from the directory handle *before* SIGKILL.
	// Hashing the caller's buffer would not prove the disk content existed.
	persisted, err := readLocalWorkspaceFile(dirfd, localSentinelFile, 4096)
	if err != nil || !bytes.Equal(persisted, content) {
		return localWorkspaceSnapshot{}, errors.New("pre-fault physical byte readback failed")
	}
	hash := sha256.Sum256(persisted)
	snapshot := localWorkspaceSnapshot{
		TenantID: "tenant-local", RunID: "run-local-1", LeaseID: "lease-local-1",
		SandboxUID: "sandbox-local-1", WorkspaceID: "workspace-local-1",
		Generation: 1, RootDevice: uint64(stat.Dev), RootInode: stat.Ino,
		SentinelDigest: "sha256:" + hex.EncodeToString(hash[:]),
	}
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return localWorkspaceSnapshot{}, err
	}
	receipt, err := syscall.Openat(dirfd, localMetadataFile,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return localWorkspaceSnapshot{}, errors.New("physical metadata already exists or is unsafe")
	}
	if err := writeAndSyncLocalFD(receipt, raw); err != nil {
		return localWorkspaceSnapshot{}, err
	}
	if err := syscall.Fsync(dirfd); err != nil {
		return localWorkspaceSnapshot{}, errors.New("workspace directory durability failed")
	}
	return snapshot, nil
}

func inspectLocalWorkspace(root string, expected localWorkspaceSnapshot) (localWorkspaceSnapshot, error) {
	dirfd, stat, err := openLocalWorkspaceRoot(root)
	if err != nil {
		return localWorkspaceSnapshot{}, err
	}
	defer syscall.Close(dirfd)
	if expected.RootDevice != uint64(stat.Dev) || expected.RootInode != stat.Ino {
		return localWorkspaceSnapshot{}, errors.New("physical workspace directory replaced")
	}
	metadata, err := readLocalWorkspaceFile(dirfd, localMetadataFile, 4096)
	if err != nil {
		return localWorkspaceSnapshot{}, err
	}
	var saved localWorkspaceSnapshot
	decoder := json.NewDecoder(bytes.NewReader(metadata))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&saved) != nil || decoder.Decode(new(any)) != io.EOF || saved != expected {
		return localWorkspaceSnapshot{}, errors.New("durable workspace binding does not match original")
	}
	bytesOnDisk, err := readLocalWorkspaceFile(dirfd, localSentinelFile, 4096)
	if err != nil {
		return localWorkspaceSnapshot{}, err
	}
	sum := sha256.Sum256(bytesOnDisk)
	if "sha256:"+hex.EncodeToString(sum[:]) != saved.SentinelDigest {
		return localWorkspaceSnapshot{}, errors.New("physical workspace sentinel changed")
	}
	return saved, nil
}

func openLocalWorkspaceRoot(root string) (int, syscall.Stat_t, error) {
	var info syscall.Stat_t
	if root == "" || root[0] != '/' {
		return -1, info, errors.New("absolute disposable root required")
	}
	fd, err := syscall.Open(root, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return -1, info, errors.New("workspace unavailable or symlinked")
	}
	if err := syscall.Fstat(fd, &info); err != nil ||
		info.Mode&syscall.S_IFMT != syscall.S_IFDIR || info.Mode&0077 != 0 {
		_ = syscall.Close(fd)
		return -1, info, errors.New("workspace root is unsafe or not owner-private")
	}
	return fd, info, nil
}

func writeAndSyncLocalFD(fd int, data []byte) error {
	file := os.NewFile(uintptr(fd), "disposable-local-write")
	n, err := file.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("durable disposable write failed: %w", err)
	}
	return nil
}

func readLocalWorkspaceFile(dirfd int, name string, limit int) ([]byte, error) {
	fd, err := syscall.Openat(dirfd, name, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("workspace file absent or unsafe")
	}
	file := os.NewFile(uintptr(fd), "disposable-local-read")
	defer file.Close()
	var stat syscall.Stat_t
	if syscall.Fstat(fd, &stat) != nil || stat.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return nil, errors.New("workspace file is not regular")
	}
	content, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || len(content) == 0 || len(content) > limit {
		return nil, errors.New("workspace file read invalid")
	}
	return content, nil
}
