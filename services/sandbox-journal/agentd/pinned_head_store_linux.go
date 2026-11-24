//go:build linux

package agentd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"syscall"
	"time"
)

const pinnedFloorFile = "head.json"

// PinnedHeadStore is a non-production, single-original-attempt local verifier
// store. Its directory and all ancestors must be provisioned and controlled
// independently of the AgentD source, and reside on a local filesystem with
// flock, atomic rename and fsync semantics. It does not protect against a
// malicious store owner, snapshot rollback or distributed split brain.
// Initial enrollment is an explicit trusted operator action, not source input.
type PinnedHeadStore struct {
	mu  sync.Mutex
	dir *os.File
}

type pinnedFloorRecord struct {
	Schema string      `json:"schema"`
	Ref    Ref         `json:"ref"`
	Head   InspectHead `json:"head"`
}

func OpenPinnedHeadStore(path string) (*PinnedHeadStore, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnverified
	}
	dir := os.NewFile(uintptr(fd), "pinned-head-directory")
	info, err := dir.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !ownedFile(info, false) {
		dir.Close()
		return nil, ErrUnverified
	}
	return &PinnedHeadStore{dir: dir}, nil
}

func ownedFile(info os.FileInfo, regular bool) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == uint32(os.Geteuid()) && (!regular || (info.Mode().IsRegular() && info.Mode().Perm() == 0600 && st.Nlink == 1))
}

func (s *PinnedHeadStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == nil {
		return nil
	}
	err := s.dir.Close()
	s.dir = nil
	return err
}

func (s *PinnedHeadStore) locked(fn func(int) error) error {
	if s == nil {
		return ErrUnverified
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dir == nil {
		return ErrUnverified
	}
	fd := int(s.dir.Fd())
	info, err := s.dir.Stat()
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !ownedFile(info, false) {
		return ErrUnverified
	}
	lockfd, err := syscall.Openat(fd, "head.lock", syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return ErrUnverified
	}
	lock := os.NewFile(uintptr(lockfd), "pinned-head-lock")
	defer lock.Close()
	lockInfo, err := lock.Stat()
	if err != nil || !ownedFile(lockInfo, true) {
		return ErrUnverified
	}
	for {
		err = syscall.Flock(lockfd, syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		return ErrUnverified
	}
	defer syscall.Flock(lockfd, syscall.LOCK_UN)
	return fn(fd)
}

func readPinnedFloor(fd int, expected Ref) (InspectHead, error) {
	f, err := syscall.Openat(fd, pinnedFloorFile, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ENOENT) {
		return InspectHead{}, os.ErrNotExist
	}
	if err != nil {
		return InspectHead{}, ErrUnverified
	}
	file := os.NewFile(uintptr(f), pinnedFloorFile)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !ownedFile(info, true) || info.Size() <= 0 || info.Size() > maxPinnedHeadGrantBytes {
		return InspectHead{}, ErrUnverified
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxPinnedHeadGrantBytes+1))
	if err != nil || len(raw) > maxPinnedHeadGrantBytes {
		return InspectHead{}, ErrUnverified
	}
	var record pinnedFloorRecord
	if json.Unmarshal(raw, &record) != nil {
		return InspectHead{}, ErrUnverified
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(raw, canonical) || record.Schema != "acp.agentd-local-pinned-floor/v1" || record.Ref != expected || !validPinnedHead(record.Head) {
		return InspectHead{}, ErrUnverified
	}
	return record.Head, nil
}

func writePinnedFloor(fd int, ref Ref, head InspectHead) error {
	raw, err := json.Marshal(pinnedFloorRecord{Schema: "acp.agentd-local-pinned-floor/v1", Ref: ref, Head: head})
	if err != nil || len(raw) > maxPinnedHeadGrantBytes {
		return ErrUnverified
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return ErrUnverified
	}
	name := ".head-" + hex.EncodeToString(random[:])
	tmpfd, err := syscall.Openat(fd, name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return ErrUnverified
	}
	defer syscall.Unlinkat(fd, name)
	tmp := os.NewFile(uintptr(tmpfd), name)
	n, writeErr := tmp.Write(raw)
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if writeErr != nil || n != len(raw) || syncErr != nil || closeErr != nil {
		return ErrUnverified
	}
	if syscall.Renameat(fd, name, fd, pinnedFloorFile) != nil || syscall.Fsync(fd) != nil {
		return ErrUnverified
	}
	return nil
}

// Enroll establishes one out-of-band approved initial floor. An existing or
// unreadable record cannot be replaced by this operation.
func (s *PinnedHeadStore) Enroll(ref Ref, head InspectHead) error {
	if !ref.valid() || !validPinnedHead(head) {
		return ErrUnverified
	}
	return s.locked(func(fd int) error {
		if _, err := readPinnedFloor(fd, ref); !errors.Is(err, os.ErrNotExist) {
			return ErrUnverified
		}
		return writePinnedFloor(fd, ref, head)
	})
}

func (s *PinnedHeadStore) Read(ref Ref) (InspectHead, error) {
	var head InspectHead
	if !ref.valid() {
		return head, ErrUnverified
	}
	err := s.locked(func(fd int) error {
		var err error
		head, err = readPinnedFloor(fd, ref)
		if err != nil || syscall.Fsync(fd) != nil {
			return ErrUnverified
		}
		return nil
	})
	if err != nil {
		return InspectHead{}, err
	}
	return head, nil
}

// Advance atomically checks the expected current floor and authenticates the
// complete extension while holding the independent local verifier lock.
// A lost acknowledgement must be reconciled with Read, not blind retry.
func (s *PinnedHeadStore) Advance(ref Ref, expected InspectHead, raw, signature []byte, events []JournaledInspection, authorityKey, sourceKey ed25519.PublicKey, now time.Time) (InspectHead, error) {
	var candidate InspectHead
	err := s.locked(func(fd int) error {
		floor, err := readPinnedFloor(fd, ref)
		if err != nil || floor != expected {
			return ErrUnverified
		}
		candidate, err = VerifyPinnedHeadExtension(raw, signature, events, ref, floor, authorityKey, sourceKey, now)
		if err != nil {
			return ErrUnverified
		}
		if candidate == floor {
			if syscall.Fsync(fd) != nil {
				return ErrUnverified
			}
			return nil
		}
		return writePinnedFloor(fd, ref, candidate)
	})
	if err != nil {
		return InspectHead{}, err
	}
	return candidate, nil
}
