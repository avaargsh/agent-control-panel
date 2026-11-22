// Command acp-postfault-verify enforces the non-production full Golden Path
// proof boundary. It is read-only and never issues a Guard Permit, executes
// a command, starts a Workflow or writes a RunIntent.
package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/postfault"
)

const maxBundleBytes = 128 << 10

const expectedBindingVersion = "acp.postfault-expected/v1"

// The expected binding must be read independently from the actual ACP/Runtime
// authority and fault injector, not copied from the submitted bundle.
type expectedBinding struct {
	Schema  string            `json:"schema"`
	Subject postfault.Subject `json:"subject"`
	FaultID string            `json:"fault_id"`
	FaultAt time.Time         `json:"fault_at"`
}

func matchesExpected(bundle postfault.Bundle, expected expectedBinding) error {
	if bundle.Subject != expected.Subject || bundle.Fault.ID != expected.FaultID ||
		!bundle.Fault.At.Equal(expected.FaultAt) {
		return errors.New("postfault bundle does not match independently accepted Run and injected fault")
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		// Never print raw payloads, keys, bearer tokens or provider errors.
		fmt.Fprintln(os.Stderr, "POSTFAULT RECOVERY BLOCKED:", err)
		os.Exit(1)
	}
	fmt.Println("POSTFAULT RECOVERY VERIFIED: signed cross-authority continuity contract satisfied")
}

func run(args []string) error {
	flags := flag.NewFlagSet("acp-postfault-verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "", "externally signed recovery bundle")
	expectedPath := flags.String("expected", "", "independent ACP/Runtime same-Run and injected-fault binding")
	trustDir := flags.String("trust-dir", "", "out-of-band trusted authority public keys")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 ||
		*bundlePath == "" || *expectedPath == "" || *trustDir == "" {
		return errors.New("requires --bundle, --expected and --trust-dir; absence is not a PASS")
	}
	data, err := privateBoundedInput(*bundlePath)
	if err != nil || len(data) > maxBundleBytes {
		return errors.New("no bounded external postfault bundle available")
	}
	var bundle postfault.Bundle
	if !postfault.StrictDecode(data, &bundle) {
		return errors.New("postfault bundle is invalid")
	}
	bindingBytes, err := privateBoundedInput(*expectedPath)
	if err != nil || len(bindingBytes) > 4096 {
		return errors.New("independent authoritative Run/fault binding unavailable")
	}
	var expected expectedBinding
	if !postfault.StrictDecode(bindingBytes, &expected) ||
		expected.Schema != expectedBindingVersion || expected.FaultID == "" || expected.FaultAt.IsZero() {
		return errors.New("independent authoritative Run/fault binding is invalid")
	}
	if err := matchesExpected(bundle, expected); err != nil {
		return err
	}
	keys := make(map[string]ed25519.PublicKey, 4)
	for _, authority := range []string{"runtime", "sandbox", "agentd", "guard"} {
		path := filepath.Join(*trustDir, authority+".pub")
		publicKey, err := privateBoundedInput(path)
		if err != nil || len(publicKey) > 128 {
			return fmt.Errorf("missing independently configured %s trust key", authority)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(string(publicKey)))
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid independently configured %s trust key", authority)
		}
		keys[authority] = ed25519.PublicKey(raw)
	}
	if err := postfault.Verify(bundle, keys, time.Now().UTC()); err != nil {
		return err
	}
	return nil
}

func privateBoundedInput(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 ||
		info.Size() > maxBundleBytes {
		return nil, errors.New("required input file unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("required input file unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return nil, errors.New("required input file changed or is unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBundleBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxBundleBytes {
		return nil, errors.New("required input file invalid")
	}
	return raw, nil
}
