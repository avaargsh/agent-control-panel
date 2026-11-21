// Command acp-postfault-verify enforces the non-production full Golden Path
// proof boundary. It is read-only and never issues a Guard Permit, executes
// a command, starts a Workflow or writes a RunIntent.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
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
	trustDir := flags.String("trust-dir", "", "out-of-band trusted authority public keys")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 ||
		*bundlePath == "" || *trustDir == "" {
		return errors.New("requires --bundle and --trust-dir; absence is not a PASS")
	}
	data, err := privateBoundedInput(*bundlePath)
	if err != nil || len(data) > maxBundleBytes {
		return errors.New("no bounded external postfault bundle available")
	}
	var bundle postfault.Bundle
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&bundle) != nil || decoder.Decode(new(any)) != io.EOF {
		return errors.New("postfault bundle is invalid")
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
	if err != nil { return nil, errors.New("required input file unavailable") }
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
