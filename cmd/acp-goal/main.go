// acp-goal prepares an immutable Issue Goal input for authenticated admission.
// The prepare command is offline and never submits a Run or creates a PR.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 || args[0] != "prepare" {
		return errors.New("usage: acp-goal prepare --file manifest.json (or --file - for stdin)")
	}
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("file", "", "Issue Goal manifest path; - reads stdin")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if *path == "" || flags.NArg() != 0 {
		return errors.New("prepare requires exactly one --file path")
	}
	var reader io.Reader = stdin
	if *path != "-" {
		file, err := os.Open(*path)
		if err != nil {
			return fmt.Errorf("open manifest: %w", err)
		}
		defer file.Close()
		reader = file
	}
	// Bound untrusted input before decoding. The core parser also enforces
	// the same limit and rejects duplicate keys and unknown fields.
	raw, err := io.ReadAll(io.LimitReader(reader, 32*1024+1))
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	prepared, err := issuegoal.Prepare(raw)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(prepared)
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "acp-goal:", err)
		os.Exit(1)
	}
}
