// acp-goal prepares and inspects immutable Issue Goal input, then optionally
// submits it for non-dispatch RunIntent admission over explicit loopback TLS.
// No command dispatches Runtime work, writes GitHub or grants tool effects.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

type issueReader interface {
	Read(context.Context, string) (issuegoal.GitHubIssueSnapshot, error)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	return runWithIssueReader(args, stdin, stdout, stderr, issuegoal.NewPublicIssueReader())
}

func runWithIssueReader(args []string, stdin io.Reader, stdout, stderr io.Writer, reader issueReader) error {
	if len(args) == 0 {
		return errors.New("usage: acp-goal prepare | snapshot | inspect | submit")
	}
	switch args[0] {
	case "prepare":
		return prepare(args, stdin, stdout, stderr)
	case "snapshot":
		return snapshot(args, stdout, stderr, reader)
	case "submit":
		return submit(args, stdin, stdout, stderr)
	case "inspect":
		baselines, ok := reader.(baselineReader)
		if !ok {
			return errors.New("public baseline reader not configured")
		}
		return inspect(args, stdin, stdout, stderr, reader, baselines)
	default:
		return errors.New("usage: acp-goal prepare --file manifest.json | snapshot --issue-url https://github.com/owner/repo/issues/123")
	}
}

func prepare(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("file", "", "Issue Goal manifest path; - reads stdin")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
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

func snapshot(args []string, stdout, stderr io.Writer, reader issueReader) error {
	flags := flag.NewFlagSet("snapshot", flag.ContinueOnError)
	flags.SetOutput(stderr)
	issueURL := flags.String("issue-url", "", "public GitHub Issue HTTPS URL")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || issuegoal.ValidateIssueURL(*issueURL) != nil || reader == nil {
		return errors.New("snapshot requires exactly one valid --issue-url")
	}
	observed, err := reader.Read(context.Background(), *issueURL)
	if err != nil {
		return err
	}
	return json.NewEncoder(stdout).Encode(struct {
		Schema              string `json:"schema"`
		IssueURL            string `json:"issue_url"`
		IssueSnapshotDigest string `json:"issue_snapshot_digest"`
		IssueID             int64  `json:"issue_id"`
		UpdatedAt           string `json:"updated_at"`
	}{
		Schema:              observed.Schema,
		IssueURL:            observed.IssueURL,
		IssueSnapshotDigest: observed.Digest,
		IssueID:             observed.IssueID,
		UpdatedAt:           observed.UpdatedAt,
	})
}

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "acp-goal:", err)
		os.Exit(1)
	}
}
