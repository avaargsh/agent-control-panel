package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestGoalTopLevelHelpListsCommandsWithoutExecution(t *testing.T) {
	for _, arg := range []string{"--help", "-h", "help"} {
		t.Run(arg, func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			if err := run([]string{arg}, strings.NewReader(""), &out, &diagnostics); err != nil {
				t.Fatalf("top-level help failed: %v", err)
			}
			for _, command := range []string{"prepare", "snapshot", "inspect", "submit", "status"} {
				if !strings.Contains(diagnostics.String(), command) {
					t.Errorf("help missing %s: %s", command, diagnostics.String())
				}
			}
			if out.Len() != 0 {
				t.Fatalf("help must not produce a proposal or receipt: %s", out.String())
			}
		})
	}
}

func TestGoalTopLevelInvalidCommandShowsCompleteUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"unknown"}, {"--help", "submit"}} {
		var out, diagnostics bytes.Buffer
		err := run(args, strings.NewReader(""), &out, &diagnostics)
		if err == nil || out.Len() != 0 {
			t.Fatalf("invalid command accepted: %v, %s", args, out.String())
		}
		for _, command := range []string{"prepare", "snapshot", "inspect", "submit", "status"} {
			if !strings.Contains(err.Error(), command) {
				t.Errorf("usage missing %s: %v", command, err)
			}
		}
	}
}

func TestGoalTopLevelHelpIncludesRequiredArguments(t *testing.T) {
	var out, diagnostics bytes.Buffer
	if err := run([]string{"--help"}, strings.NewReader(""), &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	for _, synopsis := range []string{
		"prepare --file PATH",
		"snapshot --issue-url URL",
		"inspect --file PATH",
		"submit --file PATH --url URL --token-file PATH --ca-file PATH",
		"status --file PATH --url URL --token-file PATH --ca-file PATH",
		"[--hold-record PATH]",
	} {
		if !strings.Contains(diagnostics.String(), synopsis) {
			t.Errorf("help missing synopsis %q", synopsis)
		}
	}
	if out.Len() != 0 {
		t.Fatal("help must not emit a JSON result")
	}
}
