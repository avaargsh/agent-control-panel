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

func TestGoalInvalidURLDiagnosticNamesExpectedEndpoint(t *testing.T) {
	for _, tc := range []struct {
		command string
		path    string
	}{
		{"submit", "/api/v1/goals:submit"},
		{"status", "/api/v1/goals:status"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			var out, diagnostics bytes.Buffer
			err := run([]string{tc.command, "--file", "-", "--url", "https://127.0.0.1:443/wrong",
				"--token-file", "unused", "--ca-file", "unused"}, strings.NewReader(""), &out, &diagnostics)
			if err == nil || !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("expected diagnostic naming %s, got %v", tc.path, err)
			}
			if out.Len() != 0 {
				t.Fatal("invalid endpoint must not emit a receipt")
			}
		})
	}
}
