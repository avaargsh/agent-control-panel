package main

import (
	"strings"
	"testing"
)

func TestStandaloneHelpIsNotVerification(t *testing.T) {
	for _, arg := range []string{"--help", "-h"} {
		t.Run(arg, func(t *testing.T) {
			err := run([]string{arg})
			if err == nil {
				t.Fatal("help unexpectedly returned a verification success")
			}
			for _, field := range []string{"Usage of acp-evidence-verify", "-package", "-expected", "-trust-dir", "-archive-seal", "-archive-pub", "-require-linked"} {
				if !strings.Contains(err.Error(), field) {
					t.Errorf("expected help to include %q: %v", field, err)
				}
			}
		})
	}
}
