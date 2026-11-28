package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMigrateRejectsInvalidSecretBeforeConnecting(t *testing.T) {
	for _, value := range []string{"", "not-a-password", strings.Repeat("a", 65), strings.Repeat("a", 64) + "\n\n"} {
		secret := filepath.Join(t.TempDir(), "password")
		if err := os.WriteFile(secret, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		err := migrate(context.Background(), "127.0.0.1:1", secret)
		if err == nil || !strings.Contains(err.Error(), "invalid development database password file") {
			t.Fatalf("expected rejection before connecting, got %v", err)
		}
	}
}
