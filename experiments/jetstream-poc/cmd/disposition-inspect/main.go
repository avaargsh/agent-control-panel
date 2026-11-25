package main

import (
	"context"
	"os"

	jetstreampoc "github.com/avaargsh/agent-control-panel/experiments/jetstream-poc"
)

func main() {
	os.Exit(jetstreampoc.RunDispositionInspectCLI(context.Background(), os.Args[1:], os.Getenv, os.Stdout, os.Stderr))
}
