package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/httpapi"
)

// version, commit, buildDate, and modified are optional link-time overrides:
//
//	go build -ldflags "-X main.version= -X main.commit= -X main.buildDate= -X main.modified="
//
// Empty version prints as devel. Empty commit, build date, and modified fall
// back to runtime/debug.ReadBuildInfo settings vcs.revision, vcs.time, and
// vcs.modified, or print as unknown.
var (
	version   string
	commit    string
	buildDate string
	modified  string
)

const usagePreamble = `Usage of agent-control-panel:
  agent-control-panel [-version]

With no flags, the process listens on LISTEN_ADDR (default 127.0.0.1:8080).
-h and -help print this usage and exit.

`

// run owns service admission and shutdown. Domain API writes will only be
// admitted once a durable store and authorization boundary are integrated.
func run(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	var ready atomic.Bool
	srv := &http.Server{
		Handler:           httpapi.Handler(&ready),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	stopped := make(chan error, 1)
	ready.Store(true)
	slog.Info("control plane listening", "addr", ln.Addr().String())
	go func() { stopped <- srv.Serve(ln) }()
	select {
	case err := <-stopped:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		ready.Store(false)
		drain, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(drain); err != nil {
			_ = srv.Close()
			return err
		}
		return nil
	}
}

// execute parses CLI flags. It does not read the environment, open a socket,
// or load credentials. serve is true only when the caller should start the
// listener. Help and version write to stdout and return exit code 0. Invalid
// flags write the error and usage to stderr and return exit code 2.
func execute(args []string, stdout, stderr io.Writer) (exitCode int, serve bool) {
	var parsed bytes.Buffer
	flags, showVersion := newFlagSet(&parsed)
	err := flags.Parse(args)
	if err != nil {
		target := stderr
		code := 2
		if errors.Is(err, flag.ErrHelp) {
			target = stdout
			code = 0
		}
		if _, copyErr := io.Copy(target, &parsed); copyErr != nil {
			return 1, false
		}
		return code, false
	}
	if flags.NArg() > 0 {
		fmt.Fprintf(stderr, "unexpected argument: %s\n", flags.Arg(0))
		flags.SetOutput(stderr)
		flags.Usage()
		return 2, false
	}
	if *showVersion {
		if _, err := fmt.Fprint(stdout, currentVersion()); err != nil {
			return 1, false
		}
		return 0, false
	}
	return 0, true
}

func newFlagSet(w io.Writer) (*flag.FlagSet, *bool) {
	flags := flag.NewFlagSet("agent-control-panel", flag.ContinueOnError)
	flags.SetOutput(w)
	showVersion := flags.Bool("version", false, "print version, commit, build date, and modified state, then exit")
	flags.Usage = func() {
		fmt.Fprint(flags.Output(), usagePreamble)
		flags.PrintDefaults()
	}
	return flags, showVersion
}

func currentVersion() string {
	info, ok := debug.ReadBuildInfo()
	ver, rev, built, mod := resolveBuild(version, commit, buildDate, modified, info, ok)
	return fmt.Sprintf("agent-control-panel version %s\ncommit: %s\nbuild date: %s\nmodified: %s\n", ver, rev, built, mod)
}

func resolveBuild(linkVersion, linkCommit, linkDate, linkModified string, info *debug.BuildInfo, ok bool) (ver, rev, built, mod string) {
	ver, rev, built, mod = linkVersion, linkCommit, linkDate, linkModified
	if ok && info != nil {
		for _, setting := range info.Settings {
			switch setting.Key {
			case "vcs.revision":
				if rev == "" {
					rev = setting.Value
				}
			case "vcs.time":
				if built == "" {
					built = setting.Value
				}
			case "vcs.modified":
				if mod == "" {
					mod = setting.Value
				}
			}
		}
	}
	if ver == "" || ver == "(devel)" {
		ver = "devel"
	}
	if rev == "" {
		rev = "unknown"
	}
	if built == "" {
		built = "unknown"
	}
	if mod == "" {
		mod = "unknown"
	}
	return ver, rev, built, mod
}

func main() {
	// Flags are handled before any environment read or socket so -version,
	// -help, and unknown flags neither bind a port nor load credentials.
	if code, serve := execute(os.Args[1:], os.Stdout, os.Stderr); !serve {
		os.Exit(code)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	if err := run(ctx, addr); err != nil {
		slog.Error("control plane stopped", "error", err)
		os.Exit(1)
	}
}
