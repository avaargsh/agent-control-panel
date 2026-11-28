package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
	"time"
)

func TestExecuteNoFlagsStartsListenerPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code, serve := execute(nil, &stdout, &stderr)
	if code != 0 || !serve {
		t.Fatalf("code=%d serve=%v, want 0 and serve", code, serve)
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestHelpExitsZeroWithoutServing(t *testing.T) {
	for _, arg := range []string{"-h", "-help", "--help"} {
		t.Run(arg, func(t *testing.T) {
			stdout, stderr, code, serve := runExecute(t, []string{arg})
			if code != 0 || serve {
				t.Fatalf("code=%d serve=%v, want 0 and no listener", code, serve)
			}
			if stderr != "" {
				t.Fatalf("help wrote stderr: %q", stderr)
			}
			for _, want := range []string{"Usage of agent-control-panel", "-version", "LISTEN_ADDR", "127.0.0.1:8080"} {
				if !strings.Contains(stdout, want) {
					t.Errorf("usage missing %q: %q", want, stdout)
				}
			}
		})
	}
}

func TestVersionFlagPrintsResolvedBuildWithoutServing(t *testing.T) {
	t.Setenv("LISTEN_ADDR", "192.0.2.1:9")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "sentinel-secret")
	t.Setenv("PGTEST_DSN", "postgres://sentinel@127.0.0.1/nope")

	for _, arg := range []string{"-version", "--version"} {
		t.Run(arg, func(t *testing.T) {
			stdout, stderr, code, serve := runExecute(t, []string{arg})
			if code != 0 || serve {
				t.Fatalf("code=%d serve=%v, want 0 and no listener", code, serve)
			}
			if stderr != "" {
				t.Fatalf("version wrote stderr: %q", stderr)
			}
			if stdout != currentVersion() {
				t.Fatalf("stdout=%q want %q", stdout, currentVersion())
			}
			for _, secret := range []string{"sentinel-secret", "192.0.2.1", "postgres://sentinel"} {
				if strings.Contains(stdout, secret) {
					t.Fatalf("version output included environment value %q: %q", secret, stdout)
				}
			}
		})
	}
}

func TestVersionFlagUsesLinkOverrides(t *testing.T) {
	withLinkValues(t, "v9.9.9-test", "abc123", "2026-11-28T00:00:00Z", "false")
	stdout, stderr, code, serve := runExecute(t, []string{"-version"})
	if code != 0 || serve || stderr != "" {
		t.Fatalf("code=%d serve=%v stderr=%q", code, serve, stderr)
	}
	const want = "agent-control-panel version v9.9.9-test\ncommit: abc123\nbuild date: 2026-11-28T00:00:00Z\nmodified: false\n"
	if stdout != want {
		t.Fatalf("stdout=%q", stdout)
	}
}

func TestInvalidFlagsPrintUsageOnStderr(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{name: "unknown", args: []string{"-not-a-flag"}, want: "flag provided but not defined: -not-a-flag"},
		{name: "bad boolean", args: []string{"-version=nope"}, want: "invalid boolean value"},
		{name: "positional", args: []string{"extra"}, want: "unexpected argument: extra"},
		{name: "version with positional", args: []string{"-version", "extra"}, want: "unexpected argument: extra"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LISTEN_ADDR", "127.0.0.1:1")
			stdout, stderr, code, serve := runExecute(t, tc.args)
			if code == 0 || serve {
				t.Fatalf("code=%d serve=%v, want non-zero and no listener", code, serve)
			}
			if code != 2 {
				t.Fatalf("code=%d, want 2", code)
			}
			if stdout != "" {
				t.Fatalf("stdout=%q", stdout)
			}
			if !strings.Contains(stderr, tc.want) || !strings.Contains(stderr, "Usage of agent-control-panel") {
				t.Fatalf("stderr=%q", stderr)
			}
			if strings.Contains(stderr, "control plane listening") {
				t.Fatalf("listener started: %q", stderr)
			}
		})
	}
}

func TestResolveBuild(t *testing.T) {
	vcs := &debug.BuildInfo{
		Main: debug.Module{Version: "(devel)"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "deadbeef"},
			{Key: "vcs.time", Value: "2026-01-02T03:04:05Z"},
			{Key: "vcs.modified", Value: "true"},
			{Key: "GOARCH", Value: "amd64"},
		},
	}
	cases := []struct {
		name                       string
		version, commit, date, mod string
		info                       *debug.BuildInfo
		ok                         bool
		wantVer, wantRev           string
		wantDate, wantMod          string
	}{
		{
			name:    "no build info",
			wantVer: "devel", wantRev: "unknown", wantDate: "unknown", wantMod: "unknown",
		},
		{
			name: "vcs settings and devel version",
			info: vcs, ok: true,
			wantVer: "devel", wantRev: "deadbeef", wantDate: "2026-01-02T03:04:05Z", wantMod: "true",
		},
		{
			name: "module pseudo-version is not the printed version",
			info: &debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20261125080459-60065bd1b962+dirty"}}, ok: true,
			wantVer: "devel", wantRev: "unknown", wantDate: "unknown", wantMod: "unknown",
		},
		{
			name:    "link overrides beat build info",
			version: "v9", commit: "abc", date: "then", mod: "false",
			info: vcs, ok: true,
			wantVer: "v9", wantRev: "abc", wantDate: "then", wantMod: "false",
		},
		{
			name:   "partial link override keeps other vcs values",
			commit: "abc",
			info:   vcs, ok: true,
			wantVer: "devel", wantRev: "abc", wantDate: "2026-01-02T03:04:05Z", wantMod: "true",
		},
		{
			name: "info ignored when unavailable",
			info: vcs, ok: false,
			wantVer: "devel", wantRev: "unknown", wantDate: "unknown", wantMod: "unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotVer, gotRev, gotDate, gotMod := resolveBuild(tc.version, tc.commit, tc.date, tc.mod, tc.info, tc.ok)
			if gotVer != tc.wantVer || gotRev != tc.wantRev || gotDate != tc.wantDate || gotMod != tc.wantMod {
				t.Fatalf("got %s %s %s %s, want %s %s %s %s", gotVer, gotRev, gotDate, gotMod, tc.wantVer, tc.wantRev, tc.wantDate, tc.wantMod)
			}
		})
	}
}

func TestBuiltBinaryFlagsDoNotListen(t *testing.T) {
	bin := buildTestBinary(t, "-X main.version=v0.1.0 -X main.commit=abc123 -X main.buildDate=2026-11-28T00:00:00Z -X main.modified=false")
	env := []string{
		"LISTEN_ADDR=127.0.0.1:1",
		"AWS_SECRET_ACCESS_KEY=sentinel-secret",
		"PGTEST_DSN=postgres://sentinel@127.0.0.1/nope",
	}
	t.Run("version", func(t *testing.T) {
		stdout, stderr, code := runBinary(t, bin, []string{"-version"}, env)
		if code != 0 {
			t.Fatalf("code=%d stderr=%q", code, stderr)
		}
		const want = "agent-control-panel version v0.1.0\ncommit: abc123\nbuild date: 2026-11-28T00:00:00Z\nmodified: false\n"
		if stdout != want {
			t.Fatalf("stdout=%q", stdout)
		}
		if strings.Contains(stdout+stderr, "sentinel") || strings.Contains(stderr, "control plane listening") {
			t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
		}
	})
	t.Run("help", func(t *testing.T) {
		stdout, stderr, code := runBinary(t, bin, []string{"-help"}, env)
		if code != 0 || stderr != "" || !strings.Contains(stdout, "Usage of agent-control-panel") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		stdout, stderr, code := runBinary(t, bin, []string{"-not-a-flag"}, env)
		if code != 2 || stdout != "" || !strings.Contains(stderr, "Usage of agent-control-panel") {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
		}
		if strings.Contains(stderr, "control plane listening") {
			t.Fatalf("listener started: %q", stderr)
		}
	})
}

func runExecute(t *testing.T, args []string) (stdout, stderr string, code int, serve bool) {
	t.Helper()
	var outBuf, errBuf bytes.Buffer
	code, serve = execute(args, &outBuf, &errBuf)
	return outBuf.String(), errBuf.String(), code, serve
}

func withLinkValues(t *testing.T, ver, rev, date, mod string) {
	t.Helper()
	prev := [4]string{version, commit, buildDate, modified}
	version, commit, buildDate, modified = ver, rev, date, mod
	t.Cleanup(func() {
		version, commit, buildDate, modified = prev[0], prev[1], prev[2], prev[3]
	})
}

func buildTestBinary(t *testing.T, ldflags string) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate package directory")
	}
	bin := filepath.Join(t.TempDir(), "agent-control-panel")
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	cmd := exec.Command(goBin, "build", "-buildvcs=false", "-ldflags", ldflags, "-o", bin, ".")
	cmd.Dir = filepath.Dir(file)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func runBinary(t *testing.T, bin string, args, env []string) (stdout, stderr string, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf
	err := cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		t.Fatalf("command hung; listener may have started: %v", err)
	}
	if err != nil {
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) {
			t.Fatalf("run: %v\nstderr: %s", err, errBuf.String())
		}
		code = exitErr.ExitCode()
	}
	return outBuf.String(), errBuf.String(), code
}

func TestCurrentVersionMatchesResolveBuild(t *testing.T) {
	withLinkValues(t, "", "", "", "")
	info, ok := debug.ReadBuildInfo()
	ver, rev, built, mod := resolveBuild(version, commit, buildDate, modified, info, ok)
	want := fmt.Sprintf("agent-control-panel version %s\ncommit: %s\nbuild date: %s\nmodified: %s\n", ver, rev, built, mod)
	if got := currentVersion(); got != want {
		t.Fatalf("currentVersion=%q want %q", got, want)
	}
}
