package jetstreampoc

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDispositionInspectCLIRealEvidence(t *testing.T) {
	_, pool := pocRepository(t)
	js, _, _, cfg := pocNATS(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	record := dispositionRecord{
		stream: cfg.SourceStream, consumer: cfg.SourceConsumer, sequence: 1,
		hash: strings.Repeat("a", 64), reason: "EVENT_ID_CONFLICT",
		dlq: cfg.DLQStream, subject: cfg.DLQSubject + ".cli", evidence: []byte("private diagnostic evidence"),
	}
	j := NewDispositionJournal(pool)
	if _, _, err := j.ensure(ctx, record); err != nil {
		t.Fatal(err)
	}
	if err := j.markPublishAttempt(ctx, record); err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, record.subject, record.evidence); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"PGTEST_DSN": os.Getenv("PGTEST_DSN"), "NATS_POC_URL": os.Getenv("NATS_POC_URL"),
		"ACP_POC_SCHEMA": pool.Config().ConnConfig.RuntimeParams["search_path"],
	}
	args := []string{"-source-stream", cfg.SourceStream, "-source-consumer", cfg.SourceConsumer,
		"-dlq-stream", cfg.DLQStream, "-dlq-subject", cfg.DLQSubject, "-sequence", "1"}
	var stdout, stderr bytes.Buffer
	if code := RunDispositionInspectCLI(ctx, args, func(key string) string { return env[key] }, &stdout, &stderr); code != 0 {
		t.Fatalf("diagnostic exit=%d stderr=%s", code, stderr.String())
	}
	var out DispositionInspection
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil || out.JournalState != "ATTEMPT_UNCONFIRMED" || out.BrokerState != "MATCHING" {
		t.Fatalf("wrong diagnostic: %s err=%v", stdout.String(), err)
	}
	if strings.Contains(stdout.String(), string(record.evidence)) {
		t.Fatal("CLI leaked raw evidence")
	}
	// Exercise the real command in a separate OS process against the same
	// live evidence. Never put credentials in arguments or failure output.
	binary := filepath.Join(t.TempDir(), "disposition-inspect")
	build := exec.CommandContext(ctx, "go", "build", "-mod=readonly", "-race", "-o", binary, "./cmd/disposition-inspect")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build diagnostic executable: %v: %s", err, output)
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, overridden := env[key]; !overridden {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	var binaryOut, binaryErr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &binaryOut, &binaryErr
	if err := cmd.Run(); err != nil {
		t.Fatalf("diagnostic executable failed: %v", err)
	}
	if binaryErr.Len() != 0 || !bytes.Equal(binaryOut.Bytes(), stdout.Bytes()) {
		t.Fatal("executable output differs from verified read-only observation")
	}
	t.Log("JETSTREAM_DISPOSITION_CLI_LIVE_EXEC_PASS")
	var started, published bool
	if err := pool.QueryRow(ctx, "SELECT publish_started,published FROM poc_dlq_dispositions").Scan(&started, &published); err != nil || !started || published {
		t.Fatalf("CLI changed journal state: %t/%t err=%v", started, published, err)
	}
}

func TestDispositionInspectCLIRejectsUnsafeInputs(t *testing.T) {
	ctx := context.Background()
	args := []string{"-source-stream", "SOURCE", "-source-consumer", "CONSUMER",
		"-dlq-stream", "DLQ", "-dlq-subject", "poc.dlq", "-sequence", "1"}
	for i, tc := range []map[string]string{
		{},
		{"PGTEST_DSN": "postgres://postgres:secret@example.invalid/db", "NATS_POC_URL": "nats://127.0.0.1:4222", "ACP_POC_SCHEMA": "test_jetstream_123"},
		{"PGTEST_DSN": "postgres://postgres:secret@127.0.0.1/db", "NATS_POC_URL": "nats://example.invalid:4222", "ACP_POC_SCHEMA": "test_jetstream_123"},
		{"PGTEST_DSN": "postgres://postgres:secret@127.0.0.1/db", "NATS_POC_URL": "nats://127.0.0.1:4222", "ACP_POC_SCHEMA": "public"},
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := RunDispositionInspectCLI(ctx, args, func(key string) string { return tc[key] }, &stdout, &stderr)
			if code != 2 || stdout.Len() != 0 || strings.Contains(stderr.String(), "secret") {
				t.Fatalf("unsafe configuration accepted or leaked credentials: code=%d", code)
			}
		})
	}
}
