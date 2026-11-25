package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"testing"
	"time"
)

type listenerLogWriter chan []byte

func (w listenerLogWriter) Write(p []byte) (int, error) {
	select {
	case w <- append([]byte(nil), p...):
	default:
	}
	return len(p), nil
}

func TestRunReportsBoundLoopbackAddress(t *testing.T) {
	logs := make(listenerLogWriter, 8)
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, "127.0.0.1:0") }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("run shutdown: %v", err)
			}
		case <-time.After(20 * time.Second):
			t.Error("run did not shut down")
		}
	})

	var event struct {
		Message string `json:"msg"`
		Address string `json:"addr"`
	}
	select {
	case raw := <-logs:
		if err := json.Unmarshal(raw, &event); err != nil {
			t.Fatalf("decode listener log: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("listener did not report its bound address")
	}
	if event.Message != "control plane listening" {
		t.Fatalf("unexpected listener event: %q", event.Message)
	}
	host, port, err := net.SplitHostPort(event.Address)
	if err != nil || host != "127.0.0.1" || port == "" || port == "0" {
		t.Fatalf("expected allocated loopback address, got %q", event.Address)
	}

	client := &http.Client{Timeout: 5 * time.Second}
	for _, tc := range []struct {
		path string
		want string
	}{
		{"/livez", "ok\n"},
		{"/readyz", "ready\n"},
		{"/api/v1/meta", ""},
	} {
		t.Run(tc.path, func(t *testing.T) {
			resp, err := client.Get("http://" + event.Address + tc.path)
			if err != nil {
				t.Fatalf("reported address was not reachable: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
			}
			if tc.path == "/api/v1/meta" {
				var meta struct {
					Service    string `json:"service"`
					APIVersion string `json:"api_version"`
				}
				if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
					t.Fatalf("decode metadata: %v", err)
				}
				if meta.Service != "agent-control-panel" || meta.APIVersion != "v1" {
					t.Fatalf("unexpected metadata: %+v", meta)
				}
				return
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response: %v", err)
			}
			if string(body) != tc.want {
				t.Fatalf("body = %q, want %q", body, tc.want)
			}
		})
	}
}
