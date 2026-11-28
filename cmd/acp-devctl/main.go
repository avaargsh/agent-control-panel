// Command acp-devctl initializes and probes the isolated Compose development stack.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

var devPassword = regexp.MustCompile(`^[a-f0-9]{64}$`)

func migrate(ctx context.Context, address, secretFile string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" || secretFile == "" {
		return errors.New("development database address and password file required")
	}
	file, err := os.Open(secretFile)
	if err != nil {
		return errors.New("development database password file unavailable")
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 66))
	password := strings.TrimSuffix(string(raw), "\n")
	if err != nil || !devPassword.MatchString(password) {
		return errors.New("invalid development database password file; run deploy/dev/init.sh")
	}
	dsn := url.URL{Scheme: "postgres", User: url.UserPassword("acp_dev", password), Host: address, Path: "/acp_dev", RawQuery: "sslmode=disable"}
	config, err := pgxpool.ParseConfig(dsn.String())
	if err != nil {
		return errors.New("invalid development database configuration")
	}
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return errors.New("development database unavailable")
	}
	defer pool.Close()
	return runpg.Migrate(ctx, pool)
}

func probe(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8080/readyz", nil)
	if err != nil {
		return err
	}
	client := &http.Client{Transport: &http.Transport{}, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 16))
	if err != nil || resp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ready" {
		return errors.New("operations service is not ready")
	}
	return nil
}

func run(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: acp-devctl migrate | probe")
	}
	switch args[0] {
	case "migrate":
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		return migrate(ctx, os.Getenv("ACP_DEV_PG_ADDRESS"), os.Getenv("ACP_DEV_PG_PASSWORD_FILE"))
	case "probe":
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return probe(ctx)
	default:
		return errors.New("usage: acp-devctl migrate | probe")
	}
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "acp-devctl:", err)
		os.Exit(1)
	}
}
