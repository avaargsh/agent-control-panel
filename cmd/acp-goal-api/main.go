// Command acp-goal-api is an opt-in, loopback-only, non-dispatch ACP
// GitHub Issue Goal admission endpoint. It must never start a Runtime Run,
// execute a tool or create a GitHub PR.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/admission"
	"github.com/avaargsh/agent-control-panel/internal/goalhttp"
	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

type config struct {
	listenAddress  string
	certFile       string
	keyFile        string
	dsnFile        string
	oauthCAFile    string
	oauthEndpoint  string
	oauthIssuer    string
	oauthAudience  string
	oauthClientID  string
	oauthSecretFile string
	policy        admission.TrustedGitHubIssuePolicy
}

func readConfig(getenv func(string) string) (config, error) {
	must := func(key string) (string, error) {
		s := getenv(key)
		if s == "" || strings.TrimSpace(s) != s || len(s) > 4096 {
			return "", fmt.Errorf("missing or invalid required setting %s", key)
		}
		return s, nil
	}
	c := config{}
	fields := []struct {
		key string
		dst *string
	}{
		{"ACP_GOAL_LISTEN_ADDR", &c.listenAddress},
		{"ACP_GOAL_TLS_CERT_FILE", &c.certFile},
		{"ACP_GOAL_TLS_KEY_FILE", &c.keyFile},
		{"ACP_GOAL_PG_DSN_FILE", &c.dsnFile},
		{"ACP_GOAL_OAUTH_CA_FILE", &c.oauthCAFile},
		{"ACP_GOAL_OAUTH_ENDPOINT", &c.oauthEndpoint},
		{"ACP_GOAL_OAUTH_ISSUER", &c.oauthIssuer},
		{"ACP_GOAL_OAUTH_AUDIENCE", &c.oauthAudience},
		{"ACP_GOAL_OAUTH_CLIENT_ID", &c.oauthClientID},
		{"ACP_GOAL_OAUTH_CLIENT_SECRET_FILE", &c.oauthSecretFile},
		{"ACP_GOAL_TENANT_ID", &c.policy.Target.TenantID},
		{"ACP_GOAL_PROJECT_ID", &c.policy.Target.ProjectID},
		{"ACP_GOAL_AGENT_ID", &c.policy.Target.AgentID},
		{"ACP_GOAL_RELEASE_ID", &c.policy.Target.ReleaseID},
		{"ACP_GOAL_SESSION_ID", &c.policy.Target.SessionID},
		{"ACP_GOAL_GITHUB_REPOSITORY", &c.policy.Repository},
		{"ACP_GOAL_TARGET_BRANCH", &c.policy.TargetBranch},
		{"ACP_GOAL_RULES_DIGEST", &c.policy.AcceptanceRulesDigest},
	}
	for _, field := range fields {
		value, err := must(field.key)
		if err != nil {
			return config{}, err
		}
		*field.dst = value
	}
	host, port, err := net.SplitHostPort(c.listenAddress)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return config{}, errors.New("Goal API must explicitly bind a loopback IP address")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return config{}, errors.New("Goal API listen port must be 1..65535")
	}
	for _, raw := range []string{c.oauthEndpoint, c.oauthIssuer} {
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil ||
			u.Fragment != "" || u.RawQuery != "" || u.String() != raw {
			return config{}, errors.New("OAuth issuer and introspection endpoint must be fixed HTTPS URLs")
		}
	}
	if issuegoal.ValidateIssueURL("https://github.com/"+c.policy.Repository+"/issues/1") != nil ||
		issuegoal.ValidateTargetBranch(c.policy.TargetBranch) != nil ||
		len(c.policy.AcceptanceRulesDigest) != len("sha256:")+64 ||
		!strings.HasPrefix(c.policy.AcceptanceRulesDigest, "sha256:") {
		return config{}, errors.New("invalid trusted GitHub source scope")
	}
	for _, ch := range c.policy.AcceptanceRulesDigest[len("sha256:"):] {
		if !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'f') {
			return config{}, errors.New("invalid acceptance rules digest")
		}
	}
	budgetKeys := []struct {
		key string
		dst *int64
		max int64
	}{
		{"ACP_GOAL_MAX_TOKENS", &c.policy.MaxBudget.MaxTokens, 10_000_000},
		{"ACP_GOAL_MAX_RUNTIME_SECONDS", &c.policy.MaxBudget.MaxRuntimeSeconds, 86_400},
		{"ACP_GOAL_MAX_SANDBOX_SECONDS", &c.policy.MaxBudget.MaxSandboxSeconds, 86_400},
	}
	for _, budget := range budgetKeys {
		raw, err := must(budget.key)
		if err != nil {
			return config{}, err
		}
		number, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || number <= 0 || number > budget.max {
			return config{}, fmt.Errorf("invalid upper budget for %s", budget.key)
		}
		*budget.dst = number
	}
	if c.policy.MaxBudget.MaxSandboxSeconds > c.policy.MaxBudget.MaxRuntimeSeconds {
		return config{}, errors.New("sandbox budget cannot exceed runtime budget")
	}
	switch getenv("ACP_GOAL_ALLOW_UNPROTECTED_TEST_BRANCH") {
	case "":
		c.policy.RequireProtectedBranch = true
	case "true":
		c.policy.RequireProtectedBranch = false
	default:
		return config{}, errors.New("unprotected test branch requires an explicit true override")
	}
	return c, nil
}

// Read secret bytes only from owner-private regular files; never log the
// content. This deliberately refuses convenient world-readable config files.
func readSecretFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Size() == 0 || info.Size() > 1<<16 {
		return "", errors.New("required private credential file is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("required private credential file is unavailable")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<16+1))
	if err != nil || len(data) == 0 || len(data) > 1<<16 {
		return "", errors.New("required credential bytes are unavailable")
	}
	value := strings.TrimRight(string(data), "\r\n")
	if value == "" || strings.ContainsAny(value, "\r\n\x00") {
		return "", errors.New("invalid credential bytes")
	}
	return value, nil
}

func serve(ctx context.Context, c config) error {
	certificate, err := tls.LoadX509KeyPair(c.certFile, c.keyFile)
	if err != nil {
		return errors.New("Goal API TLS key pair unavailable")
	}
	caPEM, err := os.ReadFile(c.oauthCAFile)
	if err != nil {
		return errors.New("OAuth trust bundle unavailable")
	}
	cas := x509.NewCertPool()
	if !cas.AppendCertsFromPEM(caPEM) {
		return errors.New("invalid OAuth trust bundle")
	}
	oauthSecret, err := readSecretFile(c.oauthSecretFile)
	if err != nil {
		return err
	}
	defer func() { oauthSecret = "" }()
	auth, err := admission.NewIntrospector(admission.IntrospectionConfig{
		Endpoint: c.oauthEndpoint, Issuer: c.oauthIssuer,
		Audience: c.oauthAudience, ClientID: c.oauthClientID,
		ClientSecret: oauthSecret,
		HTTPClient: &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: cas, MinVersion: tls.VersionTLS12},
		}},
	})
	if err != nil {
		return errors.New("invalid trusted OAuth introspection configuration")
	}
	dsn, err := readSecretFile(c.dsnFile)
	if err != nil {
		return err
	}
	pgConfig, err := pgxpool.ParseConfig(dsn)
	dsn = ""
	if err != nil {
		return errors.New("invalid PostgreSQL connection configuration")
	}
	// A remote database must use full server-certificate hostname
	// verification; loopback/Unix socket is permitted for isolated demos.
	dbHost := pgConfig.ConnConfig.Host
	local := dbHost == "localhost" || dbHost == "127.0.0.1" ||
		dbHost == "::1" || strings.HasPrefix(dbHost, "/")
	if !local && (pgConfig.ConnConfig.TLSConfig == nil ||
		pgConfig.ConnConfig.TLSConfig.InsecureSkipVerify ||
		pgConfig.ConnConfig.TLSConfig.ServerName == "") {
		return errors.New("remote PostgreSQL must use verified TLS")
	}
	pgConfig.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, pgConfig)
	if err != nil {
		return errors.New("PostgreSQL connection configuration rejected")
	}
	defer pool.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = pool.Ping(pingCtx)
	cancel()
	if err != nil {
		return errors.New("PostgreSQL authority unavailable")
	}
	// This binary is not a migration runner or a schema owner. Fail closed
	// if the production migration job has not prepared ACP authority tables.
	var ready bool
	if err := pool.QueryRow(ctx, `SELECT
		to_regclass('run_intents') IS NOT NULL AND
		to_regclass('outbox_events') IS NOT NULL AND
		to_regclass('admission_tenants') IS NOT NULL AND
		to_regclass('admission_memberships') IS NOT NULL`).Scan(&ready); err != nil || !ready {
		return errors.New("ACP authority schema missing")
	}
	repo := runpg.New(pool)
	factory, err := goalhttp.NewCatalogGoalServiceFactory(repo, auth)
	if err != nil {
		return errors.New("Goal admission authority configuration rejected")
	}
	// No caller-configurable outbound GitHub host, credentials or redirect
	// behavior: the existing public Issue reader is read-only and fixed-origin.
	source, err := admission.NewTrustedGitHubIssueVerifier(issuegoal.NewPublicIssueReader(), c.policy)
	if err != nil {
		return errors.New("GitHub source policy configuration rejected")
	}
	handler, err := goalhttp.NewHandler(factory, source)
	if err != nil {
		return errors.New("Goal API handler configuration rejected")
	}
	srv := &http.Server{
		Addr: c.listenAddress, Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{certificate},
		},
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 60 * time.Second, IdleTimeout: 15 * time.Second,
		MaxHeaderBytes: 8192,
	}
	listener, err := tls.Listen("tcp", c.listenAddress, srv.TLSConfig)
	if err != nil {
		return errors.New("Goal API TLS loopback listener unavailable")
	}
	done := make(chan error, 1)
	go func() { done <- srv.Serve(listener) }()
	select {
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("Goal API listener exited")
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
			return errors.New("Goal API shutdown failed")
		}
		<-done
		return nil
	}
}

func main() {
	c, err := readConfig(os.Getenv)
	if err != nil {
		log.Fatal("ACP Goal API configuration incomplete or invalid: ", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := serve(ctx, c); err != nil {
		log.Fatal("ACP Goal API unavailable: ", err)
	}
}
