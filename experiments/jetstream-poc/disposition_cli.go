package jetstreampoc

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

var inspectSchemaPattern = regexp.MustCompile("^test_jetstream_[0-9]+$")
var inspectNamePattern = regexp.MustCompile("^[A-Za-z0-9_-]+$")
var inspectSubjectPattern = regexp.MustCompile("^[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)*$")

func inspectLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// RunDispositionInspectCLI is a local POC diagnostic entry point. It accepts
// only numeric loopback endpoints and an explicitly named disposable schema.
// Errors are deliberately generic so credentials and broker payloads are not
// copied to command output. Exit 0 means observation succeeded, NOT approval.
func RunDispositionInspectCLI(parent context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("disposition-inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var cfg Config
	var sequence int64
	flags.StringVar(&cfg.SourceStream, "source-stream", "", "source stream")
	flags.StringVar(&cfg.SourceConsumer, "source-consumer", "", "durable consumer")
	flags.StringVar(&cfg.DLQStream, "dlq-stream", "", "expected DLQ stream")
	flags.StringVar(&cfg.DLQSubject, "dlq-subject", "", "expected DLQ subject prefix")
	flags.Int64Var(&sequence, "sequence", 0, "source stream sequence")
	if err := flags.Parse(args); err == flag.ErrHelp {
		fmt.Fprintln(stdout, "Usage: disposition-inspect -source-stream NAME -source-consumer NAME -dlq-stream NAME -dlq-subject PREFIX -sequence N")
		fmt.Fprintln(stdout, "Environment: PGTEST_DSN, NATS_POC_URL, ACP_POC_SCHEMA (test_jetstream_<digits>). Local disposable fixtures only.")
		return 0
	} else if err != nil || flags.NArg() != 0 ||
		!inspectNamePattern.MatchString(cfg.SourceStream) || !inspectNamePattern.MatchString(cfg.SourceConsumer) ||
		!inspectNamePattern.MatchString(cfg.DLQStream) || !inspectSubjectPattern.MatchString(cfg.DLQSubject) || sequence <= 0 {
		fmt.Fprintln(stderr, "invalid diagnostic arguments; use -help")
		return 2
	}
	dsn, brokerURL, schema := getenv("PGTEST_DSN"), getenv("NATS_POC_URL"), getenv("ACP_POC_SCHEMA")
	if dsn == "" || !inspectSchemaPattern.MatchString(schema) {
		fmt.Fprintln(stderr, "explicit disposable database DSN and schema are required")
		return 2
	}
	pg, err := pgxpool.ParseConfig(dsn)
	if err != nil || !inspectLoopback(pg.ConnConfig.Host) {
		fmt.Fprintln(stderr, "invalid local PostgreSQL configuration")
		return 2
	}
	for _, fallback := range pg.ConnConfig.Fallbacks {
		if !inspectLoopback(fallback.Host) {
			fmt.Fprintln(stderr, "non-local PostgreSQL fallback is prohibited")
			return 2
		}
	}
	u, err := url.Parse(brokerURL)
	if err != nil || u.Scheme != "nats" || !inspectLoopback(u.Hostname()) ||
		u.Port() == "" || u.Path != "" || u.RawQuery != "" || u.Fragment != "" || strings.Contains(brokerURL, ",") {
		fmt.Fprintln(stderr, "invalid local NATS configuration")
		return 2
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port <= 0 || port > 65535 {
		fmt.Fprintln(stderr, "invalid local NATS port")
		return 2
	}
	// This is a fresh connection with an explicit schema and server-side
	// read-only transactions. No migration or implicit schema initialization.
	pg.ConnConfig.RuntimeParams = map[string]string{
		"search_path": schema + ",pg_catalog",
		"default_transaction_read_only": "on",
	}
	pg.MaxConns = 1
	pg.MinConns = 0
	pg.MinIdleConns = 0
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, pg)
	if err != nil {
		fmt.Fprintln(stderr, "database connection initialization failed")
		return 1
	}
	defer pool.Close()
	nc, err := nats.Connect(brokerURL, nats.NoReconnect(), nats.Timeout(2*time.Second))
	if err != nil {
		fmt.Fprintln(stderr, "broker connection failed")
		return 1
	}
	defer nc.Close()
	js, err := jetstream.New(nc)
	if err != nil {
		fmt.Fprintln(stderr, "broker client initialization failed")
		return 1
	}
	observation, err := NewDispositionJournal(pool).InspectDisposition(ctx, js, cfg, sequence)
	if err != nil {
		fmt.Fprintln(stderr, "disposition inspection failed; no settlement authorized")
		return 1
	}
	if err := json.NewEncoder(stdout).Encode(observation); err != nil {
		fmt.Fprintln(stderr, "diagnostic output failed")
		return 1
	}
	return 0
}
