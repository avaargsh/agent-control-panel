// Command acp-authority-api serves the bounded internal execution authority.
// The migration job owns DDL; this executable must use a dedicated read-only
// data-access role and never receives OAuth access tokens or agent credentials.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/authorityhttp"
	runpg "github.com/avaargsh/agent-control-panel/internal/runintent/postgres"
	"github.com/jackc/pgx/v5/pgxpool"
)

type config struct {
	dsn, cert, key, ca, peer, tenant, address string
	releaseDirectory, publicationKey          string
}

func readConfig(getenv func(string) string) (config, error) {
	c := config{
		dsn: getenv("ACP_AUTHORITY_DATABASE_URL"), cert: getenv("ACP_AUTHORITY_TLS_CERT"),
		key: getenv("ACP_AUTHORITY_TLS_KEY"), ca: getenv("ACP_AUTHORITY_CLIENT_CA"),
		peer: getenv("ACP_AUTHORITY_PEER_SPIFFE_ID"), tenant: getenv("ACP_AUTHORITY_TENANT"),
		address:          getenv("ACP_AUTHORITY_LISTEN_ADDR"),
		releaseDirectory: getenv("ACP_AUTHORITY_RELEASE_DIRECTORY"), publicationKey: getenv("ACP_AUTHORITY_PUBLICATION_KEY"),
	}
	if c.dsn == "" || c.cert == "" || c.key == "" || c.ca == "" || c.peer == "" || c.tenant == "" {
		return config{}, errors.New("database, mTLS trust and tenant configuration required")
	}
	if (c.releaseDirectory == "") != (c.publicationKey == "") {
		return config{}, errors.New("publication requires both release artifacts and signing key")
	}
	if c.address == "" {
		c.address = "127.0.0.1:8444"
	}
	return c, nil
}

func serve(ctx context.Context, c config) error {
	certificate, err := tls.LoadX509KeyPair(c.cert, c.key)
	if err != nil {
		return errors.New("authority server key pair unavailable")
	}
	pem, err := os.ReadFile(c.ca)
	if err != nil {
		return errors.New("authority client CA unavailable")
	}
	cas := x509.NewCertPool()
	if !cas.AppendCertsFromPEM(pem) {
		return errors.New("invalid authority client CA")
	}
	cfg, err := pgxpool.ParseConfig(c.dsn)
	if err != nil {
		return errors.New("invalid authority database configuration")
	}
	// Defense in depth; production must also enforce DB role restrictions.
	cfg.ConnConfig.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.MaxConns = 8
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return errors.New("authority database unavailable")
	}
	defer pool.Close()
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	err = pool.Ping(pingCtx)
	cancel()
	if err != nil {
		return errors.New("authority database unavailable")
	}
	if err := verifyAuthorityDatabaseRole(ctx, pool); err != nil {
		return err
	}
	repo := runpg.New(pool)
	var handler http.Handler
	if c.publicationKey != "" {
		file, err := os.Open(c.publicationKey)
		if err != nil {
			return errors.New("publication signing key unavailable")
		}
		seed, err := io.ReadAll(io.LimitReader(file, ed25519.SeedSize+1))
		_ = file.Close()
		if err != nil || len(seed) != ed25519.SeedSize {
			return errors.New("invalid publication signing seed")
		}
		privateKey := ed25519.NewKeyFromSeed(seed)
		clear(seed)
		publisher, err := authorityhttp.NewPublisher(c.releaseDirectory, privateKey)
		clear(privateKey)
		if err != nil {
			return err
		}
		defer publisher.Close()
		handler, err = authorityhttp.NewPublicationHandler(repo, publisher, c.peer, c.tenant)
		if err != nil {
			return err
		}
	} else {
		handler, err = authorityhttp.NewHandler(repo, c.peer, c.tenant)
		if err != nil {
			return err
		}
	}
	srv := &http.Server{
		Addr: c.address, Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert,
			ClientCAs: cas, Certificates: []tls.Certificate{certificate},
		},
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8192,
	}
	errs := make(chan error, 1)
	go func() { errs <- srv.ListenAndServeTLS("", "") }()
	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
			return err
		}
		<-errs
		return nil
	}
}

func main() {
	c, err := readConfig(os.Getenv)
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer cancel()
	if err := serve(ctx, c); err != nil {
		log.Fatal("ACP authority service stopped")
	}
}
