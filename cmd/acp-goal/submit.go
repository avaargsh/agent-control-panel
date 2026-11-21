package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/goalhttp"
	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

const (
	maxGoalReplyBytes  = 4096
	maxCABytes         = 64 << 10
	maxBearerBytes     = 8192
	unknownGoalReceipt = "GoalSubmit acceptance receipt unverifiable; outcome unknown, inspect ACP before retrying"
)

// submit sends only an immutable, already prepared Issue Goal proposal to the
// opt-in loopback TLS host. A 201/200 is RunIntent admission, not execution.
func submit(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("submit", flag.ContinueOnError)
	flags.SetOutput(stderr)
	filePath := flags.String("file", "", "prepared Issue Goal JSON path; - reads stdin")
	endpoint := flags.String("url", "", "direct https://127.0.0.1:PORT/api/v1/goals:submit endpoint")
	tokenFile := flags.String("token-file", "", "private file containing an opaque OAuth bearer token")
	caFile := flags.String("ca-file", "", "PEM trust anchor for the direct TLS Goal API")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *filePath == "" || *tokenFile == "" || *caFile == "" {
		return errors.New("submit requires --file, --url, --token-file and --ca-file")
	}
	if err := validGoalSubmitURL(*endpoint); err != nil {
		return err
	}
	proposalBytes, err := readGoalProposal(*filePath, stdin)
	if err != nil {
		return err
	}
	proposal, _, _, err := issuegoal.DecodePrepared(proposalBytes)
	if err != nil {
		return errors.New("invalid prepared Issue Goal proposal; run acp-goal prepare first")
	}
	bearer, err := privateGoalBearer(*tokenFile)
	if err != nil {
		return err
	}
	roots, err := explicitGoalTrustRoots(*caFile)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, *endpoint, bytes.NewReader(proposalBytes))
	if err != nil {
		return errors.New("invalid GoalSubmit request")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	// Never honor proxy environment variables or follow redirects with a
	// bearer token. The operator must connect directly to a numeric loopback
	// address and explicitly trust the server's CA.
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{
			RootCAs: roots, MinVersion: tls.VersionTLS13,
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	if err != nil {
		// Never include the request URL or low-level error; either can expose
		// credentials or wrongly imply the server definitely rejected the write.
		return errors.New("GoalSubmit transport failed; outcome unknown, inspect ACP before retrying")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GoalSubmit not accepted (HTTP %d); inspect ACP before retrying", resp.StatusCode)
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || !strings.Contains(resp.Header.Get("Cache-Control"), "no-store") {
		return errors.New(unknownGoalReceipt)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGoalReplyBytes+1))
	if err != nil || len(body) > maxGoalReplyBytes {
		return errors.New(unknownGoalReceipt)
	}
	var receipt struct {
		Schema        string `json:"schema"`
		RunIntentID   string `json:"run_intent_id"`
		RequestDigest string `json:"request_digest"`
		Status        string `json:"status"`
		Created       *bool  `json:"created"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF ||
		receipt.Schema != goalhttp.AcceptanceVersion ||
		receipt.RequestDigest != proposal.RequestDigest ||
		receipt.Created == nil || *receipt.Created != (resp.StatusCode == http.StatusCreated) ||
		!validGoalReceiptID(receipt.RunIntentID) || !validGoalReceiptStatus(receipt.Status) ||
		(*receipt.Created && receipt.Status != "PENDING") {
		return errors.New(unknownGoalReceipt)
	}
	return json.NewEncoder(stdout).Encode(receipt)
}

func validGoalSubmitURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" ||
		u.Path != goalhttp.SubmitPath || u.RawPath != "" || u.String() != raw {
		return errors.New("submit URL must be an exact direct HTTPS GoalSubmit endpoint")
	}
	ip := net.ParseIP(u.Hostname())
	port, err := strconv.Atoi(u.Port())
	if ip == nil || !ip.IsLoopback() || err != nil || port < 1 || port > 65535 {
		return errors.New("submit URL must use a numeric loopback IP and explicit port")
	}
	return nil
}

func readGoalProposal(path string, stdin io.Reader) ([]byte, error) {
	var source io.Reader = stdin
	if path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return nil, errors.New("prepared Goal file unavailable")
		}
		defer file.Close()
		source = file
	}
	data, err := io.ReadAll(io.LimitReader(source, issuegoal.MaxPreparedBytes+1))
	if err != nil || len(data) == 0 || len(data) > issuegoal.MaxPreparedBytes {
		return nil, errors.New("prepared Goal file invalid or too large")
	}
	return data, nil
}

func privateGoalBearer(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 ||
		info.Size() == 0 || info.Size() > maxBearerBytes+2 {
		return "", errors.New("OAuth token must be in a private regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("OAuth token file unavailable")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm()&0077 != 0 ||
		!os.SameFile(info, opened) {
		return "", errors.New("OAuth token file changed or is unsafe")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maxBearerBytes+3))
	if err != nil {
		return "", errors.New("OAuth token file unavailable")
	}
	token := strings.TrimRight(string(raw), "\r\n")
	if len(token) == 0 || len(token) > maxBearerBytes {
		return "", errors.New("OAuth token file invalid")
	}
	for _, ch := range []byte(token) {
		if ch <= 32 || ch >= 127 {
			return "", errors.New("OAuth token file invalid")
		}
	}
	return token, nil
}

func explicitGoalTrustRoots(path string) (*x509.CertPool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, errors.New("Goal API TLS trust anchor unavailable")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxCABytes {
		return nil, errors.New("Goal API TLS trust anchor invalid")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxCABytes+1))
	if err != nil || len(data) == 0 || len(data) > maxCABytes {
		return nil, errors.New("Goal API TLS trust anchor invalid")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(data) {
		return nil, errors.New("Goal API TLS trust anchor invalid")
	}
	return roots, nil
}

func validGoalReceiptID(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, ch := range []byte(value) {
		if ch <= 32 || ch >= 127 || ch == '/' || ch == '?' || ch == '#' {
			return false
		}
	}
	return true
}

func validGoalReceiptStatus(value string) bool {
	switch value {
	case "PENDING", "DISPATCHING", "UNKNOWN", "RECONCILING", "ACCEPTED", "REJECTED", "MANUAL_REVIEW":
		return true
	default:
		return false
	}
}
