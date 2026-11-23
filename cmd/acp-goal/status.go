package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/avaargsh/agent-control-panel/internal/goalhttp"
	"github.com/avaargsh/agent-control-panel/internal/issuegoal"
)

const unknownGoalStatus = "Goal status unconfirmed; UNKNOWN/HOLD, do not retry without authoritative reconciliation"

// status reads only the ACP-owned original RunIntent under a newly authorized
// OAuth/Catalog snapshot. The prepared input is not sent to GoalSubmit, and a
// 404 is never treated as evidence that a previous request was rolled back.
func status(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	filePath := flags.String("file", "", "original prepared Issue Goal JSON; - reads stdin")
	endpoint := flags.String("url", "", "direct loopback TLS /api/v1/goals:status endpoint")
	tokenFile := flags.String("token-file", "", "private OAuth bearer token file")
	caFile := flags.String("ca-file", "", "explicit TLS CA trust bundle")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 || *filePath == "" || *tokenFile == "" || *caFile == "" {
		return errors.New("status requires --file, --url, --token-file and --ca-file")
	}
	if err := validGoalStatusURL(*endpoint); err != nil {
		return err
	}
	proposalBytes, err := readGoalProposal(*filePath, stdin)
	if err != nil {
		return err
	}
	proposal, _, _, err := issuegoal.DecodePrepared(proposalBytes)
	if err != nil {
		return errors.New("invalid original prepared Issue Goal")
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
		return errors.New("invalid Goal status request")
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return errors.New(unknownGoalStatus)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Missing includes no record, different request identity, revoked
		// scope and unavailable catalog. None is terminal absence evidence.
		return errors.New(unknownGoalStatus)
	}
	media, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	cache := resp.Header.Values("Cache-Control")
	if err != nil || media != "application/json" || len(cache) != 1 ||
		!strings.EqualFold(strings.TrimSpace(cache[0]), "no-store") {
		return errors.New(unknownGoalStatus)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGoalReplyBytes+1))
	if err != nil || len(body) > maxGoalReplyBytes ||
		issuegoal.ValidateUniqueJSONKeys(body) != nil {
		return errors.New(unknownGoalStatus)
	}
	var receipt struct {
		Schema        string `json:"schema"`
		RunIntentID   string `json:"run_intent_id"`
		RequestDigest string `json:"request_digest"`
		Status        string `json:"status"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&receipt) != nil || decoder.Decode(new(any)) != io.EOF ||
		receipt.Schema != goalhttp.StatusVersion ||
		receipt.RequestDigest != proposal.RequestDigest ||
		!validGoalReceiptID(receipt.RunIntentID) ||
		!validGoalReceiptStatus(receipt.Status) {
		return errors.New(unknownGoalStatus)
	}
	return json.NewEncoder(stdout).Encode(receipt)
}
