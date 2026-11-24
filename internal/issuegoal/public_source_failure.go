package issuegoal

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
)

// PublicSourceFailure is an internal, sanitized description of a failed
// read-only GitHub source observation. Its fields contain only controlled
// reason codes, HTTP status and optional bounded numeric diagnostics; no URLs,
// response bodies, raw headers or request credentials are retained. It is NOT an authorization or retry decision.
type PublicSourceFailure struct {
	Operation       string // issue or baseline
	Reason          string // transport, http_status, invalid_media or invalid_body
	HTTPStatus      int    // zero only when no HTTP response was received
	cause           error
	rateDiagnostics string
}

func (e *PublicSourceFailure) Error() string {
	if e == nil {
		return "GitHub source observation unavailable"
	}
	if e.HTTPStatus == 0 {
		return fmt.Sprintf("%v: %s %s", e.cause, e.Operation, e.Reason)
	}
	return fmt.Sprintf("%v: %s %s HTTP %d", e.cause, e.Operation, e.Reason, e.HTTPStatus) + e.rateDiagnostics
}

func (e *PublicSourceFailure) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func newPublicSourceFailure(cause error, operation, reason string, status int) error {
	if !errors.Is(cause, ErrIssueSourceUnavailable) && !errors.Is(cause, ErrBaselineSourceUnavailable) {
		return cause
	}
	return &PublicSourceFailure{
		Operation: operation, Reason: reason, HTTPStatus: status, cause: cause,
	}
}

// Diagnostic exposes only the safe classification and validated numbers for
// operator evidence. These observations are not a root-cause or retry decision.
func (e *PublicSourceFailure) Diagnostic() string {
	if e == nil {
		return "GitHub source observation unavailable"
	}
	return fmt.Sprintf("operation=%s reason=%s http_status=%d%s", e.Operation, e.Reason, e.HTTPStatus, e.rateDiagnostics)
}

// Only a single ASCII decimal value is accepted. Reject duplicates, HTTP
// dates, signed values, whitespace, overflow and unbounded provider claims.
// Never retain the original header value.
func boundedDecimalHeader(header http.Header, name string, max uint64) (uint64, bool) {
	values := header.Values(name)
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 10 {
		return 0, false
	}
	for _, ch := range values[0] {
		if ch < '0' || ch > '9' {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(values[0], 10, 64)
	return n, err == nil && n <= max
}

func newPublicHTTPStatusFailure(cause error, operation string, response *http.Response) error {
	err := newPublicSourceFailure(cause, operation, "http_status", response.StatusCode)
	failure, ok := err.(*PublicSourceFailure)
	if !ok {
		return err
	}
	// Only statuses relevant to throttling or temporary unavailability.
	// Even zero remaining does not by itself establish why a 403 occurred.
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusTooManyRequests {
		if n, ok := boundedDecimalHeader(response.Header, "X-RateLimit-Remaining", 1000000000); ok {
			failure.rateDiagnostics += fmt.Sprintf(" rate_remaining=%d", n)
		}
	}
	if response.StatusCode == http.StatusForbidden || response.StatusCode == http.StatusTooManyRequests || response.StatusCode == http.StatusServiceUnavailable {
		if n, ok := boundedDecimalHeader(response.Header, "Retry-After", 86400); ok {
			failure.rateDiagnostics += fmt.Sprintf(" retry_after_seconds=%d", n)
		}
	}
	return failure
}
