package issuegoal

import (
	"errors"
	"fmt"
)

// PublicSourceFailure is an internal, sanitized description of a failed
// read-only GitHub source observation. Its fields contain only controlled
// reason codes and HTTP status; no URLs, response bodies, headers or request
// credentials are retained. It is NOT an authorization or retry decision.
type PublicSourceFailure struct {
	Operation  string // issue or baseline
	Reason     string // transport, http_status, invalid_media or invalid_body
	HTTPStatus int    // zero only when no HTTP response was received
	cause      error
}

func (e *PublicSourceFailure) Error() string {
	if e == nil {
		return "GitHub source observation unavailable"
	}
	if e.HTTPStatus == 0 {
		return fmt.Sprintf("%v: %s %s", e.cause, e.Operation, e.Reason)
	}
	return fmt.Sprintf("%v: %s %s HTTP %d", e.cause, e.Operation, e.Reason, e.HTTPStatus)
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
