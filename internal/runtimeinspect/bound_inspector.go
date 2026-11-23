package runtimeinspect

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/avaargsh/agent-control-panel/internal/runintent"
)

const developmentInspectPath = "/internal/v2/run-intents:inspect"

// InspectBound obtains a read-only Runtime proof of the exact principal,
// resource and normalized input binding, using the original ACP bytes.
// The v1 correlation lookup cannot prove these properties. Do not fall
// back to it on unavailable endpoints, timeouts or conflicting receipts.
func (c *Client) InspectBound(ctx context.Context, claimed runintent.Intent, input []byte) (Inspection, error) {
	if c == nil || c.client == nil || c.base == "" {
		return Inspection{}, ErrInvalidConfig
	}
	if claimed.Validate() != nil || claimed.Status != runintent.Reconciling ||
		!claimed.LeaseExpiresAt.After(time.Now()) {
		return Inspection{}, ErrNotReconcilable
	}
	scope := InspectRequest{TenantID: claimed.TenantID, RunIntentID: claimed.ID, RequestDigest: claimed.RequestDigest}
	if err := scope.Validate(); err != nil {
		return Inspection{}, err
	}
	body, err := buildAcceptanceBody(claimed, input)
	if err != nil {
		return Inspection{}, err
	}
	requestCtx, cancel := context.WithDeadline(ctx, claimed.LeaseExpiresAt)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, c.base+developmentInspectPath, bytes.NewReader(body))
	if err != nil {
		return Inspection{}, ErrInvalidRequest
	}
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	res, err := c.client.Do(req)
	if err != nil {
		return Inspection{}, ErrUnavailable
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return Inspection{}, ErrRemoteDenied
	case http.StatusConflict:
		return Inspection{}, ErrRemoteConflict
	default:
		return Inspection{}, ErrUnavailable
	}
	if !singleRuntimeJSONContentType(res.Header) {
		return Inspection{}, ErrInvalidResponse
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxResponseBytes || !utf8.Valid(raw) {
		return Inspection{}, ErrInvalidResponse
	}
	receipt, err := parseInspectResponse(raw, scope)
	if err != nil {
		return Inspection{}, err
	}
	if receipt.Status == Found {
		fields, err := uniqueObject(raw)
		if err != nil || string(fields["created"]) != "false" {
			return Inspection{}, ErrInvalidResponse
		}
	}
	return receipt, nil
}

var _ boundInspector = (*Client)(nil)
