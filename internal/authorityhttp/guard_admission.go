package authorityhttp

import (
	"context"
	"net/http"

	"github.com/avaargsh/agent-control-panel/internal/authoritycutover"
)

// acquireGuardAdmission keeps the shared PostgreSQL admission/DDL lease until
// the response has been flushed. It is called only after mTLS and request
// validation so unauthenticated or malformed traffic cannot hold database
// leases. A writer without Flush support fails closed.
func acquireGuardAdmission(
	w http.ResponseWriter,
	ctx context.Context,
	gate authoritycutover.RequestGate,
	fail func(int, string),
	code string,
) (func(), bool) {
	if gate == nil {
		return nil, true
	}
	lease, err := gate.Acquire(ctx)
	if err != nil || lease == nil {
		if lease != nil {
			_ = lease.Release()
		}
		fail(http.StatusServiceUnavailable, code)
		return nil, false
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		_ = lease.Release()
		fail(http.StatusServiceUnavailable, code)
		return nil, false
	}
	return func() {
		defer func() { _ = lease.Release() }()
		flusher.Flush()
	}, true
}

// checkGuardAuthorityRole brackets a Guard-only catalog read with fresh
// authority database-role attestations while the admission lease is held.
func checkGuardAuthorityRole(
	ctx context.Context,
	check func(context.Context) error,
	fail func(int, string),
	code string,
) bool {
	if ctx.Err() != nil {
		fail(http.StatusServiceUnavailable, code)
		return false
	}
	if check != nil {
		if err := check(ctx); err != nil {
			fail(http.StatusServiceUnavailable, code)
			return false
		}
	}
	if ctx.Err() != nil {
		fail(http.StatusServiceUnavailable, code)
		return false
	}
	return true
}
