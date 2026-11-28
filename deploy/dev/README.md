# ACP local development stack

This is a loopback-only bootstrap for the read-only Operations HTTP service and
a disposable PostgreSQL 16.16 database. It is not a Runtime or production deployment.
There is no task admission, model call, IdP, approval, or external tool execution.

On Linux, install Docker Engine with Compose v2, OpenSSL, and curl. Use a
local Unix Docker socket, including a rootless socket if configured. Then run:

```sh
./deploy/dev/verify.sh
```

The script creates a local random database password on first use, builds the
Go 1.27.4 binaries, waits for PostgreSQL, applies the existing checksum-ledger
migrations with the one-shot migration container, and exposes Operations on
`127.0.0.1:18080` after migrations succeed. It checks the HTTP endpoints
and reruns migrations to check idempotency. The Operations container has no
database credentials or route to the internal database network. Choose another
port with `ACP_DEV_HTTP_PORT=18081 ./deploy/dev/verify.sh`. Each checkout
gets its own persistent Compose project name in the private `.secrets/`
directory so a second checkout cannot take over the first one's services or
volume. Use the wrapper for all Compose commands:

```sh
./deploy/dev/compose.sh ps
./deploy/dev/compose.sh down
```

To intentionally delete this development database, add `--volumes` to the
`down` command. Keep the private `deploy/dev/.secrets/` directory while
keeping the volume: the stored project name selects that volume, and deleting
the password file does not rotate an initialized database password.

The database role is the isolated development bootstrap owner, not a production
service role. The [Go builder](https://hub.docker.com/layers/library/golang/1-bookworm/)
and [PostgreSQL image](https://hub.docker.com/layers/library/postgres/16.16-bookworm/images/sha256-d755a91aff87574a57060f86ecc0d55f83ccb51ceec6ec6f904c1210d018d998)
use immutable multi-platform image indexes. Update each digest together with
its tag and version assertion, then rerun the smoke. Runtime/Temporal are not
part of this slice. The HTTP readiness check covers the Operations process only. The path-filtered
[development Compose workflow](../../.github/workflows/acp-dev-compose.yml)
runs the documented command on a real Docker runner and verifies persistence
after down/up plus checkout-scoped cleanup. It is not a production check.
