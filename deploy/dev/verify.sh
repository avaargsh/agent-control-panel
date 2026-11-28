#!/bin/sh
set -eu
cd "$(dirname "$0")"
./init.sh
./compose.sh config --quiet
./compose.sh up --build --wait --wait-timeout 120
base="http://127.0.0.1:${ACP_DEV_HTTP_PORT:-18080}"
test "$(curl --noproxy '*' --fail --silent --show-error --max-time 5 "$base/livez")" = ok
test "$(curl --noproxy '*' --fail --silent --show-error --max-time 5 "$base/readyz")" = ready
./compose.sh run --rm --no-deps migrate
curl --noproxy '*' --fail --silent --show-error --max-time 5 "$base/api/v1/meta"
