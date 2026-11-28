#!/bin/sh
set -eu
cd "$(dirname "$0")"
./init.sh
./compose.sh config --quiet
./compose.sh up --build --wait --wait-timeout 120
test "$(./compose.sh exec -T db psql -XAt -v ON_ERROR_STOP=1 -U acp_dev -d acp_dev -c 'SHOW server_version_num')" = 160016
base="http://127.0.0.1:${ACP_DEV_HTTP_PORT:-18080}"
test "$(curl --noproxy '*' --fail --silent --show-error --max-time 5 "$base/livez")" = ok
test "$(curl --noproxy '*' --fail --silent --show-error --max-time 5 "$base/readyz")" = ready
./compose.sh run --rm --no-deps migrate
meta=$(curl --noproxy '*' --fail --silent --show-error --max-time 5 "$base/api/v1/meta")
test "$meta" = '{"service":"agent-control-panel","api_version":"v1"}'
printf '%s\n' ACP_COMPOSE_SMOKE_PASS
