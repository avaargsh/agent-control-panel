#!/bin/sh
set -eu
cd "$(dirname "$0")"
# This stack is for a local development engine only. Resolve then pin the
# endpoint so a selected remote Docker context cannot receive the commands.
if [ -n "${DOCKER_CONTEXT:-}" ] || [ -z "${DOCKER_HOST:-}" ]; then
    context=$(docker context show)
    endpoint=$(docker context inspect "$context" --format '{{(index .Endpoints "docker").Host}}')
else
    endpoint=$DOCKER_HOST
fi
case "$endpoint" in
    unix:///*) ;;
    *) printf '%s\n' 'ACP dev stack requires a local Unix Docker socket' >&2; exit 1 ;;
esac
unset DOCKER_HOST DOCKER_CONTEXT
./init.sh
ACP_DEV_PROJECT_NAME=$(cat .secrets/project-name)
printf '%s\n' "$ACP_DEV_PROJECT_NAME" | grep -Eq '^acp-dev-[a-f0-9]{16}$' || {
    printf '%s\n' 'invalid local Compose project name' >&2
    exit 1
}
export ACP_DEV_PROJECT_NAME
exec docker --host "$endpoint" compose -p "$ACP_DEV_PROJECT_NAME" "$@"
