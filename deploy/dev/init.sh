#!/bin/sh
set -eu
cd "$(dirname "$0")"
umask 077
test ! -L .secrets || { printf "%s\n" "refusing symlinked .secrets directory" >&2; exit 1; }
mkdir -p .secrets
chmod 700 .secrets
write_once() (
    path=$1
    mode=$2
    shift 2
    if [ ! -e "$path" ]; then
        tmp=$(mktemp .secrets/init.XXXXXX)
        trap 'rm -f "$tmp"' EXIT
        "$@" > "$tmp"
        chmod "$mode" "$tmp"
        ln "$tmp" "$path" 2>/dev/null || test -f "$path"
    fi
    test -f "$path" && test ! -L "$path"
)
make_project_name() {
    suffix=$(openssl rand -hex 8)
    printf 'acp-dev-%s\n' "$suffix"
}
# File-backed Compose secrets are bind mounts. The source directory is private
# even though the mounted password must be readable by the non-root UID.
write_once .secrets/postgres-password 444 openssl rand -hex 32
write_once .secrets/project-name 400 make_project_name
