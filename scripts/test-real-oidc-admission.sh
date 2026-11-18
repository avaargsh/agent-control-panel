#!/usr/bin/env bash
set -euo pipefail

mode="${1:-oidc}"
case "$mode" in
  oidc|golden-path) ;;
  *) echo "expected oidc or golden-path"; exit 1 ;;
esac

# Disposable issuer and credentials only. Never point this script at an
# existing issuer, cluster, production realm or externally exposed port.
: "${PGTEST_DSN:?disposable PostgreSQL DSN required}"
root="$(mktemp -d)"
name="acp-oidc-$RANDOM-$$"
cleanup() {
  docker rm -f "$name" >/dev/null 2>&1 || true
  rm -rf -- "$root"
}
trap cleanup EXIT
mkdir -p "$root/realm" "$root/tls"
chmod 755 "$root" "$root/realm" "$root/tls"

openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -subj '/CN=ACP disposable issuer CA' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign' \
  -keyout "$root/ca.key" -out "$root/ca.crt" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -subj '/CN=localhost' \
  -keyout "$root/tls/server.key" -out "$root/server.csr" >/dev/null 2>&1
cat > "$root/server.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth
keyUsage=critical,digitalSignature,keyEncipherment
EOF
openssl x509 -req -in "$root/server.csr" -CA "$root/ca.crt" \
  -CAkey "$root/ca.key" -CAcreateserial -days 1 \
  -extfile "$root/server.ext" -out "$root/tls/server.crt" >/dev/null 2>&1

export ACP_REAL_IDP_SECRET="$(openssl rand -hex 32)"
export ACP_REAL_RUNNER_SECRET="$(openssl rand -hex 32)"
if [[ "${GITHUB_ACTIONS:-}" == true ]]; then
  echo "::add-mask::$ACP_REAL_IDP_SECRET"
  echo "::add-mask::$ACP_REAL_RUNNER_SECRET"
fi

python3 - "$root/realm/acp-ci-realm.json" <<'PY'
import json
import os
import sys

def scope(name, include=True, mappers=None):
    return {
        "name": name, "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": str(include).lower(),
                       "display.on.consent.screen": "false"},
        "protocolMappers": mappers or [],
    }

def client(client_id, secret, service_account=False):
    return {
        "clientId": client_id, "secret": secret, "enabled": True,
        "protocol": "openid-connect", "publicClient": False,
        "clientAuthenticatorType": "client-secret", "standardFlowEnabled": False,
        "directAccessGrantsEnabled": False, "serviceAccountsEnabled": service_account,
        "defaultClientScopes": ["acp-ci-observe", "acp-ci-audience"] if service_account else [],
        "optionalClientScopes": ["acp:run-intent:create"] if service_account else [],
    }

realm = {
    "realm": "acp-ci", "enabled": True, "sslRequired": "all",
    "accessTokenLifespan": 30,
    "clientScopes": [
        scope("acp-ci-observe"),
        scope("acp:run-intent:create"),
        scope("acp-ci-audience", False, [{
            "name": "ACP audience", "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": "acp-control-plane",
                       "access.token.claim": "true", "id.token.claim": "false",
                       "introspection.token.claim": "true"}
        }]),
    ],
    "clients": [
        client("acp-control-plane", os.environ["ACP_REAL_IDP_SECRET"]),
        client("acp-ci-runner", os.environ["ACP_REAL_RUNNER_SECRET"], True),
    ],
}
with open(sys.argv[1], "w") as f:
    json.dump(realm, f)
PY

# The container runs as a different UID. These are disposable job-only
# files; the CA key is never mounted into the issuer container.
chmod 644 "$root/realm/acp-ci-realm.json" "$root/tls/server.crt" "$root/tls/server.key"
# Keycloak 26.8.2, observed in live issuer acceptance #44249476537.
image="quay.io/keycloak/keycloak@sha256:c68e286cacd87b942ac1939a0a1481461109d6acd3a57dc496969a319a76bbf0"
docker pull "$image"
digest="$(docker image inspect --format '{{index .RepoDigests 0}}' "$image")"
if [[ "$digest" != "$image" ]]; then
  echo "unexpected issuer image digest"
  exit 1
fi
echo "Disposable issuer image: $digest"
docker run --rm -d --name "$name" \
  -p 127.0.0.1:8443:8443 \
  -v "$root/realm:/opt/keycloak/data/import:ro" \
  -v "$root/tls:/tls:ro" \
  "$digest" start-dev --import-realm --http-enabled=false \
  --hostname=https://localhost:8443 \
  --https-certificate-file=/tls/server.crt \
  --https-certificate-key-file=/tls/server.key >/dev/null

export ACP_REAL_IDP_ISSUER="https://localhost:8443/realms/acp-ci"
export ACP_REAL_IDP_CA="$root/ca.crt"
export ACP_REAL_IDP=1
ready=0
for _ in $(seq 1 90); do
  if curl --cacert "$ACP_REAL_IDP_CA" --silent --fail --max-time 3 \
      "$ACP_REAL_IDP_ISSUER/.well-known/openid-configuration" >/dev/null; then
    ready=1
    break
  fi
  if ! docker inspect --format '{{.State.Running}}' "$name" 2>/dev/null | grep -qx true; then
    echo "Disposable issuer exited before discovery was ready"
    exit 1
  fi
  sleep 2
done
if (( ready != 1 )); then
  echo "Disposable issuer HTTPS discovery did not become ready"
  exit 1
fi

if [[ "$mode" == golden-path ]]; then
  : "${ACP_CROSS_SERVICE:?golden path requires two independent databases}"
  : "${ACP_RUNTIME_API_BIN:?golden path requires the pinned Runtime API binary}"
  : "${ACP_RUNTIME_TEMPORAL_TEST_BIN:?golden path requires the pinned Temporal test binary}"
  export ACP_GOLDEN_PATH=1
  go test -race -count=1 -v -run '^TestCrossServiceLostACKRecoversOneRuntimeRunAfterProcessRestart
 ./internal/runtimeinspect
else
  go test -race -count=1 -v -run '^TestRealOIDCServiceAccountCatalogAdmission
 ./internal/admission
fi
