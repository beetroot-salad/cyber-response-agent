#!/usr/bin/env bash
# The Defender app on the dev stack, for a browser on the host: http://localhost:8000.
#
#   .devcontainer/dev-app.sh start    check the stack, then start what is not running
#   .devcontainer/dev-app.sh status   what is running, and where its log is
#   .devcontainer/dev-app.sh stop     stop what `start` started
#
# Run inside the dev container. It starts three things, each in the background with its log and pid file in the
# state folder (`DEFENDER_DEV_APP_STATE`, default `~/.cache/defender-dev-app`), so they outlive the shell:
#
# - the API (`python -m defender.api_server`) on 127.0.0.1:8001, over the dev PostgreSQL, Keycloak and OpenBao;
# - Vite's dev server (`bun run dev`, hot reload) on the container's port 8000, `/api` sent to the API;
# - `response-app-forward`, an nginx container on the compose network that publishes the host's 127.0.0.1:8000 to
#   the dev container's 8000. The dev container publishes no port of its own, and the sign-in realm registers only
#   `http://localhost:8000/api/auth/callback`, so the app must be at exactly that address in the host's browser.
#
# It also starts `python -m defender.lifecycle serve` (which carries out tenant creation) when none is running, and
# stops only one it started. It never migrates the database, starts compose services or changes the realm: a check
# that fails names what to do. See defender/docs/development-operations.md, "Running the API on the dev database and
# real sign-in".
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISSUER="${DEFENDER_DEV_ISSUER:-$REPO/playground-issuer}"
STATE="${DEFENDER_DEV_APP_STATE:-$HOME/.cache/defender-dev-app}"
PY="${DEFENDER_PYTHON:-$REPO/defender/.venv/bin/python}"
ADMIN="${DEFENDER_DEV_ADMIN:-admin@dev.local}"
API_PORT=8001
APP_PORT=8000
FORWARDER=response-app-forward
DEVCONTAINER=response-devcontainer
FORWARD_IMAGE=nginx:1.27.5-alpine
# The dev realms' client secret (.devcontainer/keycloak/realm-*.json): dev-only, the same for every client.
DEV_CLIENT_SECRET=dev-only-change-me
# The KV mount the dev OpenBao keeps tenant credentials on (playground-issuer/recovery/bao_bootstrap.py).
KV_MOUNT=tenant-credentials

say() { printf '[dev-app] %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

pid_alive() { [ -f "$STATE/$1.pid" ] && kill -0 "$(cat "$STATE/$1.pid")" 2>/dev/null; }
port_open() { timeout 1 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }

# The two settings the API shares with the lifecycle, read from lifecycle.env without taking the rest of it (its
# PYTHONPATH names the checkout the lifecycle runs from, not this one).
lifecycle_value() { (set +u; source "$ISSUER/lifecycle.env" >/dev/null; printf '%s' "${!1:-}"); }

check() {
  [ -x "$PY" ] || die "no python at $PY: make the checkout's venv, or set DEFENDER_PYTHON"
  command -v bun >/dev/null || die "bun is not on PATH"
  command -v docker >/dev/null || die "docker is not on PATH"
  [ -f "$ISSUER/lifecycle.env" ] || die "no $ISSUER/lifecycle.env: run .devcontainer/provision-dev-issuer.sh (or set DEFENDER_DEV_ISSUER)"
  [ -s "$ISSUER/client/credential-writer.token" ] || die "no OpenBao writer token in $ISSUER/client/"
  DSN="$(lifecycle_value DEFENDER_DATABASE_DSN)"
  CERTS="$(lifecycle_value SSL_CERT_DIR)"
  [ -n "$DSN" ] || die "$ISSUER/lifecycle.env sets no DEFENDER_DATABASE_DSN"

  local realm issuer
  for realm in defender defender-programs; do
    issuer="$(curl -fsS --max-time 5 "http://keycloak:8080/realms/$realm/.well-known/openid-configuration" 2>/dev/null \
      | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["issuer"])' 2>/dev/null)" \
      || die "Keycloak does not serve realm $realm at http://keycloak:8080: start the keycloak service, with both realms imported"
    [ "$issuer" = "http://localhost:8080/realms/$realm" ] \
      || die "realm $realm's issuer is $issuer, not http://localhost:8080/realms/$realm"
  done
  # Keycloak imports the realm files on its first start only, so a live realm made before a change to them keeps the
  # old settings. Asked the way the browser will ask: an unregistered callback is refused (400), a registered one is
  # sent on (302). The theme is the realm's loginTheme, read with the dev admin of docker-compose.yml.
  local auth="http://keycloak:8080/realms/defender/protocol/openid-connect/auth?response_type=code&scope=openid"
  local code
  code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
    "$auth&client_id=defender-api&redirect_uri=http%3A%2F%2Flocalhost%3A$APP_PORT%2Fapi%2Fauth%2Fcallback")"
  [ "$code" = 302 ] || die "the live realm 'defender' does not accept http://localhost:$APP_PORT/api/auth/callback \
(Keycloak answered $code): add it to the defender-api client's Valid redirect URIs (admin console at \
http://localhost:8080, admin / dev-only-change-me), or recreate Keycloak's data so it imports keycloak/realm-defender.json"
  local token theme
  token="$(curl -s --max-time 5 -d grant_type=password -d client_id=admin-cli -d username=admin \
    -d password=dev-only-change-me http://keycloak:8080/realms/master/protocol/openid-connect/token \
    | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["access_token"])' 2>/dev/null)" || token=""
  if [ -n "$token" ]; then
    theme="$(curl -s --max-time 5 -H "Authorization: Bearer $token" http://keycloak:8080/admin/realms/defender \
      | "$PY" -c 'import json,sys; print(json.load(sys.stdin).get("loginTheme") or "")' 2>/dev/null)" || theme=""
    [ "$theme" = defender ] || say "the sign-in pages will wear Keycloak's own look: the realm's login theme is \
'${theme:-unset}', not 'defender' (set it in the admin console's Realm settings > Themes; a Keycloak container \
made before the theme mount also needs recreating: docker compose up -d keycloak, from the host)"
  fi
  SSL_CERT_DIR="$CERTS" "$PY" -c '
import json, sys, urllib.request
try:
    sealed = json.load(urllib.request.urlopen("https://openbao:8200/v1/sys/seal-status", timeout=5))["sealed"]
except Exception as error:
    sys.exit(f"OpenBao is not reachable at https://openbao:8200 ({error})")
if sealed:
    sys.exit("OpenBao is sealed: unseal it (playground-issuer/seal/)")' || die "OpenBao check failed"
  # The version check only reads; upgrading the shared database is the operator's decision.
  PYTHONPATH="$REPO" "$PY" -c 'import sys; import defender.migrations as m; m.check_version(sys.argv[1])' "$DSN" \
    || die "the database is not at this code's migration head: python -m defender.migrations upgrade (it is shared: other checkouts use it too)"
}

write_settings() {
  mkdir -p "$STATE/secrets"
  chmod 700 "$STATE" "$STATE/secrets"
  local name
  for name in signin signin-admin programs-admin; do
    printf '%s\n' "$DEV_CLIENT_SECRET" >"$STATE/secrets/$name"
  done
  chmod 600 "$STATE"/secrets/*
  printf 'administrators: [%s]\n' "$ADMIN" >"$STATE/administrators.yaml"
}

start_api() {
  if pid_alive api; then say "API already running (pid $(cat "$STATE/api.pid"))"; return; fi
  port_open 127.0.0.1 "$API_PORT" && die "port $API_PORT is in use by something else"
  say "starting the API on 127.0.0.1:$API_PORT (log: $STATE/api.log)"
  (
    cd "$REPO"
    export PYTHONPATH="$REPO" SSL_CERT_DIR="$CERTS" DEFENDER_DATABASE_DSN="$DSN"
    export DEFENDER_API_HOST=127.0.0.1 DEFENDER_API_PORT="$API_PORT"
    export DEFENDER_API_FRONTEND_ORIGIN="http://localhost:$APP_PORT"
    export DEFENDER_API_ADMINISTRATORS_FILE="$STATE/administrators.yaml"
    export DEFENDER_KEYCLOAK_SERVER_URL=http://keycloak:8080
    export DEFENDER_KEYCLOAK_ISSUER=http://localhost:8080/realms/defender
    export DEFENDER_KEYCLOAK_CLIENT_ID=defender-api
    export DEFENDER_KEYCLOAK_CLIENT_SECRET_FILE="$STATE/secrets/signin"
    export DEFENDER_KEYCLOAK_ADMIN_CLIENT_ID=defender-api-admin
    export DEFENDER_KEYCLOAK_ADMIN_CLIENT_SECRET_FILE="$STATE/secrets/signin-admin"
    export DEFENDER_KEYCLOAK_PROGRAMS_ISSUER=http://localhost:8080/realms/defender-programs
    export DEFENDER_KEYCLOAK_PROGRAMS_AUDIENCE=defender-api-programs
    export DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_ID=defender-api-programs-admin
    export DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_SECRET_FILE="$STATE/secrets/programs-admin"
    export DEFENDER_OPENBAO_ADDR=https://openbao:8200
    export DEFENDER_OPENBAO_KV_MOUNT="$KV_MOUNT"
    export DEFENDER_API_OPENBAO_TOKEN_FILE="$ISSUER/client/credential-writer.token"
    setsid nohup "$PY" -m defender.api_server >"$STATE/api.log" 2>&1 </dev/null &
    echo $! >"$STATE/api.pid"
  )
  local waited=0
  until port_open 127.0.0.1 "$API_PORT"; do
    pid_alive api || { tail -n 20 "$STATE/api.log" >&2; die "the API stopped at start (above, from $STATE/api.log)"; }
    [ "$waited" -lt 60 ] || die "the API did not listen within 60s: see $STATE/api.log"
    sleep 1; waited=$((waited + 1))
  done
}

start_lifecycle() {
  if pgrep -f 'defender.lifecycle serve' >/dev/null; then
    pid_alive lifecycle || say "a lifecycle service is already running (not this script's): leaving it"
    return
  fi
  say "starting the lifecycle service (log: $STATE/lifecycle.log)"
  (
    cd "$REPO"
    set +u; source "$ISSUER/lifecycle.env"; set -u
    export PYTHONPATH="$REPO"
    setsid nohup "$PY" -m defender.lifecycle serve >"$STATE/lifecycle.log" 2>&1 </dev/null &
    echo $! >"$STATE/lifecycle.pid"
  )
}

start_vite() {
  if pid_alive vite; then say "Vite already running (pid $(cat "$STATE/vite.pid"))"; return; fi
  port_open 127.0.0.1 "$APP_PORT" && die "port $APP_PORT is in use by something else"
  say "starting Vite on port $APP_PORT (log: $STATE/vite.log)"
  (
    cd "$REPO/defender/frontend"
    [ -d node_modules ] || bun install --frozen-lockfile >"$STATE/bun-install.log" 2>&1 \
      || die "bun install failed: see $STATE/bun-install.log"
    # Every interface, not Vite's configured localhost: the forwarder reaches the container over the compose network.
    export DEFENDER_INGRESS_API_UPSTREAM="127.0.0.1:$API_PORT"
    setsid nohup bun run dev --host 0.0.0.0 >"$STATE/vite.log" 2>&1 </dev/null &
    echo $! >"$STATE/vite.pid"
  )
  local waited=0
  until port_open 127.0.0.1 "$APP_PORT"; do
    pid_alive vite || { tail -n 20 "$STATE/vite.log" >&2; die "Vite stopped at start (above, from $STATE/vite.log)"; }
    [ "$waited" -lt 90 ] || die "Vite did not listen within 90s: see $STATE/vite.log"
    sleep 1; waited=$((waited + 1))
  done
}

# Whether the app answers at 127.0.0.1:$APP_PORT on the host itself, asked from a container on the host's network.
host_answers() {
  docker run --rm --network host "$FORWARD_IMAGE" wget -q -O /dev/null -T 3 "http://127.0.0.1:$APP_PORT/" 2>/dev/null
}

start_forwarder() {
  if [ "$(docker inspect -f '{{.State.Running}}' "$FORWARDER" 2>/dev/null)" = true ]; then
    say "forwarder already running"; return
  fi
  # An attached editor (VS Code, the devcontainer CLI) forwards a port the container starts listening on by itself,
  # shortly after. Then the host's port is already the app's, and a forwarder could not bind it.
  local tries
  for tries in 1 2 3 4 5; do
    if host_answers; then say "the host's 127.0.0.1:$APP_PORT already reaches the app (an editor forwards it)"; return; fi
    sleep 1
  done
  docker rm -f "$FORWARDER" >/dev/null 2>&1 || true
  local network
  network="$(docker inspect -f '{{range $name, $_ := .NetworkSettings.Networks}}{{$name}} {{end}}' "$DEVCONTAINER" | awk '{print $1}')"
  [ -n "$network" ] || die "no network found for $DEVCONTAINER"
  say "publishing the host's 127.0.0.1:$APP_PORT to $DEVCONTAINER:$APP_PORT ($FORWARDER)"
  # A plain TCP forward, so Vite's hot-reload websocket and every header pass as they are.
  docker run -d --name "$FORWARDER" --restart unless-stopped --network "$network" \
    -p "127.0.0.1:$APP_PORT:$APP_PORT" "$FORWARD_IMAGE" sh -c "cat >/etc/nginx/nginx.conf <<'EOF'
events {}
stream {
  resolver 127.0.0.11 valid=10s;
  map \$remote_addr \$upstream { default $DEVCONTAINER:$APP_PORT; }
  server { listen $APP_PORT; proxy_pass \$upstream; }
}
EOF
exec nginx -g 'daemon off;'" >/dev/null
}

stop_one() {
  local name=$1
  if pid_alive "$name"; then
    # The process group setsid made: bun's own children (Vite) go with it.
    kill -TERM -- "-$(cat "$STATE/$name.pid")" 2>/dev/null || kill -TERM "$(cat "$STATE/$name.pid")" 2>/dev/null || true
    say "stopped $name"
  fi
  rm -f "$STATE/$name.pid"
}

status() {
  local name
  for name in api vite lifecycle; do
    if pid_alive "$name"; then echo "$name: running (pid $(cat "$STATE/$name.pid"), log $STATE/$name.log)"
    else echo "$name: not started by this script"; fi
  done
  pgrep -f 'defender.lifecycle serve' >/dev/null && ! pid_alive lifecycle && echo "lifecycle: another one is running"
  local forwarder
  forwarder="$(docker inspect -f '{{.State.Status}}' "$FORWARDER" 2>/dev/null)" || forwarder="absent (not needed while an editor forwards port $APP_PORT)"
  echo "forwarder: $forwarder"
}

case "${1:-}" in
  start)
    check
    write_settings
    start_api
    start_lifecycle
    start_vite
    start_forwarder
    cat >&2 <<EOF
[dev-app] ready: http://localhost:$APP_PORT in a browser on the host.
[dev-app] First sign-in as $ADMIN: open the set-password mail the API sends it, at http://localhost:8025 (Mailpit).
[dev-app] The realm asks for an authenticator app (a one-time code) on the first sign-in.
EOF
    ;;
  stop)
    stop_one vite
    stop_one api
    stop_one lifecycle
    docker rm -f "$FORWARDER" >/dev/null 2>&1 && say "removed $FORWARDER" || true
    ;;
  status) status ;;
  *) sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2 ;;
esac
