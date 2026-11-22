#!/usr/bin/env bash
# The Defender app on the dev stack, for a browser on the host: http://localhost:8000.
#
#   .devcontainer/dev-app.sh start    start what is not running
#   .devcontainer/dev-app.sh status   what is running, and where its log is
#   .devcontainer/dev-app.sh stop     stop what `start` started
#
# Run inside the dev container. It starts, each in the background with its log and pid file in the state folder
# (`DEFENDER_DEV_APP_STATE`, default `~/.cache/defender-dev-app`), so they outlive the shell:
#
# - the API (`python -m defender.api_server`) on 127.0.0.1:8001, over the dev PostgreSQL, Keycloak and OpenBao. Its
#   own start checks (database version, OpenBao, both realms) refuse start naming the step; the script shows that log.
# - Vite's dev server (`bun run dev`, hot reload) on the container's port 8000, `/api` sent to the API;
# - `python -m defender.lifecycle serve` (which carries out tenant creation), only when none is running; it stops only
#   one it started.
#
# The sign-in realm registers only `http://localhost:8000/api/auth/callback`, so the app must be at exactly that address
# in the host's browser. docker-compose.yml publishes the dev container's 8000 on the host's 127.0.0.1:8000; a container
# made before that relies on an attached editor forwarding the port.
#
# The API's own start refuses a realm that does not accept that callback (#1620). The script never migrates the
# database, starts compose services or changes the realm.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ISSUER="${DEFENDER_DEV_ISSUER:-$REPO/playground-issuer}"
STATE="${DEFENDER_DEV_APP_STATE:-$HOME/.cache/defender-dev-app}"
PY="${DEFENDER_PYTHON:-$REPO/defender/.venv/bin/python}"
ADMIN="${DEFENDER_DEV_ADMIN:-admin@dev.local}"
API_PORT=8001
APP_PORT=8000
# Keycloak as the dev container reaches it, and its realms as the browser (and so every token's issuer) names them.
KC=http://keycloak:8080
KC_REALMS=http://localhost:8080/realms
KEYCLOAK_CONTAINER=response-keycloak
DEVCONTAINER=response-devcontainer
PROBE_IMAGE=nginx:1.27.5-alpine
# The KV mount the dev OpenBao keeps tenant credentials on (`KV` in playground-issuer/recovery/bao_bootstrap.py).
KV_MOUNT=tenant-credentials

say() { printf '[dev-app] %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

pid_of() { cat "$STATE/$1.pid" 2>/dev/null; }
pid_alive() { kill -0 "$(pid_of "$1")" 2>/dev/null; }
port_open() { timeout 1 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }
# A lifecycle service this script did not start (another checkout's, or a lab's).
foreign_lifecycle() { pgrep -f 'defender.lifecycle serve' >/dev/null && ! pid_alive lifecycle; }
# The JSON on stdin's field $1, or nothing.
json_field() { "$PY" -c 'import json,sys; print(json.load(sys.stdin).get(sys.argv[1]) or "")' "$1" 2>/dev/null; }

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

  # The login theme, read as the live Keycloak's bootstrap admin: a warning only.
  local password token theme
  password="$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$KEYCLOAK_CONTAINER" 2>/dev/null \
    | sed -n 's/^KC_BOOTSTRAP_ADMIN_PASSWORD=//p')" || password=""
  token="$(curl -s --max-time 5 -d grant_type=password -d client_id=admin-cli -d username=admin \
    --data-urlencode "password=$password" "$KC/realms/master/protocol/openid-connect/token" | json_field access_token)" || token=""
  if [ -n "$token" ]; then
    theme="$(curl -s --max-time 5 -H "Authorization: Bearer $token" "$KC/admin/realms/defender" | json_field loginTheme)" || theme=""
    [ "$theme" = defender ] || say "the sign-in pages will wear Keycloak's own look: the realm's login theme is \
'${theme:-unset}', not 'defender' (set it in the admin console's Realm settings > Themes; a Keycloak container \
made before the theme mount also needs recreating: docker compose up -d keycloak, from the host)"
  fi
}

# The API's files: each client secret as the realm files hold it, the administrators, and OpenBao's address as the
# deployment defines it (`defender.configuration.issuer`).
write_settings() {
  mkdir -p "$STATE/secrets"
  chmod 700 "$STATE" "$STATE/secrets"
  printf 'administrators: [%s]\n' "$ADMIN" >"$STATE/administrators.yaml"
  BAO="$(PYTHONPATH="$REPO" "$PY" - "$REPO/.devcontainer/keycloak" "$STATE/secrets" <<'EOF'
import json, os, sys
from pathlib import Path
from defender.configuration.issuer import OPENBAO_URL
realms, out = Path(sys.argv[1]), Path(sys.argv[2])
for name, realm, client in (("signin", "defender", "defender-api"), ("signin-admin", "defender", "defender-api-admin"),
                            ("programs-admin", "defender-programs", "defender-api-programs-admin")):
    clients = json.loads((realms / f"realm-{realm}.json").read_text(encoding="utf-8"))["clients"]
    path = out / name
    path.write_text(next(c["secret"] for c in clients if c["clientId"] == client) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)
print(OPENBAO_URL)
EOF
)" || die "could not write the API's settings"
}

# Start $1 (a name for its pid and log) in the background, running the rest of the arguments.
launch() {
  local name=$1; shift
  setsid nohup "$@" >"$STATE/$name.log" 2>&1 </dev/null &
  echo $! >"$STATE/$name.pid"
}

# Wait until each named process listens on its port (`name:port`), or show its log's tail when it stopped first.
await_ports() {
  local waited=0 pending=("$@") left entry
  while [ "${#pending[@]}" -gt 0 ]; do
    left=()
    for entry in "${pending[@]}"; do
      port_open 127.0.0.1 "${entry#*:}" && continue
      pid_alive "${entry%%:*}" || { tail -n 20 "$STATE/${entry%%:*}.log" >&2; die "${entry%%:*} stopped at start (above, from $STATE/${entry%%:*}.log)"; }
      left+=("$entry")
    done
    pending=("${left[@]+"${left[@]}"}")
    [ "${#pending[@]}" -eq 0 ] && break
    [ "$waited" -lt 450 ] || die "not listening within 90s: ${pending[*]}; see their logs in $STATE"
    sleep 0.2; waited=$((waited + 1))
  done
}

start_api() {
  if pid_alive api; then say "API already running (pid $(pid_of api))"; return 1; fi
  port_open 127.0.0.1 "$API_PORT" && die "port $API_PORT is in use by something else"
  say "starting the API on 127.0.0.1:$API_PORT (log: $STATE/api.log)"
  (
    cd "$REPO"
    export PYTHONPATH="$REPO" SSL_CERT_DIR="$CERTS" DEFENDER_DATABASE_DSN="$DSN"
    export DEFENDER_API_HOST=127.0.0.1 DEFENDER_API_PORT="$API_PORT"
    export DEFENDER_API_FRONTEND_ORIGIN="http://localhost:$APP_PORT"
    export DEFENDER_FORGE_DOMAIN=forge.localhost
    export DEFENDER_API_ADMINISTRATORS_FILE="$STATE/administrators.yaml"
    export DEFENDER_KEYCLOAK_SERVER_URL="$KC"
    export DEFENDER_KEYCLOAK_ISSUER="$KC_REALMS/defender"
    export DEFENDER_KEYCLOAK_CLIENT_ID=defender-api
    export DEFENDER_KEYCLOAK_CLIENT_SECRET_FILE="$STATE/secrets/signin"
    export DEFENDER_KEYCLOAK_ADMIN_CLIENT_ID=defender-api-admin
    export DEFENDER_KEYCLOAK_ADMIN_CLIENT_SECRET_FILE="$STATE/secrets/signin-admin"
    export DEFENDER_KEYCLOAK_PROGRAMS_ISSUER="$KC_REALMS/defender-programs"
    export DEFENDER_KEYCLOAK_PROGRAMS_AUDIENCE=defender-api-programs
    export DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_ID=defender-api-programs-admin
    export DEFENDER_KEYCLOAK_PROGRAMS_ADMIN_CLIENT_SECRET_FILE="$STATE/secrets/programs-admin"
    export DEFENDER_OPENBAO_ADDR="$BAO" DEFENDER_OPENBAO_KV_MOUNT="$KV_MOUNT"
    export DEFENDER_API_OPENBAO_TOKEN_FILE="$ISSUER/client/credential-writer.token"
    launch api "$PY" -m defender.api_server
  )
}

start_lifecycle() {
  if pgrep -f 'defender.lifecycle serve' >/dev/null; then
    foreign_lifecycle && say "a lifecycle service is already running (not this script's): leaving it"
    return
  fi
  say "starting the lifecycle service (log: $STATE/lifecycle.log)"
  (
    cd "$REPO"
    set +u; source "$ISSUER/lifecycle.env"; set -u
    # #1592: the request worker's two settings, which .devcontainer/forgejo/setup.sh's header says how to read.
    [ -n "${DEFENDER_LIFECYCLE_KEYCLOAK_SOURCE_ID:-}" ] && [ -n "${DEFENDER_LIFECYCLE_FORGE_SESSIONS_DSN:-}" ] \
      || die "$ISSUER/lifecycle.env sets no DEFENDER_LIFECYCLE_KEYCLOAK_SOURCE_ID or DEFENDER_LIFECYCLE_FORGE_SESSIONS_DSN: run .devcontainer/forgejo/setup.sh and add both, as its header says"
    export PYTHONPATH="$REPO"
    launch lifecycle "$PY" -m defender.lifecycle serve
  )
}

start_vite() {
  if pid_alive vite; then say "Vite already running (pid $(pid_of vite))"; return 1; fi
  port_open 127.0.0.1 "$APP_PORT" && die "port $APP_PORT is in use by something else"
  say "starting Vite on port $APP_PORT (log: $STATE/vite.log)"
  (
    cd "$REPO/defender/frontend"
    [ -d node_modules ] || bun install --frozen-lockfile >"$STATE/bun-install.log" 2>&1 \
      || die "bun install failed: see $STATE/bun-install.log"
    # Every interface, not Vite's configured localhost: a published port arrives on the container's network address.
    export DEFENDER_INGRESS_API_UPSTREAM="127.0.0.1:$API_PORT"
    launch vite bun run dev --host 0.0.0.0
  )
}

# How the host's 127.0.0.1:$APP_PORT reaches the app: published by compose, or forwarded by an attached editor.
check_host_reach() {
  [ -n "$(docker port "$DEVCONTAINER" "$APP_PORT" 2>/dev/null)" ] && return
  # An editor (VS Code, the devcontainer CLI) forwards a port shortly after the container starts listening on it. One
  # container on the host's network asks for up to 5 seconds.
  if docker run --rm --network host "$PROBE_IMAGE" sh -c "for i in 1 2 3 4 5; do \
wget -q -O /dev/null -T 1 http://127.0.0.1:$APP_PORT/ && exit 0; sleep 1; done; exit 1" >/dev/null 2>&1; then
    say "the host's 127.0.0.1:$APP_PORT reaches the app through the editor's forward"; return
  fi
  say "the host's 127.0.0.1:$APP_PORT does not reach the app: this dev container predates publishing port $APP_PORT. \
Rebuild it (Dev Containers: Rebuild Container), or forward port $APP_PORT from your editor"
}

stop_one() {
  local name=$1
  if pid_alive "$name"; then
    # The process group setsid made: bun's own children (Vite) go with it.
    kill -TERM -- "-$(pid_of "$name")" 2>/dev/null || kill -TERM "$(pid_of "$name")" 2>/dev/null || true
    say "stopped $name"
  fi
  rm -f "$STATE/$name.pid"
}

status() {
  local name
  for name in api vite lifecycle; do
    if pid_alive "$name"; then echo "$name: running (pid $(pid_of "$name"), log $STATE/$name.log)"
    elif [ "$name" = lifecycle ] && foreign_lifecycle; then echo "lifecycle: another one is running (not this script's)"
    else echo "$name: not running"; fi
  done
  if [ -n "$(docker port "$DEVCONTAINER" "$APP_PORT" 2>/dev/null)" ]; then echo "port $APP_PORT: published by compose"
  else echo "port $APP_PORT: not published (an editor's forward, or rebuild the dev container)"; fi
}

# Sourced (a test reads the settings `start_api` passes), it only defines the functions.
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
case "${1:-}" in
  start)
    check
    write_settings
    # The API and Vite start together (Vite only proxies to the API), then both are awaited.
    waits=()
    start_api && waits+=("api:$API_PORT")
    start_lifecycle
    start_vite && waits+=("vite:$APP_PORT")
    await_ports "${waits[@]+"${waits[@]}"}"
    check_host_reach
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
    ;;
  status) status ;;
  *)
    cat >&2 <<'EOF'
usage: .devcontainer/dev-app.sh start|status|stop
  start    start what is not running
  status   what is running, and where its log is
  stop     stop what `start` started
EOF
    exit 2
    ;;
esac
fi
