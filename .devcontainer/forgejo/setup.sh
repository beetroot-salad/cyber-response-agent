#!/usr/bin/env bash
# The dev Forgejo's people side (#1592): its sessions database, the two dev logins on it, and the `product` login
# source that signs people in with their Keycloak account. CI's `forgejo-live` job runs it as dev does.
#
#   COMPOSE="docker compose -f .devcontainer/docker-compose.yml" .devcontainer/forgejo/setup.sh
#
# `COMPOSE` is the compose command to use (default as above, from the repository root). The script:
#
# 1. starts `postgres` and, when the `forgejo_sessions` database is absent, runs .devcontainer/postgres/forgejo-sessions.sql
#    (roles, the database, its table; mounted read-only at /defender-postgres);
# 2. creates the dev logins when absent, password `dev-only-change-me`: `fs_forgejo_dev` in `fs_forgejo` (the
#    settings file's `PROVIDER_CONFIG`) and `fs_lifecycle_dev` in `fs_lifecycle` (the lifecycle's
#    `DEFENDER_LIFECYCLE_FORGE_SESSIONS_DSN`);
# 3. starts `keycloak` and `forgejo`;
# 4. adds the `product` login source when absent, with the shipped realm's `forgejo` client secret. Its id, the
#    lifecycle's `DEFENDER_LIFECYCLE_KEYCLOAK_SOURCE_ID`, is the first column of its line in
#    `forgejo admin auth list` (run as `git` in the `forgejo` container).
#
# It may be run again: each step skips what exists. Progress goes to stderr; it prints nothing a caller parses.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
COMPOSE="${COMPOSE:-docker compose -f .devcontainer/docker-compose.yml}"
REALM=.devcontainer/keycloak/realm-defender.json
DEV_PASSWORD=dev-only-change-me
WAIT_SECONDS=180

say() { printf '[forgejo-setup] %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

# psql as the dev cluster's superuser, in the `postgres` service, over TCP: on a fresh volume the image's first-start
# server answers on its socket alone, and restarts, after the healthcheck already passes.
psql_dev() { $COMPOSE exec -T postgres psql -h 127.0.0.1 -U defender -d postgres -v ON_ERROR_STOP=1 -qtA "$@"; }
forgejo_cli() { $COMPOSE exec -T -u git forgejo forgejo "$@"; }

say "starting postgres"
$COMPOSE up -d --wait postgres
deadline=$((SECONDS + WAIT_SECONDS))
until answer="$(psql_dev -c "SELECT 1" 2>&1)"; do
  [ "$SECONDS" -lt "$deadline" ] || die "postgres did not answer within ${WAIT_SECONDS}s: $answer"
  sleep 1
done

# Each check is its own assignment, so a failing psql stops the script (set -e) instead of reading as "absent".
sessions_db="$(psql_dev -c "SELECT 1 FROM pg_database WHERE datname = 'forgejo_sessions'")"
if [ -z "$sessions_db" ]; then
  say "building the forgejo_sessions database"
  psql_dev -f /defender-postgres/forgejo-sessions.sql >/dev/null
fi

for pair in fs_forgejo_dev:fs_forgejo fs_lifecycle_dev:fs_lifecycle; do
  login="${pair%%:*}" role="${pair#*:}"
  exists="$(psql_dev -c "SELECT 1 FROM pg_roles WHERE rolname = '$login'")"
  if [ -z "$exists" ]; then
    say "creating the login $login in $role"
    psql_dev -c "CREATE ROLE $login LOGIN PASSWORD '$DEV_PASSWORD' IN ROLE $role"
  fi
done

say "starting keycloak and forgejo"
$COMPOSE up -d keycloak forgejo

# The CLI refuses until the server has set up its database, so the first answer means Forgejo is ready. Adding the
# source fetches Keycloak's discovery, so it is retried until Keycloak answers.
deadline=$((SECONDS + WAIT_SECONDS))
until sources="$(forgejo_cli admin auth list 2>&1)"; do
  [ "$SECONDS" -lt "$deadline" ] || die "forgejo did not answer \`admin auth list\` within ${WAIT_SECONDS}s: $sources"
  sleep 2
done

if ! awk '$2 == "product" { found = 1 } END { exit !found }' <<<"$sources"; then
  secret="$(python3 -c 'import json, sys
[client] = [c for c in json.load(open(sys.argv[1]))["clients"] if c["clientId"] == "forgejo"]
print(client["secret"])' "$REALM")"
  say "adding the product login source"
  deadline=$((SECONDS + WAIT_SECONDS))
  until added="$(forgejo_cli admin auth add-oauth --name product --provider openidConnect --key forgejo \
      --secret "$secret" --scopes openid --scopes email --scopes profile \
      --auto-discover-url http://keycloak:8080/realms/defender/.well-known/openid-configuration 2>&1)"; do
    [ "$SECONDS" -lt "$deadline" ] || die "forgejo did not add the product login source within ${WAIT_SECONDS}s: $added"
    sleep 2
  done
fi
say "done"
