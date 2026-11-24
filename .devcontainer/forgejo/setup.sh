#!/usr/bin/env bash
# The dev Forgejo's people side (#1592): the `product` login source that signs people in with their Keycloak account.
# CI's `forgejo-live` job runs it as dev does.
#
#   COMPOSE="docker compose -f .devcontainer/docker-compose.yml" .devcontainer/forgejo/setup.sh
#
# `COMPOSE` is the compose command to use (default as above, from the repository root). The script:
#
# 1. starts `keycloak` and `forgejo`; compose first runs `forgejo-sessions`, which builds Forgejo's sessions database
#    and the two dev logins on it, password `dev-only-change-me`: `fs_forgejo_dev` in `fs_forgejo` (the settings file's
#    `PROVIDER_CONFIG`) and `fs_lifecycle_dev` in `fs_lifecycle` (the lifecycle's `DEFENDER_LIFECYCLE_FORGE_SESSIONS_DSN`);
# 2. adds the `product` login source when absent, with the shipped realm's `forgejo` client secret. Its id, the
#    lifecycle's `DEFENDER_LIFECYCLE_KEYCLOAK_SOURCE_ID`, is the first column of its line in
#    `forgejo admin auth list` (run as `git` in the `forgejo` container).
#
# The `forgejo` client and its sign-in flow come from the realm file, which Keycloak imports on first start only: on an
# older realm, add them by hand first (defender/CLAUDE.md, "Upgrade from before #1592"). It may be run again: each step
# skips what exists. Progress goes to stderr; it prints nothing a caller parses.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/../.."
COMPOSE="${COMPOSE:-docker compose -f .devcontainer/docker-compose.yml}"
REALM=.devcontainer/keycloak/realm-defender.json
WAIT_SECONDS=180

say() { printf '[forgejo-setup] %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

forgejo_cli() { $COMPOSE exec -T -u git forgejo forgejo "$@"; }

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
