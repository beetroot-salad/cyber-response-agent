#!/usr/bin/env bash
# Dev issuer provisioning (#1108 P4, U1/U4, O12/O13). Run from the dev container, at the repo
# root's .devcontainer/ or anywhere: it finds the repo from its own path. Idempotent: every step
# checks before it acts, so a re-run repairs a half-provisioned issuer and changes nothing on a
# provisioned one (except minting a fresh AppRole secret_id when asked with --rotate-secret).
#
#   provision-dev-issuer.sh prepare
#       Make <repo>/playground-issuer/: the dev CA, the openbao TLS certificate, the 32-byte
#       static-seal key and the storage folder, owned by the openbao user (uid 100). Then
#       restart the `openbao` service so it starts on them.
#
#   provision-dev-issuer.sh provision <tenant-id> --bot <login> --repo <owner/name> [--rotate-secret]
#       prepare, then: initialise OpenBao (recovery keys to playground-issuer/recovery/, never
#       printed), the identity-token signing key, the tenant's OIDC role (TTL 600 s, `tenant_id`
#       from entity metadata), an AppRole whose policy reads only that role's token, the entity
#       binding the AppRole to the tenant; the bot's Generic JWT Authorized Integration in
#       Forgejo (issuer https://openbao:8200/v1/identity/oidc, claim `tenant_id` = the tenant,
#       restricted to the repo, write:repository + write:issue); the role's client_id set to the
#       integration's audience; the AppRole client config at playground-issuer/client/issuer.json;
#       the tenant row's forge binding. It checks the bot cannot push `main`, and revokes the root
#       token it used. A later run regenerates a root token from the recovery keys inside the
#       issuer container.
#
#   provision-dev-issuer.sh migrate-forgejo-data
#       Once, before the first `up` with the bind mount: copy the old `forgejo-data` named volume
#       into <repo>/playground-knowledge/ (the old volume is kept until you delete it). Stop the
#       `forgejo` service first. Forgejo 15 -> 17 is not an automatic upgrade: back up and follow
#       Forgejo's upgrade notes (see defender/docs/development-operations.md).
#
# Deployment facts stay in files (P-4): nothing here reads or exports them through the
# environment, and nothing is printed that is secret (root token, recovery keys, secret_id).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$REPO/playground-issuer"
KNOWLEDGE_DATA="$REPO/playground-knowledge"
BAO_CONTAINER=response-openbao
FORGEJO_CONTAINER=response-forgejo
DEVCONTAINER=response-devcontainer
OLD_VOLUME=cyber-response-agent_devcontainer_forgejo-data
ISSUER=https://openbao:8200
IDENTITY="$ISSUER/v1/identity/oidc"
FORGEJO=http://127.0.0.1:3000   # inside the forgejo container
BAO_UID=100
BAO_GID=1000
SIGNING_KEY=tenants

say() { printf '[provision-dev-issuer] %s\n' "$*" >&2; }
die() { say "$*"; exit 1; }

# --- the host path of this repo (docker-outside-of-docker: bind sources are HOST paths) --------

host_repo() {
  local src
  src=$(docker inspect "$DEVCONTAINER" \
    --format '{{range .Mounts}}{{if eq .Destination "/workspace"}}{{.Source}}{{end}}{{end}}')
  [ -n "$src" ] || die "cannot find the host path of /workspace on $DEVCONTAINER"
  printf '%s%s' "$src" "${REPO#/workspace}"
}

# --- prepare: files only --------------------------------------------------------------------

prepare() {
  umask 077
  mkdir -p "$STATE"/{ca,trust,tls,seal,storage,recovery,client}
  if [ ! -s "$STATE/ca/ca.pem" ]; then
    say "making the dev CA"
    openssl req -x509 -newkey rsa:3072 -nodes -days 3650 -subj "/CN=defender dev issuer CA" \
      -keyout "$STATE/ca/ca.key" -out "$STATE/ca/ca.pem" \
      -addext "basicConstraints=critical,CA:true" -addext "keyUsage=critical,keyCertSign,cRLSign" \
      2>/dev/null
  fi
  install -m 0644 "$STATE/ca/ca.pem" "$STATE/trust/dev-issuer-ca.pem"
  if [ ! -s "$STATE/tls/server.pem" ]; then
    say "making the openbao TLS certificate"
    local ext
    ext=$(mktemp)
    printf '%s\n' "subjectAltName=DNS:openbao,DNS:localhost,IP:127.0.0.1" \
      "basicConstraints=CA:false" "keyUsage=digitalSignature,keyEncipherment" \
      "extendedKeyUsage=serverAuth" > "$ext"
    openssl req -newkey rsa:2048 -nodes -subj "/CN=openbao" \
      -keyout "$STATE/tls/server.key" -out "$STATE/tls/server.csr" 2>/dev/null
    openssl x509 -req -days 825 -in "$STATE/tls/server.csr" -CA "$STATE/ca/ca.pem" \
      -CAkey "$STATE/ca/ca.key" -CAcreateserial -extfile "$ext" -out "$STATE/tls/server.pem" \
      2>/dev/null
    rm -f "$ext" "$STATE/tls/server.csr"
  fi
  install -m 0644 "$STATE/ca/ca.pem" "$STATE/tls/ca.pem"
  if [ ! -s "$STATE/seal/unseal" ]; then
    say "making the static seal key"
    head -c 32 /dev/urandom > "$STATE/seal/unseal"
  fi
  chmod 0400 "$STATE/seal/unseal"
  chmod 0755 "$STATE" "$STATE/trust"
  chown -R "$BAO_UID:$BAO_GID" "$STATE/tls" "$STATE/seal" "$STATE/storage"
  chmod 0700 "$STATE/ca" "$STATE/recovery" "$STATE/client"
  if docker inspect "$BAO_CONTAINER" >/dev/null 2>&1; then
    docker restart "$BAO_CONTAINER" >/dev/null
  else
    say "no $BAO_CONTAINER container: run \`docker compose up -d openbao\` from .devcontainer/"
  fi
}

# --- OpenBao, through its own CLI inside the issuer container --------------------------------

bao() {  # bao [token] args...: the CLI inside the issuer container
  local token=$1; shift
  docker exec -i -e BAO_ADDR=https://127.0.0.1:8200 -e BAO_CACERT=/openbao/tls/ca.pem \
    ${token:+-e BAO_TOKEN="$token"} "$BAO_CONTAINER" bao "$@"
}

wait_for_bao() {  # until the issuer answers at all (sealed or not, initialised or not)
  local i
  for i in $(seq 1 60); do
    if bao "" status -format=json 2>/dev/null | jq -e 'has("initialized")' >/dev/null 2>&1; then
      return 0
    fi
    sleep 2
  done
  die "openbao did not answer within 120 s (docker logs $BAO_CONTAINER)"
}

initialise() {
  local status
  status=$(bao "" status -format=json || true)
  if [ "$(jq -r .initialized <<<"$status")" != true ]; then
    say "initialising openbao (recovery keys -> $STATE/recovery/keys.json)"
    bao "" operator init -format=json -recovery-shares=1 -recovery-threshold=1 \
      > "$STATE/recovery/keys.json"
    chmod 0600 "$STATE/recovery/keys.json"
    sleep 2
  fi
  status=$(bao "" status -format=json || true)
  [ "$(jq -r .sealed <<<"$status")" = false ] || die "openbao is sealed after init: check the static seal key"
}

root_token() {  # a root token for this run: the init's (first run) or one regenerated from recovery
  local keys="$STATE/recovery/keys.json" token otp nonce encoded
  token=$(jq -r '.root_token // empty' "$keys")
  if [ -n "$token" ] && bao "$token" token lookup >/dev/null 2>&1; then
    printf '%s' "$token"; return
  fi
  bao "" operator generate-root -cancel >/dev/null 2>&1 || true
  otp=$(bao "" operator generate-root -generate-otp)
  nonce=$(bao "" operator generate-root -init -otp="$otp" -format=json | jq -r .nonce)
  encoded=$(jq -r '.recovery_keys_b64[0]' "$keys" \
    | bao "" operator generate-root -nonce="$nonce" -format=json - | jq -r .encoded_token)
  bao "" operator generate-root -decode="$encoded" -otp="$otp"
}

configure_bao() {  # configure_bao token tenant -> sets ROLE, APPROLE, ROLE_ID
  local t=$1 tenant=$2 accessor entity
  ROLE="tenant-$tenant"
  APPROLE="delivery-$tenant"
  bao "$t" read identity/oidc/key/"$SIGNING_KEY" >/dev/null 2>&1 \
    || bao "$t" write identity/oidc/key/"$SIGNING_KEY" algorithm=RS256 allowed_client_ids='*' \
         rotation_period=24h verification_ttl=2h >/dev/null
  # The role first, so the issuer's JWKS is non-empty before Forgejo first fetches it (Forgejo
  # caches that fetch: an integration created against an empty JWKS keeps failing until restart).
  if ! bao "$t" read identity/oidc/role/"$ROLE" >/dev/null 2>&1; then
    bao "$t" write identity/oidc/role/"$ROLE" key="$SIGNING_KEY" ttl=600 \
      template='{"tenant_id": {{identity.entity.metadata.tenant_id}}}' >/dev/null
  fi
  bao "$t" auth list -format=json | jq -e '."approle/"' >/dev/null \
    || bao "$t" auth enable approle >/dev/null
  printf 'path "identity/oidc/token/%s" {\n  capabilities = ["read"]\n}\n' "$ROLE" \
    | bao "$t" policy write "$ROLE" - >/dev/null
  bao "$t" write auth/approle/role/"$APPROLE" token_policies="$ROLE" token_ttl=10m \
    token_max_ttl=30m secret_id_ttl=0 >/dev/null
  ROLE_ID=$(bao "$t" read -field=role_id auth/approle/role/"$APPROLE"/role-id)
  accessor=$(bao "$t" auth list -format=json | jq -r '."approle/".accessor')
  entity=$(bao "$t" write -format=json identity/entity name="$ROLE" metadata=tenant_id="$tenant" \
    | jq -r '.data.id // empty')
  [ -n "$entity" ] || entity=$(bao "$t" read -format=json identity/entity/name/"$ROLE" | jq -r .data.id)
  bao "$t" write identity/entity/id/"$entity" metadata=tenant_id="$tenant" >/dev/null
  bao "$t" write identity/lookup/entity -format=json alias_name="$ROLE_ID" \
      alias_mount_accessor="$accessor" 2>/dev/null | jq -e '.data.id' >/dev/null \
    || bao "$t" write identity/entity-alias name="$ROLE_ID" canonical_id="$entity" \
         mount_accessor="$accessor" >/dev/null
}

# --- Forgejo: the bot's Authorized Integration (web form; Forgejo 17 has no API for it) -------

fj() { docker exec -i "$FORGEJO_CONTAINER" "$@"; }

bot_login() {  # bot_login bot: a session cookie jar inside the forgejo container
  local bot=$1 password csrf
  # The bot authenticates with issuer JWTs only, so its password is unused: reset it to a
  # throwaway for this one web session.
  password="dev-$(head -c 18 /dev/urandom | base64 | tr -d '/+=')"
  docker exec -u git "$FORGEJO_CONTAINER" forgejo admin user change-password --username "$bot" \
    --password "$password" --must-change-password=false >/dev/null
  fj sh -c "rm -f /tmp/provision.jar"
  csrf=$(fj sh -c "curl -s -c /tmp/provision.jar -b /tmp/provision.jar $FORGEJO/user/login" \
    | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"$//')
  fj sh -c "curl -s -o /dev/null -c /tmp/provision.jar -b /tmp/provision.jar -X POST $FORGEJO/user/login \
    --data-urlencode _csrf='$csrf' --data-urlencode user_name='$bot' --data-urlencode password='$password'"
}

integration_audience() {  # integration_audience name -> audience of the bot's integration `name`, or ""
  local name=$1 id
  for id in $(fj sh -c "curl -s -b /tmp/provision.jar $FORGEJO/user/settings/authorized-integrations" \
      | grep -o 'authorized-integrations/generic/[0-9]*' | sed 's#.*/##' | sort -u); do
    page=$(fj sh -c "curl -s -b /tmp/provision.jar $FORGEJO/user/settings/authorized-integrations/generic/$id")
    if grep -q "id=\"name\" name=\"name\" value=\"$name\"" <<<"$page"; then
      grep -o 'id="audience" name="audience" value="[^"]*"' <<<"$page" | sed 's/.*value="//;s/"$//'
      return
    fi
  done
}

ensure_integration() {  # ensure_integration bot tenant repo -> sets AUDIENCE
  local bot=$1 tenant=$2 repo=$3 name="defender-$2" csrf rules
  bot_login "$bot"
  AUDIENCE=$(integration_audience "$name")
  if [ -z "$AUDIENCE" ]; then
    say "creating the Authorized Integration $name for $bot on $repo"
    rules=$(printf '{"rules":[{"claim":"tenant_id","compare":"eq","value":"%s"}]}' "$tenant")
    csrf=$(fj sh -c "curl -s -b /tmp/provision.jar $FORGEJO/user/settings/authorized-integrations/generic/new" \
      | grep -o 'name="_csrf" value="[^"]*"' | head -1 | sed 's/.*value="//;s/"$//')
    fj sh -c "curl -s -o /dev/null -b /tmp/provision.jar -X POST $FORGEJO/user/settings/authorized-integrations/generic/new \
      --data-urlencode _csrf='$csrf' --data-urlencode name='$name' --data-urlencode issuer='$IDENTITY' \
      --data-urlencode claim_rules='$rules' --data-urlencode resource=repo-specific \
      --data-urlencode selected_repo='$repo' \
      --data-urlencode scope=write:repository --data-urlencode scope=write:issue"
    AUDIENCE=$(integration_audience "$name")
  fi
  fj sh -c "rm -f /tmp/provision.jar"
  [ -n "$AUDIENCE" ] || die "Forgejo did not create the integration $name (is ALLOWED_DOMAINS=openbao, and the issuer's JWKS non-empty?)"
}

# --- the client config, the row's forge binding, and the protection check ---------------------

write_client_config() {  # write_client_config token rotate
  local t=$1 rotate=$2 config="$STATE/client/issuer.json" secret
  if [ "$rotate" = yes ] || [ ! -s "$config" ] || [ "$(jq -r .role_id "$config")" != "$ROLE_ID" ]; then
    secret=$(bao "$t" write -f -field=secret_id auth/approle/role/"$APPROLE"/secret-id)
    jq -n --arg issuer "$IDENTITY" --arg ca "$STATE/trust/dev-issuer-ca.pem" \
      --arg role_id "$ROLE_ID" --arg secret_id "$secret" \
      '{issuer: $issuer, ca_cert: $ca, role_id: $role_id, secret_id: $secret_id}' > "$config.tmp"
    chmod 0600 "$config.tmp"
    mv "$config.tmp" "$config"
    say "wrote the AppRole client config $config"
  fi
}

bind_forge() {  # bind_forge tenant repo: the row's forge: {origin, audience, issuer_role}
  local tenant=$1 repo=$2 row
  row="${DEFENDER_DATA_ROOT:?the dev container sets DEFENDER_DATA_ROOT}/$tenant/tenant.json"
  [ -s "$row" ] || die "no tenant row at $row: run \`python3 defender/cli/tenant.py setup $tenant\` first"
  jq --arg origin "http://forgejo:3000/$repo.git" --arg audience "$AUDIENCE" --arg role "$ROLE" \
    '.forge = {origin: $origin, audience: $audience, issuer_role: $role}' "$row" > "$row.tmp"
  mv "$row.tmp" "$row"
}

check_main_protected() {  # check_main_protected token repo: the bot, through the issuer, cannot push main
  local t=$1 repo=$2 jwt branch
  # A token for the role as the AppRole would get it: the root token has no entity, so log in.
  local secret token
  secret=$(bao "$t" write -f -field=secret_id auth/approle/role/"$APPROLE"/secret-id)
  token=$(bao "" write -field=token auth/approle/login role_id="$ROLE_ID" secret_id="$secret")
  jwt=$(bao "$token" read -field=token identity/oidc/token/"$ROLE")
  bao "$token" token revoke -self >/dev/null
  branch=$(fj sh -c "curl -s -H 'Authorization: Bearer $jwt' $FORGEJO/api/v1/repos/$repo/branches/main")
  if [ "$(jq -r '.user_can_push' <<<"$branch")" != false ]; then
    say "WARNING: the bot can push $repo main (protected=$(jq -r .protected <<<"$branch")): protect it before any drain runs"
  else
    say "$repo main is protected against the bot"
  fi
}

provision() {
  local tenant="" bot="" repo="" rotate=no t
  tenant=${1:-}; shift || true
  while [ $# -gt 0 ]; do
    case $1 in
      --bot) bot=$2; shift 2 ;;
      --repo) repo=$2; shift 2 ;;
      --rotate-secret) rotate=yes; shift ;;
      *) die "unknown argument $1" ;;
    esac
  done
  [ -n "$tenant" ] && [ -n "$bot" ] && [ -n "$repo" ] \
    || die "usage: provision <tenant-id> --bot <login> --repo <owner/name> [--rotate-secret]"
  prepare
  wait_for_bao
  initialise
  t=$(root_token)
  configure_bao "$t" "$tenant"
  ensure_integration "$bot" "$tenant" "$repo"
  bao "$t" write identity/oidc/role/"$ROLE" key="$SIGNING_KEY" ttl=600 client_id="$AUDIENCE" \
    template='{"tenant_id": {{identity.entity.metadata.tenant_id}}}' >/dev/null
  write_client_config "$t" "$rotate"
  bind_forge "$tenant" "$repo"
  check_main_protected "$t" "$repo"
  bao "$t" token revoke -self >/dev/null
  say "done: issuer $IDENTITY, role $ROLE, audience $AUDIENCE"
}

migrate_forgejo_data() {
  docker volume inspect "$OLD_VOLUME" >/dev/null 2>&1 || die "no old volume $OLD_VOLUME"
  if [ -n "$(ls -A "$KNOWLEDGE_DATA" 2>/dev/null)" ]; then
    die "$KNOWLEDGE_DATA is not empty: already migrated?"
  fi
  if [ -n "$(docker ps -q --filter name="^$FORGEJO_CONTAINER\$")" ]; then
    die "stop the forgejo service first (\`docker compose stop forgejo\`)"
  fi
  mkdir -p "$KNOWLEDGE_DATA"
  docker run --rm -v "$OLD_VOLUME":/from:ro -v "$(host_repo)/playground-knowledge":/to \
    codeberg.org/forgejo/forgejo:17.0.0 sh -c 'cp -a /from/. /to/'
  say "copied $OLD_VOLUME into $KNOWLEDGE_DATA; the volume is kept until you delete it"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case ${1:-} in
    prepare) prepare ;;
    provision) shift; provision "$@" ;;
    migrate-forgejo-data) migrate_forgejo_data ;;
    *) die "usage: $0 prepare | provision <tenant-id> --bot <login> --repo <owner/name> | migrate-forgejo-data" ;;
  esac
fi
