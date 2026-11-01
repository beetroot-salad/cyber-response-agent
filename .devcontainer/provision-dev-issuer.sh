#!/usr/bin/env bash
# Dev issuer files (#1108 P4, U1/U4, O12/O13). Run from the dev container, at the repo root's
# .devcontainer/ or anywhere: it finds the repo from its own path. Idempotent: every step checks
# before it acts, so a re-run changes nothing on a prepared issuer.
#
#   provision-dev-issuer.sh prepare
#       Make <repo>/playground-issuer/: the dev CA, the openbao TLS certificate, the 32-byte
#       static-seal key and the storage folder, owned by the openbao user (uid 100). Then
#       restart the `openbao` service so it starts on them.
#
#   provision-dev-issuer.sh migrate-forgejo-data
#       Once, before the first `up` with the bind mount: copy the old `forgejo-data` named volume
#       into <repo>/playground-knowledge/ (the old volume is kept until you delete it). Stop the
#       `forgejo` service first. Forgejo 15 -> 17 is not an automatic upgrade: back up and follow
#       Forgejo's upgrade notes (see defender/docs/development-operations.md).
#
# This script makes files and nothing else. A tenant's credentials (its OpenBao role, AppRole and
# entity, its Forgejo bot and integration, its secret file) come from the lifecycle service
# (`python -m defender.lifecycle serve`, #1214), not from here; the old `provision` subcommand is
# gone. Nothing here reads or exports deployment facts through the environment, and nothing is
# printed that is secret (P-4).
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STATE="$REPO/playground-issuer"
KNOWLEDGE_DATA="$REPO/playground-knowledge"
BAO_CONTAINER=response-openbao
FORGEJO_CONTAINER=response-forgejo
DEVCONTAINER=response-devcontainer
OLD_VOLUME=cyber-response-agent_devcontainer_forgejo-data
BAO_UID=100
BAO_GID=1000

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
  # `SSL_CERT_DIR` names this folder: Go reads every file in it, but OpenSSL (Python's TLS client,
  # so every host process minting a tenant token) finds a CA only under its hash name.
  openssl rehash "$STATE/trust" >/dev/null
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
    migrate-forgejo-data) migrate_forgejo_data ;;
    *) die "usage: $0 prepare | migrate-forgejo-data" ;;
  esac
fi
