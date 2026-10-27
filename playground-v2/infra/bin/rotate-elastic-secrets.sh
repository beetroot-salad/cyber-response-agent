#!/usr/bin/env bash
# Rotate the playground's Elastic secrets in one pass:
#   - the `elastic` superuser password            (V2_ELASTIC_PASSWORD)
#   - the `kibana_system` password, made distinct  (V2_KIBANA_PASSWORD)
#   - Kibana's encryption key                      (V2_KIBANA_ENCRYPTION_KEY; the old one is kept
#                                                   as V2_KIBANA_ENCRYPTION_KEY_PREVIOUS so saved
#                                                   objects encrypted with it stay readable)
# then recreate the stack and rotate Fleet's message-signing key pair.
#
# Every value is generated here and written straight into .env. None is printed, and none is
# passed to any process as an argument: each reaches curl as config on stdin (`-K -`), because
# an argument is read by Falco and by host process monitoring and shipped into Elasticsearch.
#
# Run from a checkout whose compose.yml and kibana/ carry the secret-hygiene changes (Kibana
# reads its secrets from kibana.yml, not --flags). Requires .env in playground-v2/.
set -euo pipefail

PLAYGROUND="$(cd "$(dirname "$0")/../.." && pwd)"
ENV_FILE="${PLAYGROUND}/.env"
CTX="${SOC_PLAYGROUND_DOCKER_CONTEXT:-soc-playground}"
cd "${PLAYGROUND}"

[ -f "${ENV_FILE}" ] || { echo "no .env at ${ENV_FILE}" >&2; exit 2; }
[ -f kibana/kibana.yml ] || { echo "this checkout lacks kibana/kibana.yml — wrong branch" >&2; exit 2; }

get() { sed -n "s/^$1=//p" "${ENV_FILE}" | tail -n1; }
OLD_EP="$(get V2_ELASTIC_PASSWORD)"
OLD_KEY="$(get V2_KIBANA_ENCRYPTION_KEY)"
[ -n "${OLD_EP}" ] && [ -n "${OLD_KEY}" ] || { echo "V2_ELASTIC_PASSWORD / V2_KIBANA_ENCRYPTION_KEY missing from .env" >&2; exit 2; }

# Hex only: these land in .env, curl config and shell, where $ " \ # * all need care.
NEW_EP="$(openssl rand -hex 24)"
NEW_KP="$(openssl rand -hex 24)"
NEW_KEY="$(openssl rand -hex 32)"

es_set_password() {  # user, new password — authenticated with the OLD elastic password
    local out
    out="$(printf 'user = "elastic:%s"\ndata = {"password":"%s"}\n' "${OLD_EP}" "$2" \
        | docker --context "${CTX}" exec -i elasticsearch \
            curl -sS -k -K - -H 'Content-Type: application/json' \
            -X POST "https://localhost:9200/_security/user/$1/_password")"
    [ "${out}" = "{}" ] || { echo "setting the $1 password failed: ${out}" >&2; exit 1; }
    echo "  $1 password set"
}

backup="${ENV_FILE}.bak-$(date -u +%Y%m%dT%H%M%SZ)"
( umask 077; cat "${ENV_FILE}" > "${backup}" )
echo "-> .env backed up to ${backup} (holds the OLD secrets; delete it once the stack is healthy)"

echo "-> rotating passwords in Elasticsearch"
es_set_password kibana_system "${NEW_KP}"
es_set_password elastic "${NEW_EP}"

echo "-> writing the new values into .env"
set_var() {  # name, value — rewrite in place (through a symlink, too) or append
    local tmp; tmp="$(mktemp)"
    awk -v k="$1" 'BEGIN { FS = OFS = "=" } $1 == k { next } { print }' "${ENV_FILE}" > "${tmp}"
    { cat "${tmp}"; printf '%s=%s\n' "$1" "$2"; } > "${ENV_FILE}"
    rm -f "${tmp}"
}
set_var V2_ELASTIC_PASSWORD "${NEW_EP}"
set_var V2_KIBANA_PASSWORD "${NEW_KP}"
set_var V2_KIBANA_ENCRYPTION_KEY_PREVIOUS "${OLD_KEY}"
set_var V2_KIBANA_ENCRYPTION_KEY "${NEW_KEY}"

echo "-> recreating the services that hold these secrets in their container env"
# Only these: a whole-stack `up` from another checkout also recreates services with relative
# bind mounts (ticket-server's seed), which resolve against this checkout's path on the VPS.
docker --context "${CTX}" compose up -d --build --no-deps \
    elasticsearch es-init kibana fleet-server fleet-init fleet-host-policies fleet-outputs-reconciler

echo "-> waiting for Kibana"
for _ in $(seq 1 60); do
    if printf 'user = "elastic:%s"\n' "${NEW_EP}" \
        | docker --context "${CTX}" exec -i kibana curl -fsS -K - http://localhost:5601/api/status \
        | grep -q '"level":"available"'; then
        break
    fi
    sleep 10
done

echo "-> re-encrypting every saved object with the new key"
# Kibana keeps a single decrypt-only key. Without this, the next rotation drops the key that
# today's objects (rule API keys, Fleet tokens) are still encrypted with, and they go unreadable.
printf 'user = "elastic:%s"\n' "${NEW_EP}" \
    | docker --context "${CTX}" exec -i kibana curl -sS -K - -H 'kbn-xsrf: x' \
        -X POST 'http://localhost:5601/api/encrypted_saved_objects/_rotate_key?batch_size=1000'
echo

echo "-> rotating Fleet's message-signing key pair"
printf 'user = "elastic:%s"\n' "${NEW_EP}" \
    | docker --context "${CTX}" exec -i kibana curl -sS -K - -H 'kbn-xsrf: x' \
        -X POST 'http://localhost:5601/api/fleet/message_signing_service/rotate_key_pair?acknowledge=true'
echo

echo "-> done. Delete ${backup} once you have checked the stack."
