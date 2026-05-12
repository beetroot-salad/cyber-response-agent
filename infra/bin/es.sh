#!/usr/bin/env bash
# Thin wrapper: curl against the playground Elasticsearch via the remote
# docker context. Auths with the container's own ELASTIC_PASSWORD env var
# (avoids the /workspace/.env shadow), so no secrets need to live here.
set -euo pipefail

usage() {
    cat <<'EOF'
Usage: infra/bin/es.sh <path> [curl-args...]

Curl a path on the playground Elasticsearch via the remote docker context.
The path is passed verbatim to curl (single-quote it to keep ?/* intact);
extra args are forwarded to curl.

Examples:
  infra/bin/es.sh /
  infra/bin/es.sh '/_cat/indices?v&s=index'
  infra/bin/es.sh '/logs-falco.alerts-*/_search' \
      -H 'Content-Type: application/json' \
      -d '{"size":2,"sort":[{"@timestamp":"desc"}]}'

Environment:
  SOC_PLAYGROUND_DOCKER_CONTEXT   docker context (default: soc-playground)
  SOC_PLAYGROUND_ES_CONTAINER     ES container   (default: elasticsearch)
EOF
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
    "")
        usage >&2
        exit 2
        ;;
esac

CONTEXT="${SOC_PLAYGROUND_DOCKER_CONTEXT:-soc-playground}"
CONTAINER="${SOC_PLAYGROUND_ES_CONTAINER:-elasticsearch}"
PATH_ARG="$1"; shift

# Build the curl command for the remote shell. Path is single-quoted to
# survive globs (?, *) intact; extra args are appended verbatim via "$@".
exec docker --context "${CONTEXT}" exec -i "${CONTAINER}" \
    sh -c 'exec curl -sS -k -u "elastic:${ELASTIC_PASSWORD}" "$@"' \
    -- "https://localhost:9200${PATH_ARG}" "$@"
