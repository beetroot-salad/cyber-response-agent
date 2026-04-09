#!/usr/bin/env bash
# Wrapper for `docker compose` that works correctly both from the host shell
# and from inside the devcontainer.
#
# The problem this solves: when invoked from inside the devcontainer, the
# docker daemon (running on the host) needs bind mount sources expressed as
# HOST paths, not devcontainer paths. We pass --project-directory pointing
# at the host-side .devcontainer/ so compose resolves relative paths against
# the host filesystem layout. From the host shell, HOST_WORKSPACE points at
# the same directory we're already in, so the same flag is harmless.
#
# Usage:
#   playground/scripts/compose.sh up -d --build target-endpoint
#   playground/scripts/compose.sh ps
#   playground/scripts/compose.sh logs -f wazuh-manager
#
# Requires .devcontainer/.env with HOST_WORKSPACE set. See .env.example.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
DEVCONTAINER_DIR="$REPO_ROOT/.devcontainer"
ENV_FILE="$DEVCONTAINER_DIR/.env"

if [ ! -f "$ENV_FILE" ]; then
    echo "error: $ENV_FILE not found" >&2
    echo "hint: copy .devcontainer/.env.example to .devcontainer/.env and fill in HOST_WORKSPACE" >&2
    exit 1
fi

# shellcheck disable=SC1090
set -a; source "$ENV_FILE"; set +a

if [ -z "${HOST_WORKSPACE:-}" ]; then
    echo "error: HOST_WORKSPACE not set in $ENV_FILE" >&2
    echo "hint: find it with:" >&2
    echo "  docker inspect response-devcontainer --format \\" >&2
    echo "    '{{range .Mounts}}{{if eq .Destination \"/workspace\"}}{{.Source}}{{end}}{{end}}'" >&2
    exit 1
fi

cd "$DEVCONTAINER_DIR"
exec docker compose --project-directory "$HOST_WORKSPACE/.devcontainer" "$@"
