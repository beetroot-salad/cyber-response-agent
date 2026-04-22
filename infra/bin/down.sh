#!/usr/bin/env bash
# Lever down: snapshot the playground VPS, then destroy the server.
# Firewall + SSH keys remain (both free on Hetzner). Snapshot storage: ~€0.01/GB/mo.
# Billing stops on server destroy. Restore via `up.sh`.
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -f /workspace/.env ]; then
    set -a; . /workspace/.env; set +a
fi
: "${HCLOUD_TOKEN:?HCLOUD_TOKEN must be set (see /workspace/.env)}"

SERVER_NAME="${SERVER_NAME:-soc-playground}"

if ! terraform state show hcloud_server.main >/dev/null 2>&1; then
    echo "Server not in Terraform state — already levered down?" >&2
    exit 1
fi

TIMESTAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DESCRIPTION="${SERVER_NAME} lever-down ${TIMESTAMP}"

echo "==> Taking snapshot: ${DESCRIPTION}"
hcloud server create-image --type=snapshot \
    --description "${DESCRIPTION}" \
    --label "project=${SERVER_NAME}" \
    --label "managed=terraform" \
    --label "role=lever-down" \
    "${SERVER_NAME}"

SNAPSHOT_ID=$(hcloud image list -l "project=${SERVER_NAME},role=lever-down" -o json \
    | python3 -c 'import json,sys; imgs=json.load(sys.stdin); print(max(imgs,key=lambda i:i["created"])["id"])')

echo "==> Snapshot created: ID ${SNAPSHOT_ID}"

echo "==> Destroying server (firewall + SSH keys stay)..."
terraform destroy -target=hcloud_server.main -auto-approve

echo ""
echo "Levered down."
echo "  Snapshot:  ${SNAPSHOT_ID}"
echo "  Restore:   infra/bin/up.sh"
echo "  Discard:   hcloud image delete ${SNAPSHOT_ID}"
