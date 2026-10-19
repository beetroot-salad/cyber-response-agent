#!/usr/bin/env bash
# Lever up: restore VPS from the latest lever-down snapshot.
# If no snapshot exists, falls back to a fresh install (default image).
set -euo pipefail

cd "$(dirname "$0")/.."

if [ -f /workspace/.env ]; then
    set -a; . /workspace/.env; set +a
fi
: "${HCLOUD_TOKEN:?HCLOUD_TOKEN must be set (see /workspace/.env)}"

SERVER_NAME="${SERVER_NAME:-soc-playground}"

if terraform state show hcloud_server.main >/dev/null 2>&1; then
    echo "Server already in Terraform state. Nothing to restore." >&2
    exit 1
fi

echo "==> Looking for latest lever-down snapshot..."
SNAPSHOT_ID=$(hcloud image list -l "project=${SERVER_NAME},role=lever-down" -o json \
    | python3 -c 'import json, sys
imgs = json.load(sys.stdin)
if imgs:
    print(max(imgs, key=lambda i: i["created"])["id"])')

if [ -z "${SNAPSHOT_ID}" ]; then
    echo "No snapshots found. Use 'terraform apply' for a fresh install." >&2
    exit 1
fi

SNAPSHOT_DESC=$(hcloud image describe "${SNAPSHOT_ID}" -o json \
    | python3 -c 'import json, sys; print(json.load(sys.stdin).get("description",""))')
echo "==> Restoring from snapshot ${SNAPSHOT_ID}: ${SNAPSHOT_DESC}"

# Pin snapshot ID for future `terraform apply` calls too (gitignored).
cat > image.auto.tfvars <<EOF
# Written by bin/up.sh — pins the restored snapshot so subsequent apply doesn't revert to fresh image.
# Remove this file and re-apply to return to a fresh Ubuntu install.
image = "${SNAPSHOT_ID}"
EOF

terraform apply -auto-approve

echo ""
echo "Levered up. Updating SSH config..."
"$(dirname "$0")/update-ssh-config.sh"

echo "Done. ssh soc-playground"
