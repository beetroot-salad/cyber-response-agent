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

# Prune the docker daemon before snapshotting. Hetzner snapshots copy every
# disk block ever written vs. the parent cloud image, not just what's live on
# disk now — dangling image layers, stopped intermediate build containers,
# and BuildKit caches all inflate the snapshot (and its creation time) without
# adding anything the restored stack actually needs. `compose up -d --build`
# on the next `up.sh` rebuilds whatever's missing from Docker Hub + apt.
#
# SKIP_PRUNE=1 bypasses for rare "I'm not sure the daemon is healthy" cases.
if [ "${SKIP_PRUNE:-0}" != "1" ]; then
    echo "==> Pruning docker images + buildx cache on VPS (pre-snapshot)"
    # `system prune` without `--volumes` keeps named volumes intact (es_data,
    # kibana_data, agent_state_*, fleet_tokens, certs) — they're what makes
    # lever-up "just work" without re-enrolling or regenerating TLS.
    docker --context "${SERVER_NAME}" system prune -af >/dev/null \
        || echo "   (system prune failed — continuing)"
    docker --context "${SERVER_NAME}" buildx prune -af >/dev/null \
        || echo "   (buildx prune failed — continuing)"
fi

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

# The IP is Hetzner's again the moment the server dies, and it gets reassigned. Leaving the
# alias pointed at it aims `ssh soc-playground` / `docker --context soc-playground` at whoever
# gets it next, and `StrictHostKeyChecking accept-new` will connect without asking once the
# known_hosts entry no longer clashes. Blank it as part of teardown, not as an afterthought.
echo "==> Clearing the SSH alias (the IP is no longer ours)"
bin/update-ssh-config.sh --clear || echo "   (ssh-config clear failed — run bin/update-ssh-config.sh --clear by hand)"

echo ""
echo "Levered down."
echo "  Snapshot:  ${SNAPSHOT_ID}"
echo "  Restore:   infra/bin/up.sh"
echo "  Discard:   hcloud image delete ${SNAPSHOT_ID}"
