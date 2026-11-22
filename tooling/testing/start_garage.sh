#!/bin/sh
# #1546: start a single-node Garage (S3) for the evidence-store tests and lay it out: one zone, one key, one bucket.
# CI's test job runs it after the gVisor step (the daemon restart there kills an earlier container), like Postgres/OpenBao.
# Usage: start_garage.sh [container-name] [host-port]. Prints the DEFENDER_TEST_GARAGE_* variables (and appends them to
# $GITHUB_ENV when set). The config is `docker cp`'d in: a bind mount fails under docker-outside-of-docker (#1082 r3).
set -eu
NAME="${1:-defender-garage}"
PORT="${2:-3900}"
BUCKET=defender-evidence-ci
ACCESS_KEY=GK000000000000000000000001
SECRET_KEY=0000000000000000000000000000000000000000000000000000000000000001
CONF="$(mktemp)"
trap 'rm -f "$CONF"' EXIT
cat >"$CONF" <<'TOML'
metadata_dir = "/var/lib/garage/meta"
data_dir = "/var/lib/garage/data"
db_engine = "sqlite"
replication_factor = 1
rpc_bind_addr = "127.0.0.1:3901"
rpc_secret = "0000000000000000000000000000000000000000000000000000000000000000"

[s3_api]
s3_region = "garage"
api_bind_addr = "0.0.0.0:3900"
TOML
docker create --name "$NAME" --runtime runc -p "127.0.0.1:$PORT:3900" dxflrs/garage:v2.1.0 >/dev/null
docker cp "$CONF" "$NAME:/etc/garage.toml"
docker start "$NAME" >/dev/null
garage() { docker exec "$NAME" /garage "$@" 2>/dev/null; }
timeout 60 sh -c "until docker exec $NAME /garage status >/dev/null 2>&1; do sleep 1; done"
NODE="$(garage status | awk '/HEALTHY/{f=1;next} f&&/^[0-9a-f]{16}/{print $1;exit}')"
garage layout assign -z dc1 -c 1G "$NODE" >/dev/null
garage layout apply --version 1 >/dev/null
garage key import --yes -n ci "$ACCESS_KEY" "$SECRET_KEY" >/dev/null
garage bucket create "$BUCKET" >/dev/null
garage bucket allow --read --write --owner "$BUCKET" --key ci >/dev/null
VARS="DEFENDER_TEST_GARAGE_ENDPOINT=http://127.0.0.1:$PORT
DEFENDER_TEST_GARAGE_ACCESS_KEY=$ACCESS_KEY
DEFENDER_TEST_GARAGE_SECRET_KEY=$SECRET_KEY
DEFENDER_TEST_GARAGE_BUCKET=$BUCKET"
echo "$VARS"
if [ -n "${GITHUB_ENV:-}" ]; then echo "$VARS" >>"$GITHUB_ENV"; fi
