#!/bin/sh
# Create the spike cluster on the dev container's jobs daemon (start-jobs-docker). k3d v5.8.3, k3s v1.33.9-k3s1.
# gVisor: the host's runsc, its shim, and (this runsc release) its sidecar folder gvisor-bin, mounted into the node.
set -eu
S=$(cd "$(dirname "$0")" && pwd); export DOCKER_HOST=unix:///var/run/docker-jobs.sock
"${K3D:-$S/bin/k3d}" cluster create spike1509 --image rancher/k3s:v1.33.9-k3s1 --servers 1 --agents 0 --no-lb \
  --api-port 127.0.0.1:16443 --servers-memory 3g \
  --k3s-arg '--disable=traefik,servicelb,metrics-server@server:0' \
  --volume /usr/bin/runsc:/usr/local/bin/runsc@server:0 \
  --volume /usr/bin/containerd-shim-runsc-v1:/usr/local/bin/containerd-shim-runsc-v1@server:0 \
  --volume /usr/bin/gvisor-bin:/usr/local/bin/gvisor-bin@server:0 \
  --volume "$S/node/config.toml.tmpl:/var/lib/rancher/k3s/agent/etc/containerd/config.toml.tmpl@server:0" \
  --volume "$S/node:/etc/spike@server:0" --wait --timeout 240s

