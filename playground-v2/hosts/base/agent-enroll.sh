#!/bin/bash
# Enroll this host's elastic-agent into the Fleet policy for HOST_ROLE, then
# run it in the background. Idempotent: sentinel file skips re-enrollment on
# container recreate so the agent.id stays stable and we don't pile up stale
# "offline" ghosts in Fleet → Agents.
#
# Depends on:
#   /fleet-tokens/${HOST_ROLE}.token   (written by fleet-host-policies init)
#   /fleet-certs/ca/ca.crt             (shared certs volume — mounted ro)
#   HOST_ROLE env                      (set per service by compose)
set -euo pipefail

if [[ -z "${HOST_ROLE:-}" ]]; then
  echo "[agent-enroll] FATAL: HOST_ROLE env not set" >&2
  exit 1
fi

TOKEN_FILE=/fleet-tokens/${HOST_ROLE}.token
CA_CERT=/fleet-certs/ca/ca.crt
STATE_DIR=/var/lib/elastic-agent       # persisted via per-host named volume
SENTINEL=${STATE_DIR}/.enrolled

# Wait for the enrollment token — fleet-host-policies may still be running.
# 60 × 5s = 5 min ceiling matches v1 target-endpoint, enough even for a cold
# Kibana on lever-up.
for _ in $(seq 1 60); do
  [[ -s "$TOKEN_FILE" ]] && break
  sleep 5
done
if [[ ! -s "$TOKEN_FILE" ]]; then
  echo "[agent-enroll] FATAL: token $TOKEN_FILE not available after 5min" >&2
  exit 1
fi

mkdir -p "$STATE_DIR"

if [[ ! -f "$SENTINEL" ]]; then
  echo "[agent-enroll] first run for role=$HOST_ROLE — enrolling"
  # `|| true` on enroll: post-enrollment the deb tries a service-manager
  # reload that fails in a systemd-less container, but the server-side
  # registration has already completed at that point. Matches v1's pattern
  # (playground/target-endpoint/entrypoint.sh).
  elastic-agent enroll --force \
    --url=https://fleet-server:8220 \
    --enrollment-token="$(cat "$TOKEN_FILE")" \
    --certificate-authorities="$CA_CERT" \
    >/var/log/elastic-agent-enroll.log 2>&1 || true
  touch "$SENTINEL"
else
  echo "[agent-enroll] sentinel present — reusing enrolled state"
fi

# Run the agent in the background; logs go where v1 expects them. The host
# container's foreground (sshd) stays PID-1-child, so sshd crash → container
# restart still applies (agent crash just leaves a logline).
nohup elastic-agent run >/var/log/elastic-agent.log 2>&1 &
echo "[agent-enroll] elastic-agent running (PID $!)"
