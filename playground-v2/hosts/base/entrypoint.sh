#!/bin/bash
# Shared host-container entrypoint. Does the minimum every role-host needs:
#   1. Seed UNIX users from inventory.yaml (HOST_NAME-scoped).
#   2. Start rsyslog + cron in the background.
#   3. If the image installed a role start hook, run it (starts nginx/postgres/etc.).
#   4. Exec whatever CMD compose passes (default: sshd -D -e).
set -euo pipefail

if [[ -z "${HOST_NAME:-}" ]]; then
  echo "[entrypoint] FATAL: HOST_NAME not set" >&2
  exit 1
fi

python3 /opt/soc-playground/seed-users.py

# rsyslog's service wrapper is awkward in containers (expects /proc/1 to be
# init). Launching rsyslogd directly works and keeps logs flowing to
# /var/log/auth.log + /var/log/syslog, which is where every triage path
# looks first.
/usr/sbin/rsyslogd

# cron is still started for any future per-host cron drops (e.g., logrotate),
# but the batch-8 baseline generators run under a Python scheduler, not crontabs
# — spec: "one shared scheduler process per identity/host pair, not a pile
# of crontabs" (docs/playground-environment-v2.md §Baseline activity generators).
service cron start >/dev/null

# Role hook is installed by the web/db stages; absent on plain hosts.
if [[ -x /opt/soc-playground/role-start.sh ]]; then
  /opt/soc-playground/role-start.sh
fi

# Enroll + launch elastic-agent in the background (Fleet-managed). Runs after
# the role hook so the agent sees a fully-set-up host at first check-in.
if [[ -n "${HOST_ROLE:-}" ]]; then
  /usr/local/bin/agent-enroll.sh
fi

# Baseline activity scheduler (batch 8). One Python process per host, spawns a
# dispatch thread per (action, identity) binding from
# /opt/soc-playground/baseline/catalog.yaml. Runs as root so it can `runuser`
# as realm identities; writes a dispatch log to /var/log/baseline.log for
# debugging (not shipped to ES). Disable by setting BASELINE_ENABLED=false
# (e.g., for clean attack-scenario runs in batch 10).
if [[ "${BASELINE_ENABLED:-true}" == "true" ]]; then
  touch /var/log/baseline.log
  nohup python3 /opt/soc-playground/baseline/scheduler.py \
    >> /var/log/baseline.log 2>&1 &
fi

exec "$@"
