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

# cron — the baseline-activity generators in batch 8 need it running now.
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

exec "$@"
