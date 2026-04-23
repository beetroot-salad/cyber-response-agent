#!/bin/bash
# Web-role hook — starts nginx. Runs after base seed + rsyslog/cron, before
# the container's foreground sshd. `service nginx start` daemonizes and
# keeps access/error logs at /var/log/nginx/; batch 7b will ship them to
# Elastic via the nginx integration.
set -euo pipefail
service nginx start >/dev/null
