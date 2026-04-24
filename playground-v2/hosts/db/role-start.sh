#!/bin/bash
# DB-role hook — starts the default postgres cluster Ubuntu installs.
# Auth, schema seeding, and pgaudit wiring happen in later batches (8/9);
# 7a just needs the daemon up so the container's service surface isn't empty.
set -euo pipefail
service postgresql start >/dev/null
