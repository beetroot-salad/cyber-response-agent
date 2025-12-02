#!/bin/bash
# @docker @environment
# Discover environment details from a source container

set -euo pipefail

CONTAINER="${1:?Usage: discover-env.sh <container_name>}"

echo "=== Environment Discovery: $CONTAINER ==="
echo ""

# @image - Get source image
echo "## Image"
docker inspect "$CONTAINER" --format='{{.Config.Image}}'
echo ""

# @os - OS information
echo "## OS"
docker exec "$CONTAINER" cat /etc/os-release 2>/dev/null | grep -E '^(ID|VERSION_ID|PRETTY_NAME)=' || echo "Unknown"
echo ""

# @packages - Installed packages (detect package manager)
echo "## Packages"
if docker exec "$CONTAINER" which dpkg >/dev/null 2>&1; then
    docker exec "$CONTAINER" dpkg -l 2>/dev/null | tail -n +6 | awk '{print $2, $3}' | head -50
elif docker exec "$CONTAINER" which rpm >/dev/null 2>&1; then
    docker exec "$CONTAINER" rpm -qa 2>/dev/null | head -50
elif docker exec "$CONTAINER" which apk >/dev/null 2>&1; then
    docker exec "$CONTAINER" apk list --installed 2>/dev/null | head -50
else
    echo "Unknown package manager"
fi
echo ""

# @processes - Running processes
echo "## Processes"
docker exec "$CONTAINER" ps aux 2>/dev/null | head -20 || echo "ps not available"
echo ""

# @cron - Cron jobs
echo "## Cron Jobs"
docker exec "$CONTAINER" cat /etc/crontab 2>/dev/null || echo "No /etc/crontab"
docker exec "$CONTAINER" ls /etc/cron.d/ 2>/dev/null | while read f; do
    echo "--- /etc/cron.d/$f ---"
    docker exec "$CONTAINER" cat "/etc/cron.d/$f" 2>/dev/null
done
