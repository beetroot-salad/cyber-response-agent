#!/bin/sh
# Start the dev container's jobs daemon (#1475) on its own socket, beside the host daemon this container already
# reaches at /var/run/docker.sock. Idempotent: an answering daemon is left as it is. Use it for live job runs:
#   DOCKER_HOST=unix:///var/run/docker-jobs.sock   (defender/docs/development-operations.md)
# It also makes the jobs' network (`DEFENDER_JOB_NETWORK`, set by docker-compose.yml): a job container joins only a
# bridge network made for it (#1170 N5).
set -eu
SOCK=/var/run/docker-jobs.sock
NETWORK=${DEFENDER_JOB_NETWORK:-defender-jobs}
# Made if missing; a run that loses the race to make it finds it made.
ready() {
  docker -H "unix://$SOCK" network inspect "$NETWORK" >/dev/null 2>&1 \
    || docker -H "unix://$SOCK" network create --driver bridge "$NETWORK" >/dev/null 2>&1 \
    || docker -H "unix://$SOCK" network inspect "$NETWORK" >/dev/null
}
if docker -H "unix://$SOCK" version >/dev/null 2>&1; then ready; exit 0; fi
if pgrep -f 'dockerd --host=unix:///var/run/docker-jobs.sock' >/dev/null; then
  echo "start-jobs-docker: a jobs daemon is running but not answering yet; see /var/log/docker-jobs.log" >&2
  exit 1
fi
# None is running: what a previous one left under /var/run (kept across a container restart) is stale, and its pid
# files would name unrelated processes of this run, which the daemon would take for its own still running.
rm -rf "$SOCK" /var/run/docker-jobs.pid /var/run/docker-jobs
# cgroup v2: a daemon nested in a container can hand controllers (memory, pids) to its containers' cgroups only once
# no process sits in this container's root cgroup, so move them all into a child first (what docker-in-docker does).
if [ -f /sys/fs/cgroup/cgroup.controllers ] && [ ! -d /sys/fs/cgroup/init ]; then
  mkdir -p /sys/fs/cgroup/init
  xargs -rn1 < /sys/fs/cgroup/cgroup.procs > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null || :
  sed -e 's/ / +/g' -e 's/^/+/' < /sys/fs/cgroup/cgroup.controllers > /sys/fs/cgroup/cgroup.subtree_control
fi
# Its own pid file and state folder, so nothing collides with the host daemon's socket under /var/run. Its images and
# containers live in /var/lib/docker, the `jobs-docker-data` volume.
nohup dockerd --host="unix://$SOCK" --pidfile=/var/run/docker-jobs.pid --exec-root=/var/run/docker-jobs \
  >/var/log/docker-jobs.log 2>&1 &
for _ in $(seq 30); do
  if docker -H "unix://$SOCK" version >/dev/null 2>&1; then ready; exit 0; fi
  sleep 1
done
echo "start-jobs-docker: the jobs daemon did not answer within 30s; see /var/log/docker-jobs.log" >&2
exit 1
