#!/usr/bin/env bash
# Sync /workspace/.ssh/config's soc-playground HostName with the current Terraform-known IP,
# and purge the stale host key so the next SSH accepts the new one.
#
#   update-ssh-config.sh            # point the alias at the current server (after `terraform apply`)
#   update-ssh-config.sh --clear    # point the alias at nothing (after the server is destroyed)
#
# --clear exists because a destroyed server's IP returns to Hetzner's pool and is reassigned
# to someone else's machine. An alias left pointing at it is aimed at a stranger, and the
# stanza's `StrictHostKeyChecking accept-new` connects without asking as soon as known_hosts
# lacks an entry to clash with. So teardown must blank the alias, not just stop billing.
# The sentinel is an RFC 2606 reserved TLD: it can never resolve, so the alias fails closed,
# and it still matches the HostName rewrite below so a later lever-up restores it normally.
set -euo pipefail

cd "$(dirname "$0")/.."

SENTINEL="soc-playground.invalid"
CONFIG=/workspace/.ssh/config

MODE="set"
if [ "${1:-}" = "--clear" ]; then
    MODE="clear"
elif [ -n "${1:-}" ]; then
    echo "Usage: $(basename "$0") [--clear]" >&2
    exit 64
fi

if [ ! -f "${CONFIG}" ]; then
    echo "${CONFIG} not found. Create it first." >&2
    exit 1
fi

if [ "${MODE}" = "set" ]; then
    NEW_HOST=$(terraform output -raw ipv4 2>/dev/null || true)
    if [ -z "${NEW_HOST}" ]; then
        echo "No ipv4 output — is the server provisioned?" >&2
        exit 1
    fi
else
    NEW_HOST="${SENTINEL}"
fi

# Rewrite HostName within the 'Host soc-playground' stanza only, and report both the value
# we replaced and the known_hosts file that stanza actually reads.
eval "$(python3 - "${CONFIG}" "${NEW_HOST}" <<'PY'
import pathlib
import re
import shlex
import sys

path, new_host = sys.argv[1], sys.argv[2]
lines = pathlib.Path(path).read_text().splitlines(keepends=True)

out, in_block, old_host, known_hosts = [], False, "", ""
for ln in lines:
    if re.match(r"^Host\s+", ln):
        in_block = ln.split()[1:] == ["soc-playground"]
    if in_block and (m := re.match(r"^(\s*HostName\s+)(\S+)", ln)):
        old_host = m.group(2)
        out.append(m.group(1) + new_host + "\n")
        continue
    if in_block and (m := re.match(r"^\s*UserKnownHostsFile\s+(\S+)", ln)):
        known_hosts = m.group(1)
    out.append(ln)

if not old_host:
    sys.exit("No HostName line in the 'Host soc-playground' stanza — refusing to guess.")

pathlib.Path(path).write_text("".join(out))
print(f"OLD_HOST={shlex.quote(old_host)}")
print(f"KNOWN_HOSTS={shlex.quote(known_hosts)}")
PY
)"

# Purge the stale key from the file the stanza actually reads. A bare `ssh-keygen -R`
# defaults to ~/.ssh/known_hosts, which is NOT where UserKnownHostsFile points — that
# mismatch is why stale keys survived this script until 2026-07-17.
if [ -n "${KNOWN_HOSTS:-}" ] && [ -f "${KNOWN_HOSTS}" ]; then
    for host in "${OLD_HOST}" "${NEW_HOST}"; do
        [ "${host}" = "${SENTINEL}" ] && continue
        ssh-keygen -R "${host}" -f "${KNOWN_HOSTS}" >/dev/null 2>&1 || true
    done
fi

if [ "${MODE}" = "clear" ]; then
    echo "Cleared ${CONFIG}: HostName -> ${NEW_HOST} (was ${OLD_HOST}) — alias now fails closed"
else
    echo "Updated ${CONFIG}: HostName -> ${NEW_HOST}"
fi
