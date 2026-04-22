#!/usr/bin/env bash
# Sync /workspace/.ssh/config's soc-playground HostName with the current Terraform-known IP.
# Also clears the known_hosts entry so the next SSH accepts the new host key.
# Run after any `terraform apply` that may change the server IP.
set -euo pipefail

cd "$(dirname "$0")/.."

IP=$(terraform output -raw ipv4 2>/dev/null || true)
if [ -z "${IP}" ]; then
    echo "No ipv4 output — is the server provisioned?" >&2
    exit 1
fi

CONFIG=/workspace/.ssh/config
if [ ! -f "${CONFIG}" ]; then
    echo "${CONFIG} not found. Create it first." >&2
    exit 1
fi

# Rewrite HostName within the 'Host soc-playground' stanza only.
python3 - "${CONFIG}" "${IP}" <<'PY'
import sys, re, pathlib
path, ip = sys.argv[1], sys.argv[2]
text = pathlib.Path(path).read_text()
lines = text.splitlines(keepends=True)
out, in_block = [], False
for ln in lines:
    if re.match(r"^Host\s+", ln):
        in_block = ln.strip() == "Host soc-playground"
    if in_block and re.match(r"^\s*HostName\s+", ln):
        out.append(re.sub(r"(^\s*HostName\s+)\S+", r"\g<1>" + ip, ln))
    else:
        out.append(ln)
pathlib.Path(path).write_text("".join(out))
PY

ssh-keygen -R "${IP}" >/dev/null 2>&1 || true
echo "Updated ${CONFIG}: HostName -> ${IP}"
