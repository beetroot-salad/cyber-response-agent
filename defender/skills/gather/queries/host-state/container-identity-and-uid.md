---
id: host-state.container-identity-and-uid
status: established
---

## Goal

Determine container metadata (name, image) and resolve a user ID to its /etc/passwd entry on that specific container. Used after Falco alerts fire with container ID but missing name/image context, and to ground privilege-escalation or unauthorized-access hypotheses on the runtime identity available on the target container.

## What to summarize

- Container name (from docker inspect or host-state container resolver)
- Container image repository and tag
- /etc/passwd entry for the given uid (username, shell, home directory, or uid not present)
- One running process as the given uid in the current process tree (to verify uid is actively in use, or none if idle)

## Query

```bash
# Query 1: Container metadata (name, image) — direct docker inspect; no host_state_cli.py verb exists
docker --context soc-playground inspect ${container_id} \
  --format '{"name":{{json .Name}},"image":{{json .Config.Image}}}'

# Query 2: /etc/passwd lookup for uid
defender/scripts/tools/host_state_cli.py passwd ${container_id} --raw | python3 -c "
import sys, json
data = json.load(sys.stdin)
uid = ${uid}
for e in data.get('entries', []):
    parts = e.split(':')
    if len(parts) >= 3 and parts[2] == str(uid):
        print(e)
"

# Query 3: Process tree on the container
defender/scripts/tools/host_state_cli.py proc-tree ${container_id} --raw
```

## Common pitfalls

- **`container-inspect` is not an implemented host_state_cli.py verb.** Use `docker --context soc-playground inspect` directly for name/image metadata; host_state_cli.py only supports `proc-tree`, `passwd`, `authorized-keys`, `fim-checksum`, `package-list`.
- **`docker inspect` does not accept `--raw`**: when `raw: true` is passed as a dispatch param for a sweep invocation that routes through the docker inspect path (Query 1), the runner appends `--raw` to the docker inspect command, producing exit 125 (`unknown flag: --raw`). The `--raw` option is valid for `host_state_cli.py` subcommands only (Queries 2 and 3, where it is already hardcoded in the template body). Omit `raw` from dispatch params when the goal is container metadata retrieval via Query 1.
- **Falco `container.name=<NA>` / `container.image.repository=null` are Falco-plugin sentinels, not host-state failures.** Falco's container plugin queries the Docker socket at alert-fire time; `<NA>` means that lookup failed (container may have exited or socket was transiently unavailable). The container ID is still a valid docker exec target — confirmed by successful `passwd` queries against the partial ID.
- **Container ID is a partial hash.** Pass the 12-char prefix directly; docker resolves partials without a separate lookup.
- **uid is an integer.** Do not confuse with username; /etc/passwd lookup by uid requires exact integer match.
- **Process tree is point-in-time.** A uid with no active processes at capture time is not evidence that the uid has never been used; re-run if the finding is load-bearing.

## Baseline (when applicable)

Compare the runtime passwd entry and process tree against the cmdb's identity stub. If the identity stub lists a different username for the same uid on this container, surface the divergence — it indicates seeding drift or container-level account hijacking.
