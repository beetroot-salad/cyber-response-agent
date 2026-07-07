---
id: host-state.container-identity-and-uid
status: established
---

## Goal

Determine container metadata (name, image) and resolve a user ID to its /etc/passwd entry on that specific container. Used after Falco alerts fire with container ID but missing name/image context, and to ground privilege-escalation or unauthorized-access hypotheses on the runtime identity available on the target container.

## What to summarize

- Container name (from `container-inspect`)
- Container image repository and tag
- /etc/passwd entry for the given uid (username, shell, home directory, or uid not present)
- One running process as the given uid in the current process tree (to verify uid is actively in use, or none if idle)

## Query

```bash
# Query 1: Container metadata (name, image) by container id
defender-host-state container-inspect ${container_id} --raw

# Query 2: /etc/passwd entry for the target uid — TWO steps. Run the adapter STANDALONE
# (it is captured to gather_raw automatically), then filter the captured payload with jq
# reading STDIN. jq is stdin-compute-only here (it never opens a file), so pipe the
# captured payload in with `cat` rather than `adapter --raw | jq`:
defender-host-state passwd ${container_id} --raw
cat ${passwd_payload} | jq -r --arg uid "${uid}" '.entries[] | select(split(":")[2] == $uid)'

# Query 3: Process tree on the container
defender-host-state proc-tree ${container_id} --raw
```

`${passwd_payload}` is the gather_raw path Query 2's standalone `passwd` call was
captured to (shown in that call's result); the filter selects the entry whose 3rd
`/etc/passwd` field (uid) equals `${uid}`.

## Common pitfalls

- **`container-inspect` takes a container id, not a host name.** It runs daemon-level `docker inspect` (name + image), so — unlike `passwd`/`proc-tree` — it neither warns on unknown-host nor routes through docker exec.
- **Falco `container.name=<NA>` / `container.image.repository=null` are Falco-plugin sentinels, not host-state failures.** Falco's container plugin queries the Docker socket at alert-fire time; `<NA>` means that lookup failed (container may have exited or socket was transiently unavailable). The container ID is still a valid target — confirmed by successful `passwd` / `container-inspect` queries against the partial ID.
- **Container ID is a partial hash.** Pass the 12-char prefix directly; docker resolves partials without a separate lookup.
- **uid is an integer.** Do not confuse with username; /etc/passwd lookup by uid requires exact integer match.
- **Process tree is point-in-time.** A uid with no active processes at capture time is not evidence that the uid has never been used; re-run if the finding is load-bearing.

## Baseline (when applicable)

Compare the runtime passwd entry and process tree against the cmdb's identity stub. If the identity stub lists a different username for the same uid on this container, surface the divergence — it indicates seeding drift or container-level account hijacking.
