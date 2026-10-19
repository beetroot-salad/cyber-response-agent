# Playground: Elastic Stack

The playground runs an Elastic Security stack (Elasticsearch + Kibana +
Fleet Server + Elastic Agent on the two endpoint containers) alongside the
existing Wazuh stack, so the SOC agent can be exercised against either SIEM.
This doc covers how the stack bootstraps, what's persisted, and the
non-obvious gotchas discovered while wiring it up.

**Not shipped in the plugin** — this is playground/dev infrastructure only.
The `soc-agent/` plugin remains vendor-neutral; per-vendor knowledge lives
under `soc-agent/knowledge/environment/systems/{vendor}/` once onboarded.

## Services (in `.devcontainer/elastic-stack.yml`)

| Service | Purpose | Lifecycle |
|---|---|---|
| `elasticsearch` | Single-node ES 8.15.3, basic license, HTTP internal | long-running |
| `elastic-setup` | One-shot: sets `kibana_system` password, mints fleet-server service token, writes token to `fleet-shared` volume | runs once per stack start |
| `kibana` | Kibana 8.15.3, reachable on host port 5602 (5601 is wazuh-dashboard) | long-running |
| `fleet-preseed` | One-shot: calls `/api/fleet/setup`, overrides default Fleet output to `http://elasticsearch:9200`, creates the Fleet Server agent policy with the `fleet_server` package attached, writes policy id | runs once, idempotent |
| `fleet-server` | Self-enrolling fleet-server agent, HTTP mode, port 8220 | long-running |
| `fleet-setup` | One-shot: creates the Endpoint Agent Policy (`is_default:true`, `system` package attached), fetches enrollment token, writes to `fleet-shared` | runs once, idempotent |
| `target-endpoint` | Existing Ubuntu endpoint + wazuh-agent, now also runs elastic-agent | long-running |
| `monitoring-host` | Existing SSH-probe container, now also runs elastic-agent | long-running |

Bootstrap ordering (compose `depends_on` + `service_completed_successfully`):

```
elasticsearch
     │
     ▼
elastic-setup ───────► kibana ───────► fleet-preseed
                                             │
                                             ▼
                                       fleet-server ─► fleet-setup
                                             │
                       target-endpoint ◄─────┴───── monitoring-host
```

## Ports

| Service | Host port | Container port | Notes |
|---|---|---|---|
| Elasticsearch | 9201 | 9200 | 9200 taken by wazuh-indexer |
| Kibana | 5602 | 5601 | 5601 taken by wazuh-dashboard |
| Fleet Server | 8220 | 8220 | |

Inside the `response-network` containers reach ES at `http://elasticsearch:9200`, Kibana at `http://kibana:5601`, fleet-server at `http://fleet-server:8220`.

## Credentials

`.env` (git-ignored):
- `ELASTIC_PASSWORD` — `elastic` superuser, for API calls
- `KIBANA_SYSTEM_PASSWORD` — set by `elastic-setup` on the `kibana_system` service account
- `KIBANA_ENCRYPTION_KEY` — saved-objects / reporting encryption, ≥32 chars

## Persistence

| State | Persistent across container recreate? | Mechanism |
|---|---|---|
| Elasticsearch indices, Fleet saved objects (policies, outputs, package policies, enrollment tokens) | **Yes** | `elasticsearch-data` named volume |
| Fleet-server service token, policy id, enrollment token | **Yes** | `fleet-shared` named volume; setup scripts are idempotent (keep existing values) |
| `target-endpoint` elastic-agent enrollment (`agent.id`, `fleet.enc`) | **Yes** | `target-endpoint-elastic-state` named volume at `/var/lib/elastic-agent` |
| `monitoring-host` elastic-agent enrollment | **Yes** | `monitoring-host-elastic-state` named volume |
| `fleet-server` self-enrollment | **Yes** | `fleet-server-state` named volume at `/usr/share/elastic-agent/state`; container runs as root (`user: "0:0"`) so the root-owned volume is writable |

So: `docker compose up -d` → `down` → `up -d` should work immediately; the endpoints re-connect with their existing `agent.id`s and resume shipping. A `docker volume rm` (or `down -v`) is the reset button.

Endpoint entrypoints check `/var/lib/elastic-agent/.enrolled` (a self-managed sentinel file created after a successful `elastic-agent enroll`) — if present, skip enrollment and just `elastic-agent run`. `elastic-agent` itself doesn't expose a stable "am I enrolled" marker before run — `state.enc` exists pre-enrollment too, `fleet.enc` isn't created on disk in 8.15 — so the sentinel is the simplest reliable signal.

## Gotchas (learned the hard way)

1. **Kibana 8.x refuses `elastic` superuser.** `ELASTICSEARCH_USERNAME=elastic` makes Kibana fail fast at boot with "value of 'elastic' is forbidden. This is a superuser account that cannot write to system indices that Kibana needs to function." You need `kibana_system` with a known password — handled by the `elastic-setup` one-shot calling `POST /_security/user/kibana_system/_password`.

2. **`curlimages/curl` runs as UID 100 (non-root).** One-shot setup containers that need to write to a named volume (`fleet-shared`) must set `user: "0:0"`, otherwise `sh: can't create /fleet-shared/...: Permission denied`.

3. **Fleet kuery requires fully-qualified saved-object paths.** `kuery=is_default_fleet_server:true` silently matches nothing; `kuery=ingest-agent-policies.attributes.is_default_fleet_server:true` works. This affects any idempotent lookup of existing policies.

4. **Fleet Server has a hardcoded 2-minute self-enrollment timeout.** If its policy doesn't exist *or* the `fleet_server` package isn't attached to it when fleet-server boots, it hangs for 2 min then crashes with `fleet-server failed: timed out waiting for Fleet Server to start after 2m0s`. The `fleet-preseed` one-shot must create the policy + attach the package *before* fleet-server starts — hence `depends_on: fleet-preseed: service_completed_successfully`.

5. **`/api/fleet/setup` does NOT create the fleet-server policy or a default agent policy.** It seeds indices and EPM metadata only. Both policies must be POSTed explicitly (`POST /api/fleet/agent_policies?sys_monitoring=true` with `is_default_fleet_server:true` or `is_default:true` in the body). The `fleet_server` package attachment similarly requires an explicit `POST /api/fleet/package_policies` call with a discovered version string — the API rejects version-less package references with `expected value of type [string] but got [undefined]`.

6. **Fleet's default Elasticsearch output ships to `http://localhost:9200`.** Agents inside docker can't reach that. `fleet-preseed` overrides it via `PUT /api/fleet/outputs/fleet-default-output` with `hosts: ["http://elasticsearch:9200"]`. Without this the beats log `Error dialing dial tcp 127.0.0.1:9200: connect: connection refused` on loop and no telemetry reaches ES.

7. **The `elastic-agent` docker image can't write to `/usr/share/elastic-agent/state` when that path is a named volume.** The image runs as a non-root user; named volumes are root-owned by default, producing `preparing STATE_PATH(...) failed: mkdir .../state/data: permission denied`. Solution used for fleet-server: `user: "0:0"` in the compose service so the agent runs as root. The alternative is an init container that chowns the volume to the agent's uid before fleet-server starts.

8. **`elastic-agent enroll` exits non-zero even on successful server-side registration.** After enrolling, it tries to reload the agent daemon via unix socket; the daemon isn't running yet, so the reload fails and the command exits 1. Server-side the agent *is* registered. The endpoint entrypoints wrap the call with `|| true` and then start `elastic-agent run` directly, which initializes the daemon fresh. Without the `|| true` the `set -e` subshell kills the whole enrollment flow.

9. **`elastic-agent.deb` postinst calls `systemctl` which doesn't exist in a build container.** Post-install fails, dpkg exits 1, image build fails. Stub systemctl during install: `ln -sf /bin/true /usr/bin/systemctl && dpkg -i ... && rm -f /usr/bin/systemctl`. Binary is installed correctly either way; only the systemd service registration was blocked.

10. **`monitoring-host` has a pinned IPv4 (`172.22.0.10`).** Recreating `target-endpoint` while `monitoring-host` is down lets target-endpoint grab `.10`, after which monitoring-host fails to start with "Address already in use". When recreating, bring up `monitoring-host` *first* (with `--no-deps` to avoid dragging target-endpoint in via the `depends_on` edge).

## Inspection one-liners

List all Fleet agents:
```bash
set -a; source /workspace/.env; set +a
curl -s -u "elastic:${ELASTIC_PASSWORD}" -H 'kbn-xsrf: x' \
  http://kibana:5601/api/fleet/agents \
  | python3 -c 'import json,sys; d=json.load(sys.stdin); [print(f"  {a[\"local_metadata\"][\"host\"][\"hostname\"]:20s} {a[\"status\"]}") for a in d["items"]]'
```

Counts in every logs-* / metrics-* data stream:
```bash
curl -s -u "elastic:${ELASTIC_PASSWORD}" \
  'http://elasticsearch:9200/_cat/indices/logs-*,metrics-*?v&h=index,docs.count,store.size&s=index'
```

Tail the most recent auth.log events ingested from endpoints:
```bash
curl -s -u "elastic:${ELASTIC_PASSWORD}" -H 'Content-Type: application/json' \
  'http://elasticsearch:9200/logs-system.auth-*/_search?size=5&sort=@timestamp:desc'
```

Agent component status on an endpoint:
```bash
docker exec target-endpoint /usr/bin/elastic-agent status
```

## Related

- `.devcontainer/elastic-stack.yml` — service definitions
- `playground/target-endpoint/entrypoint.sh` + `playground/monitoring-host/entrypoint.sh` — enrollment logic
- Wazuh stack counterpart: `.devcontainer/wazuh-stack.yml`, `.devcontainer/wazuh-overrides.yml`
