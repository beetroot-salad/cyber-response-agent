# playground-v2/ — VPS-hosted stack

Docker Compose stack running on the Hetzner VPS (`soc-playground`, provisioned by `/workspace/infra/`). Contains the real Elastic stack + ancillary services that make up the v2 playground. Design: `/workspace/docs/playground-environment-v2.md`. This dir is dev-only — not shipped with the soc-agent plugin.

## How compose targets the VPS

All commands run from the devcontainer against the remote Docker engine via SSH:

```bash
cd /workspace/playground-v2
docker --context soc-playground compose up -d
docker --context soc-playground compose ps
docker --context soc-playground compose logs -f elasticsearch
```

The `soc-playground` docker context is created by `.devcontainer/devcontainer.json`'s `postCreateCommand` and survives rebuilds. Verify: `docker context ls`.

**Why `--context` and not `docker context use`:** the devcontainer sets `DOCKER_HOST=unix:///var/run/docker.sock` in its compose file, which overrides `docker context use`. The `--context` flag per command is the workaround.

## Files

| File | Purpose |
|---|---|
| `compose.yml` | The stack (current: Elasticsearch only; Kibana/Fleet/agents incoming) |
| `.env` | Local config with secrets (gitignored). Copy from `.env.example`. |
| `.env.example` | Template — namespaced var names to avoid collisions with v1 `/workspace/.env`. |

## Env var namespacing (important)

`/workspace/.env` is auto-sourced by `.bashrc` into every shell — it carries v1 Wazuh/Elastic credentials including `ELASTIC_PASSWORD=SecretPassword`. When `docker compose` runs, shell env **overrides** `.env` file values, so an unnamespaced `ELASTIC_PASSWORD` in `playground-v2/.env` is silently shadowed by the v1 value.

Fix pattern: **namespace all playground-v2 env vars with a `V2_` prefix** (e.g., `V2_ELASTIC_PASSWORD`). Map them to their unprefixed in-container form inside `compose.yml`:

```yaml
environment:
  - ELASTIC_PASSWORD=${V2_ELASTIC_PASSWORD}  # ES reads ELASTIC_PASSWORD; we get it from V2_ELASTIC_PASSWORD
```

Before adding a new var, check for collision: `grep -E "^VAR_NAME=" /workspace/.env`.

## Current services

### setup (one-shot)

Runs before Elasticsearch. Generates a self-signed CA and node cert into the shared `certs` volume, fixes permissions for UID 1000. After ES is up, sets the `kibana_system` password via the ES security API, then exits. Idempotent: skips cert gen if `ca.zip` and `certs.zip` already exist in the volume.

### elasticsearch (9.3.3)

- Single-node, security on, **TLS on both HTTP and transport** (certs from the `certs` volume).
- `127.0.0.1:9200` on the VPS — not exposed publicly. Access via SSH tunnel (see below).
- Named volume `soc-playground_es_data` holds cluster state. Survives lever-down snapshots (`/var/lib/docker/volumes/` is on the VPS disk).
- Heap pinned via `ES_HEAP` (default 2g); container mem_limit 3g.

### kibana (9.3.3)

- Authenticates to ES as `kibana_system` over TLS (CA from shared volume).
- `127.0.0.1:5601` on the VPS — loopback only. Access via SSH tunnel:
  ```bash
  ssh -L 9200:localhost:9200 -L 5601:localhost:5601 -L 8220:localhost:8220 soc-playground
  # Browser: http://localhost:5601 → Login: elastic / $V2_ELASTIC_PASSWORD (from .env)
  # Fleet UI: http://localhost:5601/app/fleet — should show fleet-server agent online
  ```
- Encryption keys (`V2_KIBANA_ENCRYPTION_KEY`) are reused across saved-objects, security, and reporting — fine for a playground, regenerate per environment in real deployments.
- Named volume `soc-playground_kibana_data`.

### certs volume

Shared between `setup` (writer), `elasticsearch` (ro), `kibana` (ro), and `fleet-server` (ro). The `setup` script invalidates-and-regenerates when `fleet-server/fleet-server.crt` is missing (batch 4d added fleet-server to the cert list). To force full cert regeneration: `docker --context soc-playground compose down -v` (destroys data too).

### fleet-init (one-shot)

Depends on `kibana:service_healthy`. Creates the `fleet-server-policy` in Kibana via `/api/fleet/setup` + `/api/fleet/agent_policies` (idempotent — 409 on rerun is treated as success). Must run before fleet-server because `KIBANA_FLEET_SETUP=1` on the fleet-server container does *not* create this policy in Elastic 9.x — it only initializes Fleet plugin state.

### fleet-server (9.3.3)

- Runs the `elastic-agent` image with `FLEET_SERVER_ENABLE=true` + `KIBANA_FLEET_SETUP=1` + `FLEET_CA`.
- **Must run as `user: "0"`** — the default non-root user can't write to `/usr/share/elastic-agent/state` (volume is root-owned).
- Self-enrolls as a managed agent on first boot (visible in Kibana → Fleet → Agents).
- `127.0.0.1:8220` on the VPS — loopback only (agents on the same VPS reach via Docker DNS `https://fleet-server:8220`; external agents would need port exposed + a real hostname in `FLEET_URL`).
- Named volume `soc-playground_fleet_data` holds agent state. Deleting it forces re-enrollment on next start.

## Adding a new agent

### Host-based (on the VPS itself) — first-time setup already done

Prerequisites, done once:
- `/etc/hosts` on the VPS has `127.0.0.1 elasticsearch fleet-server` (so Docker service names resolve for the host agent)
- `/etc/elastic-agent/ca.crt` is the CA extracted from the `certs` volume
- Fleet's `fleet-default-output` is updated to `https://elasticsearch:9200` with the CA fingerprint pin (see gotcha below)

To enroll another host-based agent (e.g., a second VPS later):

```bash
# 1. On Kibana: create a policy + fetch enrollment token
curl -u elastic:$PW -H 'kbn-xsrf: x' -H 'Content-Type: application/json' -X POST \
  'http://kibana:5601/api/fleet/agent_policies?sys_monitoring=true' \
  -d '{"id":"POLICY_ID","name":"Name","namespace":"default","monitoring_enabled":["logs","metrics"]}'
TOKEN=$(curl -u elastic:$PW -H 'kbn-xsrf: x' \
  'http://kibana:5601/api/fleet/enrollment_api_keys?kuery=policy_id:POLICY_ID' \
  | jq -r '.items[0].api_key')

# 2. On the host: install + enroll
curl -LO https://artifacts.elastic.co/downloads/beats/elastic-agent/elastic-agent-${STACK_VERSION}-amd64.deb
dpkg -i elastic-agent-*.deb
elastic-agent enroll --force --url='https://fleet-server:8220' \
  --enrollment-token="$TOKEN" \
  --certificate-authorities=/etc/elastic-agent/ca.crt
systemctl start elastic-agent
```

### Container-based (future workload hosts)

Same flow, but the agent container will use Docker DNS for `fleet-server` and `elasticsearch` (no /etc/hosts hack needed). Mount the certs volume read-only at `/usr/share/elastic-agent/certs`.

## Workflows

### Bring up / tear down

```bash
docker --context soc-playground compose up -d
docker --context soc-playground compose down          # keeps volumes
docker --context soc-playground compose down -v       # destroys volumes (ES cluster state lost)
```

### Bump Elastic version

1. Probe which tags exist in `docker.elastic.co`:
   ```bash
   for v in 9.4.0 9.3.4 9.3.3; do
     docker --context soc-playground manifest inspect docker.elastic.co/elasticsearch/elasticsearch:$v >/dev/null 2>&1 && echo "AVAILABLE: $v"
   done
   ```
   Note: `https://artifacts-api.elastic.co/v1/versions` often lists versions before their Docker images publish — always verify against the registry.
2. Update `STACK_VERSION` in `.env`.
3. `docker --context soc-playground compose up -d` (volumes preserve data across minor bumps; majors may need upgrade procedures).

### Reset ES data (dev-only)

```bash
docker --context soc-playground compose down -v
docker --context soc-playground compose up -d
```

## Gotchas

- **VPS sysctl `vm.max_map_count=262144`** — required by ES. Set persistently via `/etc/sysctl.d/99-elasticsearch.conf` on the current VPS AND baked into `infra/cloud-init/bootstrap.yaml` for future servers.
- **Volumes live on the VPS.** `docker compose down -v` from the devcontainer destroys them remotely. Use with care.
- **Container image lag.** `docker.elastic.co` registry often trails the artifacts API by a few days. Stick to tags that pass a `manifest inspect` check.
- **Self-signed CA** — the CA lives in the `certs` volume. To connect from outside the cluster (e.g., curl from your laptop), copy the CA out: `docker --context soc-playground exec elasticsearch cat config/certs/ca/ca.crt > /tmp/ca.crt` and pass `--cacert /tmp/ca.crt`.
- **Fleet agentless sync error in Kibana logs** — Kibana's Fleet plugin tries to sync with Elastic's managed Agentless service and complains about missing client certs. Harmless for self-hosted; will be silenced when Fleet is properly configured in a later batch.
- **Kibana `/internal/security/me` is unavailable in current Kibana config** — this is an internal-API restriction, not a bug. Use the UI login at `http://localhost:5601` or the basic-auth REST APIs for scripted access.
- **`fleet-default-output` auto-defaults to `http://localhost:9200` — wrong for our setup.** `KIBANA_FLEET_SETUP=1` creates this output with a plaintext localhost URL; every enrolled agent ships monitoring data there. For us it must be `https://elasticsearch:9200` with `ca_trusted_fingerprint` set. This is a one-time fix via `PUT /api/fleet/outputs/fleet-default-output`. If you lever-down → lever-up, the output config persists in `es_data` — no re-do needed.
- **The VPS host needs `/etc/hosts` entries for Docker service names.** `127.0.0.1 elasticsearch` + `127.0.0.1 fleet-server` so host-based agents can resolve those names. **Persisted via `infra/cloud-init/bootstrap.yaml`** (runcmd with grep-gated append + `manage_etc_hosts: false` to stop cloud-init from clobbering it on lever-up).
- **Fleet Server re-enrolls as a new agent on each container restart.** `KIBANA_FLEET_SETUP=1` on the fleet-server container requests a new service token + new enrollment on every start. Across a lever-down/up cycle the old record becomes an `offline` ghost in Kibana → Fleet → Agents. Cleanup: `POST /api/fleet/agents/<old-id>/unenroll -d '{"revoke":true}'` or via UI. The Fleet Server itself keeps working fine — this is a cosmetic bookkeeping issue.
- **After lever-up, the host elastic-agent may need `systemctl restart elastic-agent`** to shake off cached DNS state and re-resolve `fleet-server` / `elasticsearch` through `/etc/hosts`. Symptom in `elastic-agent status`: fleet checkin `FAILED: lookup fleet-server on 127.0.0.53:53: server misbehaving`. Cure: restart the service. Could script this into the lever-up flow later if it proves recurring.
- **Beats sub-components in `elastic-agent status` show `x509: certificate signed by unknown authority`** even though `ca_trusted_fingerprint` is in the output config. This is a cosmetic issue in Elastic 9.x's component-status view — data still flows to ES (verified by growing doc counts). Usually settles after a few check-in cycles.
