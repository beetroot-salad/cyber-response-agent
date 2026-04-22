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

### keycloak (26.x) + keycloak-init

Identity tier — OIDC/SAML IdP with scripted user/role seeding (see v2 §Identities).

- **Realm config lives in `keycloak/realm.yaml`** (committed). Contains realm settings, roles (`sre-ops`, `developer`, `dba`, `service-account`, `contractor`), placeholder OIDC client, and ~13 seed users. Edit YAML, `compose up -d` — see "Re-seed users/roles" below for the import caveat.
- **YAML → JSON via `keycloak-init` one-shot**: `python:3.12-alpine` runs `seed.py` which is a straight `yaml.safe_load → json.dumps`. Output lands on the shared `keycloak_import` volume at `/import/realm.json`.
- **Keycloak imports on first boot**: `start-dev --import-realm` reads anything under `/opt/keycloak/data/import/`. `--import-realm` **skips the realm if it already exists** — it does not diff/update.
- **`start-dev` + H2**: dev-mode Keycloak uses embedded H2 in `/opt/keycloak/data/h2/`, persisted via the `keycloak_data` named volume. Fine for a playground; production Keycloak would need `start` mode + PostgreSQL.
- **`127.0.0.1:8080` on the VPS** — loopback only. Access via SSH tunnel:
  ```bash
  ssh -L 9200:localhost:9200 -L 5601:localhost:5601 -L 8220:localhost:8220 -L 8080:localhost:8080 soc-playground
  # Keycloak admin: http://localhost:8080/admin  → login: $V2_KEYCLOAK_ADMIN / $V2_KEYCLOAK_ADMIN_PASSWORD
  # Account console (as a seed user): http://localhost:8080/realms/soc-playground/account → e.g., sre.alice / changeme
  ```
- **Config files shipped via a build-context image** (`keycloak/Dockerfile`). The init container is `FROM python:3.12-alpine` + `COPY realm.yaml seed.py`, so the build context tar-streams those files to the remote daemon at `compose build` time — no pre-stage on the VPS needed. Note: the obvious alternative — Docker Compose `configs:` with `file: ./keycloak/realm.yaml` — does **not** work against a remote context. `file:` resolves the path on the daemon side, and `/workspace/` doesn't exist on the VPS. (`configs.*.content:` with inline YAML would also work but buries a 5KB seed inside compose.yml.)
- **Events enabled**: realm config sets `eventsEnabled: true` with the `jboss-logging` listener. The listener writes at DEBUG level, so stdout is silent unless the log level is raised — we set `KC_LOG_LEVEL=INFO,org.keycloak.events:debug` so only the events stream is verbose (root stays INFO). Sample line: `type="LOGIN", realmName="soc-playground", clientId="soc-playground-app", username="sre.alice", ipAddress="127.0.0.1", grant_type="password", ...`. Events are also stored in the realm DB and viewable in Kibana → (later) or Keycloak UI → Events.
- **Named volumes**: `soc-playground_keycloak_data` (H2 DB + server state), `soc-playground_keycloak_import` (generated realm.json — rewritten on every `compose up`).

#### Re-seed users/roles

Because `--import-realm` skips existing realms, changing `realm.yaml` has no effect on an already-imported realm. Three ways to apply edits:

1. **Nuke and re-import** (playground-level, loses Keycloak-side edits like UI-added users):
   ```bash
   docker --context soc-playground compose down
   docker --context soc-playground volume rm soc-playground_keycloak_data
   docker --context soc-playground compose up -d
   ```
2. **Admin CLI** (`kcadm.sh`) inside the container — surgical, preserves runtime state. Example pattern for adding a user:
   ```bash
   docker --context soc-playground exec keycloak /opt/keycloak/bin/kcadm.sh config credentials \
     --server http://localhost:8080 --realm master \
     --user "$V2_KEYCLOAK_ADMIN" --password "$V2_KEYCLOAK_ADMIN_PASSWORD"
   docker --context soc-playground exec keycloak /opt/keycloak/bin/kcadm.sh create users \
     -r soc-playground -s username=... -s enabled=true -s email=...
   ```
3. **Partial import via admin UI** — Keycloak → realm → Manage → Import, with "If a resource exists" = Overwrite.

The committed YAML is source-of-truth; if #2 is used for substantive changes, fold them back into `realm.yaml` so a fresh lever-up matches.

### unbound (alpine + unbound 1.20.x)

Recursive DNS resolver + playground-internal zone. Built from `playground-v2/unbound/Dockerfile` (`FROM alpine:3.20` + `apk add unbound`).

- Config: `playground-v2/unbound/unbound.conf` — `log-queries`/`log-replies` on, writes to stdout (no file, no syslog).
- Forwards `.` to `1.1.1.1` + `9.9.9.9` over plain Do53 (TLS upstream is a hardening follow-up).
- Local zone: `soc-playground.local.` (empty — batch 7 populates A records per role host).
- In-network access only (`http://unbound:53` from other containers). No host port.
- Log shape: `172.18.0.8 github.com. A IN` (query); `172.18.0.8 github.com. A IN NOERROR 0.006902 0 55` (reply — adds rcode, RTT, flags, size).

### squid (ubuntu/squid:latest, 6.13)

Forward HTTP(S) proxy with basic-auth user attribution.

- Config + bcrypt passwd: built in-image. `playground-v2/squid/Dockerfile` is two-stage: an `alpine + apache2-utils` builder generates bcrypt entries for the 13 Keycloak seed users (same plaintext `changeme`), copied into the runtime image's `/etc/squid/passwd`.
- Access log format `soc`: `%ts.%03tu %6tr %>a %[un %Ss/%03>Hs %<st %rm %ru %Sh/%<a %mt` — fields: timestamp, elapsed, client IP, **username**, result, bytes, method, URL, peer, mime.
- Sample line: `1776879941.428 102 172.18.0.8 sre.alice TCP_TUNNEL/200 5336 CONNECT example.com:443 HIER_DIRECT/172.66.147.243 -`.
- Listens on `3128/tcp` (docker network, no host port). `forwarded_for delete` + `via off` keep internal identity out of upstream requests.
- The user list in the Dockerfile must stay in sync with `keycloak/realm.yaml`. Cross-file invariant maintained by humans; no validator.

### zeek (zeek/zeek:lts, 8.0.x)

Passive monitor producing JSON conn/dns/http/ssl/files logs to the `zeek_logs` named volume.

- Runs with `network_mode: host` + `cap_add: [NET_ADMIN, NET_RAW]` so libpcap sees real VPS interfaces.
- `entrypoint.sh` picks the interface at startup: prefers the soc-playground compose bridge (`br-*`, UP) so it sees inter-container traffic; falls back to `eth0` (captures VPS↔public only). Bridge names are dynamic (`br-<12-hex>`), can't hardcode.
- Uses the `Zeek_AF_Packet` plugin (built-in): `zeek -C -i af_packet::<iface>`. `-C` ignores TCP checksums (Hetzner NICs do checksum offloading → libpcap would see bogus checksums → Zeek would drop most packets).
- JSON logs via `@load policy/tuning/json-logs.zeek` in `local.zeek`. Fields line up with Elastic's Zeek integration ECS mappings.
- Cross-source correlation already works: Zeek's `http.log` captures `"username":"sre.alice"` from Squid's CONNECT basic-auth headers, and `dns.log` shows the two-hop resolver flow (container → unbound, unbound → 1.1.1.1).
- Log ingestion into Elastic is deferred to a later batch (existing host-based elastic-agent integration or a container Filebeat).

### Adding a new proxy-attributable user

1. Add to `keycloak/realm.yaml` (realm import).
2. Add to the username list in `squid/Dockerfile`'s htpasswd loop.
3. `docker --context soc-playground compose up -d --build keycloak-init squid`.
4. For Keycloak to actually honor the new user, nuke `keycloak_data` (see "Re-seed users/roles" above).

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
- **Keycloak `--import-realm` is create-only, not upsert.** Editing `realm.yaml` after the realm exists is a no-op at next `compose up`. See "Re-seed users/roles" above. A consequence: seed passwords are only honored on first import; rotations need kcadm.sh or the UI.
- **Keycloak image has no `curl`** (UBI-minimal base). Healthcheck uses bash's `/dev/tcp` against the management port 9000. Use the CMD exec form (`["bash", "-c", ...]`) not CMD-SHELL — the default `/bin/sh` in the image doesn't expand `echo -e` escapes, so CRLFs go out as literal `\r\n` and Vert.x rejects the request with "Host header required". `printf` + explicit `bash` sidesteps this.
- **Keycloak 26 splits HTTP (8080) from management/health (9000).** `/health/ready` is only on 9000 and is enabled by `KC_HEALTH_ENABLED=true`. Only 8080 is published to the host (loopback); 9000 is internal-only and reached from the container's own healthcheck.
- **Anonymous image-VOLUME dirs persist across `compose up --build`.** `ubuntu/squid:latest` declares `/var/log/squid` and `/var/spool/squid` as VOLUMEs. Docker Compose creates anonymous volumes for them, then **re-binds the same anonymous volume on every container recreate**, even after the image changes. A build-time `chown` or `ln -sf` inside those dirs won't propagate until you `docker volume rm` the stale volume. Fix used here: declare them as `tmpfs:` in compose — ephemeral, reset from image on every start.
- **libpcap can't do promiscuous mode on the `any` pseudo-interface on modern Linux.** `zeek -i any` errors with `Promiscuous mode not supported on the "any" device`. The `Zeek_AF_Packet` plugin (`-i af_packet::<iface>`) uses kernel AF_PACKET sockets directly and sidesteps the issue — but needs a concrete interface name, not `any`. Cloud NICs with checksum offloading also require `-C` (ignore checksums) or Zeek drops most packets as invalid.
- **Ubuntu `squid` image won't let squid open `/dev/stdout` directly.** It tries a parent-dir writability check that fails (`/dev` isn't writable by user `proxy`). The image's own entrypoint already runs `tail -F /var/log/squid/*.log` to forward logs to container stdout — just write to regular files in that dir and let the entrypoint handle forwarding. Attempting `ln -sf /dev/stdout /var/log/squid/access.log` doesn't work either (the writability check can't traverse the symlink).
