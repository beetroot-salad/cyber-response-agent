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

### Role-clustered host population (batch 7a)

Eight role containers running on the compose network — the "population" half of v2 (docs/playground-environment-v2.md §Environment population). All 8 are built from a single multi-stage `hosts/Dockerfile` selected via compose `target:` + `BASE_OS` arg.

| Host | Role | OS | Service | Criticality |
|---|---|---|---|---|
| `web-1` / `web-2` | web | 22.04 | nginx | prod |
| `db-1` | db | 22.04 | postgres | prod |
| `jump-box-1` | jump-box | 24.04 | — | prod |
| `dev-ws-1` | dev-ws | 24.04 | — | dev |
| `office-ws-1` | office-ws | 22.04 | — | preprod |
| `office-ws-2` | office-ws | 24.04 | — | preprod |
| `canary-1` | canary | 22.04 | — | sandbox |

Full attributes (owner, change window, trust edges out, per-host users) live in `hosts/inventory.yaml` — the source of truth. Every consumer reads from there: user seeding today, and CMDB stub / fleet policies / baseline generators / attack scenarios in later batches.

**Build model.** One `hosts/Dockerfile` with stages `base` → `plain` | `web` | `db`. Context is `playground-v2/` (the whole dir) — required because the image pulls both `hosts/inventory.yaml` and `keycloak/realm.yaml`, and Docker's COPY cannot cross the build-context root. `playground-v2/.dockerignore` trims the context to just what the host images need (`hosts/**` + `keycloak/realm.yaml`). BuildKit caches the `base` stage once per `BASE_OS` across all 8 services.

**Identity seeding.** `hosts/base/seed-users.py` runs at container start (not build time — lets `inventory.yaml` edits take effect with `compose up -d` alone). It:

1. Reads `/opt/soc-playground/inventory.yaml` + `/opt/soc-playground/realm.yaml`.
2. Expands `inventory.roles[*].hosts` against `realm.users` → every realm user with matching realm role lands a UNIX account on each host that role authorizes.
3. Applies per-host `users:` overrides (e.g., `dev.dana` gets `sudo` on their own `office-ws-1`, not elsewhere).
4. Creates/updates accounts idempotently; password is reset to `changeme` on every boot — drift from the playground baseline is a footgun, not a feature.

**Cross-file invariant.** `keycloak/realm.yaml` users must match `hosts/inventory.yaml` expectations. No validator yet; maintained by hand. The failure mode is silent: a realm user with no matching inventory role simply gets no UNIX accounts anywhere.

**Network positioning.** All 8 hosts join the default compose network alongside `squid`, `unbound`, and `keycloak`. No host-port exposure — access from the devcontainer is via `docker --context soc-playground exec`. Zeek (host netns) sees their inter-container traffic on the compose bridge, so cross-source correlation (Zeek conn.log + nginx access.log + auditd) works out-of-box.

**What's deliberately deferred to later batches:**

- **Falco + auditd** — batch 7c.
- **SSH keys, pgaudit, nginx-as-app-frontend** — later batches (keys replace sshpass for ops realism; pgaudit replaces raw postgres log_statement).

### Per-role Fleet enrollment (batch 7b)

Every host ships an embedded `elastic-agent` (installed in the base stage from the same `STACK_VERSION` pin as ES/Kibana/Fleet Server). The agent enrolls into a **role policy** — one Fleet policy per distinct role, shared by all hosts of that role — so policy changes propagate across peers without per-host edits.

**Policy catalog** (created by the `fleet-host-policies` one-shot):

| Policy id | Agents | Base integration |
|---|---|---|
| `host-web-policy` | `web-1`, `web-2` | system (logs+metrics via `sys_monitoring=true`) |
| `host-db-policy` | `db-1` | system |
| `host-jump-box-policy` | `jump-box-1` | system |
| `host-dev-ws-policy` | `dev-ws-1` | system |
| `host-office-ws-policy` | `office-ws-1`, `office-ws-2` | system |
| `host-canary-policy` | `canary-1` | system |

Role-specific integrations (nginx on web, postgres on db, endpoint-security, Falco+auditd shipping) are layered in batches 7c / 8.

**Enrollment token distribution.** `fleet-host-policies` runs after `fleet-init`, POSTs a policy per role (409-on-conflict is the success path on re-runs), fetches the policy's enrollment API key via `GET /api/fleet/enrollment_api_keys?kuery=policy_id:<id>`, and atomic-writes the token to `/tokens/<role>.token` on the shared `fleet_tokens` volume. Each host container mounts that volume read-only and reads its role's token from `/fleet-tokens/<role>.token` at entrypoint time — hosts never hold a Kibana credential themselves.

**Sentinel-gated enrollment.** `hosts/base/agent-enroll.sh` enrolls via `elastic-agent enroll --url=https://fleet-server:8220 --certificate-authorities=/fleet-certs/ca/ca.crt --enrollment-token=<cat token>` on first boot, then drops a `.enrolled` sentinel inside the per-host `agent_state_*` volume. Subsequent container recreates skip the enroll step and reuse the persisted `agent.id` + `fleet.enc` — matches v1's target-endpoint pattern, avoids stale "offline" ghosts accumulating in Kibana → Fleet → Agents across lever-down/up cycles. The sentinel check also verifies `/etc/elastic-agent/fleet.enc` still exists: `compose up -d --build` wipes `/etc/elastic-agent` (only `/var/lib/elastic-agent` is volume-mounted), so a plain sentinel check would silently leave the agent unenrolled after a rebuild. If `fleet.enc` is gone, the script re-enrolls — this costs one fresh `agent.id` per rebuild but keeps the host reachable.

**Agent runs alongside sshd.** The entrypoint starts `elastic-agent run` in the background; sshd remains the foreground PID-1-child so container-level restart policies still key on sshd health, not on the agent's.

**Re-enroll from scratch.** If a host gets into a bad state, nuke just its agent state volume:

```bash
docker --context soc-playground compose rm -sf web-1
docker --context soc-playground volume rm soc-playground_agent_state_web_1
docker --context soc-playground compose up -d web-1
```

**Re-issue a policy's token.** Delete the old enrollment API key in Kibana → Fleet, then re-run the one-shot — the shell loop regenerates the token and re-writes `/tokens/<role>.token`:

```bash
docker --context soc-playground compose up -d --force-recreate fleet-host-policies
```

Existing agents keep working (tokens are used only at enrollment); only new enrollments need the fresh key.

**Resource footprint.** Each elastic-agent adds ~150–250 MB resident; 8 agents ≈ +1.6 GB on top of the existing ES/Kibana/Fleet Server. Within the CCX33 budget.

**Known quirks carried from v1** (see memory `reference_fleet_server_docker_9x.md` and `reference_elastic_version_registry_lag.md`):

- `elastic-agent enroll` exits non-zero from a systemd-less service-reload step even when server-side registration succeeded. `agent-enroll.sh` tolerates this with `|| true` + sentinel-on-next-line, same as v1 target-endpoint.
- `elastic-agent status` may briefly show `x509: certificate signed by unknown authority` for sub-components — cosmetic; data still flows. Usually settles after a few check-in cycles.

### Syscall monitoring (Falco — batch 7c)

One shared Falco container runs against the VPS docker daemon with the **modern eBPF** engine (CO-RE BPF, no kernel module). It sees syscalls from every container on the VPS — web/db/jump-box/dev-ws/office-ws/canary, plus unbound/squid/keycloak/etc. Per-host attribution comes from Falco's built-in container plugin: every event carries `container.name`, `container.image.repository`, and `container.id`. Kibana dashboards filter by container name to get per-host views without needing one Falco per host.

**Why shared, not per-host.** The kernel audit + BPF hooks are single-listener resources. Running 8 Falco instances would either require one-owns-the-driver arbitration (messy) or resort to the legacy kernel-module driver (impractical in containers). One Falco plus the container plugin gives equivalent visibility at a fraction of the resource cost (~400 MB vs. 8 × ~200 MB).

**Output path.** `/var/log/falco/falco.json` on the VPS host (bind-mounted out of the container). JSON lines, one event per line, conforming to Falco's schema — includes `output`, `rule`, `priority`, `source`, `tags`, and `container.*`. `stdout` mirrors the same stream for `docker --context soc-playground logs falco`.

**Ruleset.** Default Falco rules only for 7c — the bundled `falco_rules.yaml` covers the common families (terminal shell in container, sensitive file open, privileged container start, write below `/etc`). Playground-specific rules go into `/etc/falco/rules.d` in a later batch (or layered via a Fleet-managed rule bundle).

**Shipping Falco events to Elastic — manual attach (one-time).**

`fleet-host-policies` does not attach the Falco integration automatically (the `log` package version varies per Elastic release; baking the lookup into the one-shot makes it brittle). Attach it once, post-deploy, via Kibana UI or Fleet API.

Via **Kibana UI** (simplest):

1. SSH-tunnel Kibana (`ssh -L 5601:localhost:5601 soc-playground`), open `http://localhost:5601/app/fleet/policies/vps-host-policy`.
2. *Add integration* → *Custom Logs*.
3. Paths: `/var/log/falco/falco.json` · Dataset name: `falco.alerts` · Enable JSON parsing.
4. Save. The host-side elastic-agent picks it up on next check-in.

Via **Fleet API** (scriptable — run from the devcontainer, Kibana tunneled on 5601):

```bash
LOG_VER=$(curl -fsSu "elastic:$V2_ELASTIC_PASSWORD" -H 'kbn-xsrf: x' \
  http://localhost:5601/api/fleet/epm/packages/log | jq -r '.item.version')

curl -fsS -u "elastic:$V2_ELASTIC_PASSWORD" -H 'kbn-xsrf: x' -H 'Content-Type: application/json' \
  -H 'elastic-api-version: 2023-10-31' \
  -X POST http://localhost:5601/api/fleet/package_policies -d "{
    \"policy_id\": \"vps-host-policy\",
    \"package\": {\"name\": \"log\", \"version\": \"${LOG_VER}\"},
    \"name\": \"falco-logs\",
    \"namespace\": \"default\",
    \"inputs\": {
      \"logs-logfile\": {
        \"enabled\": true,
        \"streams\": {
          \"log.logs\": {
            \"enabled\": true,
            \"vars\": {
              \"paths\": [\"/var/log/falco/falco.json\"],
              \"data_stream.dataset\": \"falco.alerts\",
              \"processors\": \"- decode_json_fields:\\n    fields: [message]\\n    target: falco\\n    overwrite_keys: true\\n    add_error_key: true\\n\"
            }
          }
        }
      }
    }
  }"
```

Without the `decode_json_fields` processor, the Falco JSON line is ingested as a literal `message` string and fields like `container.name`, `rule`, `priority` aren't queryable. With it, they're nested under `falco.*` (e.g. `falco.output_fields.container.name`, `falco.rule`).

**Verify.** In Kibana → Discover, filter `data_stream.dataset: falco.alerts`. Events should show up within a few seconds of an activity trigger. Quick trigger: `docker --context soc-playground exec canary-1 bash -c 'touch /tmp/.falco-test && ls /etc/shadow || true'` — Falco's "Read sensitive file untrusted" or similar rule fires.

**auditd — deferred.** Per-container auditd in docker is fraught: the kernel audit socket is a single-listener resource, so only one container's auditd can actually attach to it at a time, and user-namespace interaction is still a moving target on modern kernels. Running auditd on the VPS host itself (plus Falco for syscall coverage + rsyslog for auth/sudo/cron) covers the same ground without fighting the kernel. If per-container auditd becomes necessary later, the cleanest route is an audit-dispatcher daemon on the VPS host that demuxes by PID → container; that's a separate design problem from batch 7.

**Re-seeding users.** `inventory.yaml` or `realm.yaml` edits apply on container restart:

```bash
docker --context soc-playground compose up -d --build web-1 web-2 db-1 jump-box-1 dev-ws-1 office-ws-1 office-ws-2 canary-1
```

The image rebuild re-bakes the YAML files; the entrypoint re-runs `seed-users.py` and creates/updates accounts. No volume deletion needed.

### Baseline activity generators (batch 8)

Each of the 8 role hosts runs a small Python scheduler (`/opt/soc-playground/baseline/scheduler.py`) that drives synthetic benign activity — web↔DB queries, scheduled service-account jobs, SRE multi-hop SSH sessions, office-user web fetches, occasional typo-failed logins. This is the layer that makes "is this unusual" a non-trivial question (docs/playground-environment-v2.md §Baseline activity generators).

**Not cron.** The spec mandates Poisson-distributed arrivals with time-of-day shape, not fixed-period cron jobs. A single Python process per host binds `(action, identity)` pairs from the catalog, draws exponential inter-arrival times, and dispatches via `runuser -u <user>` so `/var/log/auth.log` and downstream integrations see the right identity.

**Catalog.** `hosts/base/baseline/catalog.yaml` is source of truth. Each action declares `host_roles` (binds to hosts whose inventory role matches), `identities` (realm-user globs — `sre.*`, `svc.backups`), `cmd` (with `${user}`, `${target}`, `${host}`, `${wrong}` placeholders), optional `targets_from: trust_edges_out` for SSH targets, and a `schedule: {mean_s, shape}`. Shape options: `flat` (service accounts), `workhours-utc` (humans, 09–17 UTC peak), `workhours-us` (some devs, 13–21 UTC peak), `overnight-peak` (automation / backups). All shapes have a non-zero off-peak floor — real environments aren't truly idle.

**Reproducibility.** `V2_BASELINE_SEED` (default `42`) is hashed with `host:action:identity` to seed one PRNG per binding. Same seed + same catalog + same inventory → identical arrival sequences across runs. Changing the seed gives a different-but-valid shape — useful for eval harnesses that need multiple draws.

**Kill-switch.** Set `V2_BASELINE_ENABLED=false` in `.env` and `compose up -d --force-recreate <hosts>` (no rebuild needed — the env is consumed by the entrypoint, not baked in). Reserved for emergencies (e.g., baseline misbehaving and drowning a debugging session); attack-scenario runs deliberately leave baseline on so the agent investigates against realistic noise.

**Observing it.**

```bash
# Is the scheduler alive?
docker --context soc-playground exec web-1 pgrep -af scheduler.py

# What did it just do?
docker --context soc-playground exec web-1 tail -30 /var/log/baseline.log

# Did it actually hit the DB?
docker --context soc-playground exec db-1 tail -30 /var/log/postgresql/postgresql-*.log

# Did it actually hit nginx?
docker --context soc-playground exec web-1 tail -30 /var/log/nginx/access.log

# In Kibana → Discover: `logs-system.auth` should show `user.name: svc.reports`
# and friends; `logs-system.syslog` should show cron + baseline.log entries.
```

**Tuning.** Edit `catalog.yaml` → rebuild the host image → `compose up -d --build <hosts>`. Most common tweaks: dial `mean_s` up/down per action, or flip an action's `shape` to exercise time-of-day peaks differently.

**Prerequisites shipped with this batch.**

- `hosts/db/role-start.sh` now seeds an `app` database + `orders` table + `appuser` role so `app-db-query` / `app-db-insert` actions from web-1/web-2 have something to hit. Postgres's default `listen_addresses=localhost` is widened to `*` so the bridge network can reach it; `pg_hba.conf` gets an `md5` entry for the docker subnet.
- Base image adds `sshpass` (scripted SSH with the shared `changeme` password — playground-only), `postgresql-client` (psql from web tier), and `gcc` (dev-ws workstation compile activity).

**Gotcha — service accounts have `nologin` shell.** The scheduler uses `runuser -u svc.backups -s /bin/bash -- bash -c '...'` which explicitly overrides the login shell for dispatch. This is how systemd timers dispatch as `nologin` users and is the right pattern for synthetic-activity generation too.

**Gotcha — sshpass + password auth is a playground shortcut.** Production hosts would use SSH keys from a secrets manager. We accept the password-auth shape because PR #122 already set `PasswordAuthentication yes` on the host image and the stack is behind a loopback tunnel. Attack scenarios (batch 10) can still exercise credential-abuse archetypes against this same surface — the synthetic benign side just happens to use the same auth channel.

### Stub services (batch 9): CMDB, threat intel, change mgmt, ticketing

Four auth-less FastAPI stubs that round out the Tier 0/1 data layer defined in `docs/playground-environment-v2.md` §Data. Each runs in its own container on the compose network, listens on 8080 internally, and is published on VPS loopback at `127.0.0.1:8001-8004` for debugging. In-cluster consumers reach them via Docker DNS: `http://cmdb:8080`, `http://threat-intel:8080`, `http://change-mgmt:8080`, `http://ticket-server:8080`.

Footprint: 4 × 256 MB ≈ 1 GB — matches the v2 design allocation for "Ticket stub, CMDB stub, proxy, TI stub".

Shared healthcheck pattern via a `&stub-health` YAML anchor on `cmdb` (reused by the other three). Uses Python's `urllib` against `http://127.0.0.1:8080/health` — `python:3.12-slim` has no `curl` and baking one in just for liveness is wasteful (same "use what's in the image" move as Keycloak's bash+/dev/tcp probe).

#### cmdb (batch 9)

FastAPI over `hosts/inventory.yaml`. Loads the `hosts:` list into an immutable `BASE` dict at startup; an in-memory `OVERLAY` dict shallow-merges over `BASE` on every read. The overlay exists as a scaffold for the stale-CMDB chaos modes in batch 11 — batch 9 ships the surface (`POST /admin/overlay/{name}`, `DELETE /admin/overlay/{name}`, `POST /admin/reset`), not a driver.

- Build context is `playground-v2/` (not `./cmdb`) because the image must COPY `hosts/inventory.yaml` from outside its own dir. `playground-v2/.dockerignore` whitelists `cmdb/**` alongside the existing `hosts/**` + `keycloak/realm.yaml` so the root-context tar stays small.
- Endpoints: `GET /health`, `GET /hosts[?role&criticality&owner]`, `GET /hosts/{name}`, `GET /roles`, `POST/DELETE /admin/overlay/{name}`, `POST /admin/reset`.
- Merge is shallow on purpose — chaos scenarios flip a single field (owner, criticality). Deep-merging nested `os` / `service` dicts can come if a scenario needs it.

#### threat-intel (batch 9)

Local VT/OTX-shaped reputation stub, offline. Seed lives at `threat-intel/seed/indicators.json` (baked into the image — scoped build context `./threat-intel`). Mixed verdicts + types give agent tests enough material; obviously-fake IPs/domains keep the file from ever being confused with live TI.

- Endpoints: `GET /health`, `GET /lookup/{value}`, `POST /lookup`, `GET /indicators[?verdict&type&tag]`, `POST /admin/reset`.
- `/lookup/{value}` never 404s — mirrors VT/OTX, returns a synthetic `{verdict: "unknown", score: 0}` record on miss. Lets callers treat lookup as a pure function without a try/except on every call.

#### change-mgmt (batch 9)

YAML + FastAPI — the "authorized-change context" primitive from the v2 doc. Seed at `change-mgmt/seed/changes.yaml` is baked into the image; in-memory store is mutable (POST `/changes`, `POST /changes/{id}/transitions`) but resets on container restart unless the seed file is edited.

- Endpoints: `GET /health`, `GET /changes[?status&host&active_at]`, `GET /changes/{id}`, `GET /changes/active?host=<h>&at=<iso>`, `POST /changes`, `POST /changes/{id}/transitions`, `POST /admin/reset`.
- Seed windows tie to `hosts/inventory.yaml`'s `change_window` fields (e.g., `CHG-1042` covers web-1/web-2 during their Tue 02:00-04:00 UTC window). One seed CR (`CHG-1050`) intentionally spans "today" so smoke tests against `/changes/active` don't need to mint a CR.

#### ticket-server (reused from v1)

Built from `../playground/ticket-server` — the existing v1 FastAPI app. Kept in place (not moved into `playground-v2/`) so v1 integrations stay working. `build:` packages the context into a tar locally before sending to the remote daemon, so the relative path resolves on the client side and works under `--context soc-playground`.

- Seed at `../playground/ticket-server/seed/tickets.json` is bind-mounted read-only (not baked) — edits apply on `compose up -d` with no rebuild. The container's `TICKET_SEED_PATH` default matches the mount point.
- Endpoints: unchanged from v1 — `GET /health`, `GET /tickets[?status&label&q]`, `GET /tickets/{key}`, `POST /tickets`, `POST /tickets/{key}/transitions`, `POST /tickets/{key}/comments`, `POST /admin/reset`.

#### Verifying the stubs

From a host container via Docker DNS:

```bash
docker --context soc-playground exec web-1 bash -c '
  curl -fsS http://cmdb:8080/hosts/web-1 | jq .owner &&
  curl -fsS http://threat-intel:8080/lookup/185.220.101.45 | jq .verdict &&
  curl -fsS "http://change-mgmt:8080/changes/active?host=web-1&at=2026-04-24T12:00:00Z" | jq ".[].id" &&
  curl -fsS http://ticket-server:8080/tickets | jq .total
'
```

CMDB overlay round-trip:

```bash
docker --context soc-playground exec web-1 bash -c '
  curl -fsS -X POST -H "Content-Type: application/json" \
    -d "{\"owner\":\"team.platform\"}" http://cmdb:8080/admin/overlay/web-1
  curl -fsS http://cmdb:8080/hosts/web-1 | jq .owner   # team.platform
  curl -fsS -X DELETE http://cmdb:8080/admin/overlay/web-1
'
```

### Attack scenarios (batch 10)

Parameterized attack scenarios that generate realistic telemetry across auth/metadata, execution, and data-access signal categories (docs/playground-environment-v2.md §Attack-simulation surface). Runner + catalog live in `playground-v2/attacks/`. Dispatches happen from the devcontainer against compose-network containers via `docker --context soc-playground exec`. Attacks fire into the live environment with baseline activity left on — signal-vs-noise discrimination is the agent's job. Each run writes `attacks/runs/<run_id>/meta.json` (start/end timestamps + per-step rc) as an investigation-context hint. Specific-run post-mortem reproduction comes from the soc-agent's `tool_audit.jsonl` (the PostToolUse `audit_tool_calls.py` hook records `tool_input` + `tool_response` per call) — that's what the agent actually saw. Historical query reproducibility for arbitrary later replays relies on Elastic ILM retention.

Catalog (4 starter scenarios):

| id | category | source → target | signal surface |
|---|---|---|---|
| `ssh-brute-force-canary` | auth-metadata | `office-ws-1` as `dev.dana` → `canary-1` | rule-5710 / SSH invalid-user bursts on canary sshd |
| `living-off-the-land` | execution | `canary-1` (root) → self | curl-to-bash + base64-decoded shell payload — Falco execution lineage |
| `persistence-authorized-keys` | execution | `canary-1` (root) → self | append attacker key to `/root/.ssh/authorized_keys` — rule-550 FIM + Falco `write_below_etc` analog |
| `cross-tier-ssh-probe` | data-access | `office-ws-1` as `dev.dana` → `db-1` | cross-credential-anomaly — office-ws has no `trust_edges_out` to db; dev.dana has no account on db-1 |

Run workflow:

```bash
cd /workspace/playground-v2/attacks
./runner.py list
# Run (baseline stays on — fire into live noise):
./runner.py run ssh-brute-force-canary --seed 42 --intensity 8
# Review:
cat runs/<run_id>/meta.json
# Post-mortem of the agent's investigation (after it runs against the alert):
#   soc-agent/runs/<session>/tool_audit.jsonl
```

**Design notes:**

- **Live environment, no quiesce.** Baseline activity stays on for attack runs. Recreating hosts to flip `V2_BASELINE_ENABLED` would itself inject a synthetic boundary (sshd restart, fresh agent check-in, possibly fresh `agent.id` per the rebuild quirk) the agent could latch onto as a tell.
- **Reproducibility at the pattern layer, not the dispatch layer.** Per-iteration PRNG seeded as `sha256(scenario_id:seed:step_index:iteration)` keeps dispatches stable for debugging, but the agent's tool surface is broader than any time-windowed Elastic replay — host state (processes, FDs, FIM) is non-replayable. Recurring patterns at scale + Elastic ILM retention are what make investigations reproducible at the eval layer; specific-run reproducibility comes from the soc-agent's `tool_audit.jsonl` capturing each `tool_input` + `tool_response`.
- **Source/target realism.** Source hosts and identities are real compose containers + realm users, so Keycloak events, Zeek conns, sshd/auth.log, and Falco syscall events all carry the right labels. `office-ws-1` + `dev.dana` reaching `db-1` is telemetry-wise a compromised-workstation signal because neither the role mapping nor the `trust_edges_out` in `hosts/inventory.yaml` permits that path.
- **Per-step templating.** `${host}`, `${target}`, `${user}`, `${iteration}`, `${intensity}` substitute in each step's `cmd`. Repeat counts can be literal ints or the string `"${intensity}"`; `delay_s_between` sleeps between repeats; `allow_fail` lets a step's non-zero rc proceed to the next step (ssh brute force is expected to fail, so it uses `allow_fail: true`).
- **Run artifacts.** `runs/` is gitignored except for its `.gitignore`. meta.json is an investigation-context hint; the durable record of what the agent saw lives in the soc-agent run dir's `tool_audit.jsonl`.

**Deferred to later batches:**

- ILM retention pinning so the data streams the agent would query (`logs-system.*`, `logs-zeek.*`, `falco.alerts`, etc.) stay queryable for the fixture lifetime. Today the stack runs on default policies — replace with explicit retention before treating any run as a stable reference.
- Chaos control plane that drives the CMDB overlay, toxiproxy-style service outages, schema drift, and data drops (docs/playground-environment-v2.md §Phased build Phase 4).
- MinIO-dependent data-access archetypes (blob enumeration, staged exfil) — MinIO is a Tier-2 dependency.

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
- **`ca_trusted_fingerprint` needs the CA in the presented chain — `elasticsearch-certutil cert` doesn't emit one.** Without a fix, every bulk POST from elastic-agent drops with `x509: certificate signed by unknown authority` + `Exporting failed. Dropping data.`, and no `metrics-system.*` / `logs-system.*` / `logs-falco.alerts-default` data streams ever form (fleet-server's own telemetry still flows because it's not a client-of-ES). Fix baked into `setup`: after cert gen, append `ca/ca.crt` to both `elasticsearch/elasticsearch.crt` and `fleet-server/fleet-server.crt` so ES / fleet-server present a leaf+CA chain that agents can walk back to the fingerprint pin. Idempotent on existing volumes. ES hot-reloads the cert on the next TLS handshake — no restart needed.
- **Keycloak `--import-realm` is create-only, not upsert.** Editing `realm.yaml` after the realm exists is a no-op at next `compose up`. See "Re-seed users/roles" above. A consequence: seed passwords are only honored on first import; rotations need kcadm.sh or the UI.
- **Keycloak image has no `curl`** (UBI-minimal base). Healthcheck uses bash's `/dev/tcp` against the management port 9000. Use the CMD exec form (`["bash", "-c", ...]`) not CMD-SHELL — the default `/bin/sh` in the image doesn't expand `echo -e` escapes, so CRLFs go out as literal `\r\n` and Vert.x rejects the request with "Host header required". `printf` + explicit `bash` sidesteps this.
- **Keycloak 26 splits HTTP (8080) from management/health (9000).** `/health/ready` is only on 9000 and is enabled by `KC_HEALTH_ENABLED=true`. Only 8080 is published to the host (loopback); 9000 is internal-only and reached from the container's own healthcheck.
- **Anonymous image-VOLUME dirs persist across `compose up --build`.** `ubuntu/squid:latest` declares `/var/log/squid` and `/var/spool/squid` as VOLUMEs. Docker Compose creates anonymous volumes for them, then **re-binds the same anonymous volume on every container recreate**, even after the image changes. A build-time `chown` or `ln -sf` inside those dirs won't propagate until you `docker volume rm` the stale volume. Fix used here: declare them as `tmpfs:` in compose — ephemeral, reset from image on every start.
- **libpcap can't do promiscuous mode on the `any` pseudo-interface on modern Linux.** `zeek -i any` errors with `Promiscuous mode not supported on the "any" device`. The `Zeek_AF_Packet` plugin (`-i af_packet::<iface>`) uses kernel AF_PACKET sockets directly and sidesteps the issue — but needs a concrete interface name, not `any`. Cloud NICs with checksum offloading also require `-C` (ignore checksums) or Zeek drops most packets as invalid.
- **Ubuntu `squid` image won't let squid open `/dev/stdout` directly.** It tries a parent-dir writability check that fails (`/dev` isn't writable by user `proxy`). The image's own entrypoint already runs `tail -F /var/log/squid/*.log` to forward logs to container stdout — just write to regular files in that dir and let the entrypoint handle forwarding. Attempting `ln -sf /dev/stdout /var/log/squid/access.log` doesn't work either (the writability check can't traverse the symlink).
