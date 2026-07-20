# playground-v2/ — VPS-hosted stack

Docker Compose stack on the Hetzner VPS `soc-playground` (provisioned by `/workspace/infra/`): the real Elastic stack plus identity, network, host-population, and stub services that make up the v2 playground. Dev-only — not shipped with the soc-agent plugin.

- Design rationale: `/workspace/docs/playground-environment-v2.md`
- Per-service internals, attach recipes, recovery procedures, gotchas: `docs/runbook.md`

## Running commands

Everything runs from the devcontainer against the remote Docker engine. Always pass `--context soc-playground` per command (the devcontainer's `DOCKER_HOST` overrides `docker context use`):

```bash
cd /workspace/playground-v2
docker --context soc-playground compose up -d     # `down` keeps volumes; `down -v` destroys them — remotely
docker --context soc-playground exec <svc> ...    # no host ports on most services; exec or Docker DNS
```

Web UIs (Kibana 5601, Keycloak 8080, ES 9200, Fleet 8220) are loopback-only on the VPS — access via `ssh -L <port>:localhost:<port> soc-playground`. Credentials come from `.env` (gitignored; template in `.env.example`).

## Map

| When talking about... | Look at... |
|---|---|
| the stack / a service's wiring | `compose.yml` |
| the realm / Keycloak users + roles | `keycloak/realm.yaml` — source of truth; import is create-only, re-seeding is a runbook procedure |
| the hosts / inventory (roles, owners, criticality, trust edges) | `hosts/inventory.yaml` — source of truth for every consumer; `hosts/Dockerfile` builds all 8 role hosts |
| user seeding | `hosts/base/seed-users.py` (runs at container start) |
| fleet / enrollment / role policies | `hosts/base/agent-enroll.sh` + the `fleet-init` / `fleet-host-policies` one-shots in `compose.yml`; drift self-heals via the `fleet-outputs-reconciler` sidecar |
| baseline / the activity generators | `hosts/base/baseline/catalog.yaml` (actions + Poisson schedules) + `scheduler.py`; seeded by `V2_BASELINE_SEED`, kill-switch `V2_BASELINE_ENABLED` |
| the stubs (CMDB, TI, change-mgmt, identity) | `cmdb/` `threat-intel/` `change-mgmt/` `identity/` — auth-less FastAPI, reachable in-cluster by Docker DNS on :8080; ticket-server is reused from `../playground/ticket-server` |
| attacks / the runner | `attacks/runner.py` + `attacks/catalog.yaml` (`./runner.py list`, `./runner.py run <id> --seed N`); see `attacks/README.md` |
| detection rules | `detection-rules/*.json`; install/refresh with `python3 scripts/install_detection_rules.py` (idempotent). Alerts land in `.internal.alerts-security.alerts-default-*` — the defender's `alert.json` input |
| network/syscall telemetry | `unbound/` (DNS), `squid/` (auth'd proxy), `zeek/` (passive monitor), `falco/` (syscalls) |

## Conventions & invariants

- **Namespace env vars with `V2_`** (e.g. `V2_ELASTIC_PASSWORD`). `/workspace/.env` (v1 creds) is auto-sourced into every shell and shell env overrides compose `.env` values — unprefixed names get silently shadowed.
- **Cross-file invariant, maintained by hand:** users in `keycloak/realm.yaml` ↔ roles in `hosts/inventory.yaml` ↔ the htpasswd list in `squid/Dockerfile`. Divergence fails silently (a user just gets no accounts / no proxy auth).
- **Committed YAML is source of truth.** Runtime edits (kcadm, admin UIs, stub POSTs) must be folded back so a fresh lever-up matches.
- Most config edits apply with `docker --context soc-playground compose up -d --build <svc>`. Exceptions with recovery procedures in the runbook: Keycloak realm changes (import is create-only) and cert/volume resets (never wipe the `certs` volume alone).
- Several images use `playground-v2/` as their build context because they COPY `inventory.yaml`/`realm.yaml` across dirs; `.dockerignore` whitelists what they need.
