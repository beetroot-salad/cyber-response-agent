---
title: Identity stub + change-mgmt alignment (Options B + C)
status: done
groups: playground-v2, stubs, legitimacy
---

Adds two structural legitimacy primitives the soc-agent was missing in
playground-v2:

1. **Identity stub** (`playground-v2/identity/`) — FastAPI over `keycloak/realm.yaml × hosts/inventory.yaml`, exposing the realm-role × inventory-role join that `hosts/base/seed-users.py` applies on hosts. Read-only: `/users`, `/users/{name}`, `/users/{name}/authorized_hosts`, `/users/{name}/can_access?host=`, `/roles`. Loopback-exposed on `127.0.0.1:8005`. Lets the agent answer "is U authorized on H, with what shell/sudo?" without reading `/etc/passwd`.

2. **Rolling standing CRs (Option C)** — `change-mgmt/seed/standing.yaml` declares recurring change windows (daily + weekly only — no croniter dep). The app materializes occurrences covering `[now-7d, now+1d]` into STORE at startup and every 5min via an `asyncio` loop. Initial set: nightly `db-1` backup window + weekly Tuesday web-tier patching window. Idempotent CR ids encode the occurrence start (`CHG-DB-BACKUP-20260520T0200Z`). Most baseline activity is still CR-free — only the slice that legitimately *should* be CR-backed gets a standing CR.

3. **Synthetic CRs from runner (Option B)** — `attacks/runner.py --cr-mode {none,valid,stale,scope-mismatch}` POSTs a `CHG-RUNNER-…` CR to change-mgmt before firing. POST goes via `docker exec change-mgmt python -c …` so no SSH tunnel or new Python deps. `pre_run` block in `meta.json` captures the synthetic CR end-to-end. Modes exercise host-scope (`scope-mismatch`), time-scope (`stale`), and positive cover (`valid`) — forcing the agent to interrogate CR scope, not just presence.

Out of scope (deferred until a scenario needs them):
- Identity stub write / overlay endpoints (stale-IdP chaos).
- More recurrence kinds (monthly, cron expressions).
- Cross-file validator for `realm.yaml ↔ inventory.yaml ↔ squid/Dockerfile` user list.
- Catalog-level CR-mode parameterization (today it's runner CLI only).

See `/root/.claude/plans/implement-the-suggested-fluttering-horizon.md` for the originating plan; see `playground-v2/CLAUDE.md §Stub services` and `playground-v2/attacks/README.md` for runtime details.
