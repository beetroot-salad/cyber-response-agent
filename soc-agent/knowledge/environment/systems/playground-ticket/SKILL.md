---
name: playground-ticket
description: Playground ticket-server (FastAPI stub) — concrete ticketing-family ActionContract used for end-to-end act-mode validation
---

# playground-ticket

The playground ticket-server is a stateful FastAPI mock at
`http://ticket-server:8080` (see `playground/ticket-server/app.py`). It exists
so that act-mode dispatch (`hooks/scripts/close_ticket_action.py`) can be
exercised against a real HTTP backend instead of the no-op
`stub_ticket_cli.py`.

## CLI

`scripts/tools/playground_ticket_cli.py` — ticketing-family ActionContract
adapter, stdlib-only (urllib).

```bash
# health
python3 scripts/tools/playground_ticket_cli.py health-check

# dry-run close (default)
python3 scripts/tools/playground_ticket_cli.py close \
    --ticket-id SEC-1 \
    --reason "benign-burst (monitoring-probe)" \
    --author "soc-agent v3.4.0" \
    --documentation "Investigation: run-abc; archetype: monitoring-probe"

# real close (only the Stop-stage hook ever passes --execute)
python3 scripts/tools/playground_ticket_cli.py close ... --execute
```

Dry-run short-circuits before any HTTP call, so `--ticket-id PROBE-0 --dry-run`
is safe regardless of whether the ticket exists.

## Config

`config.env` only needs `PLAYGROUND_TICKET_BASE_URL`. Default value:

- From inside the dev compose network: `http://ticket-server:8080`
- From the host shell:                  `http://localhost:8080`

The stub is auth-less; no env-var secrets.

## Upstream API shape

| Verb | Path | Notes |
|---|---|---|
| GET  | `/health` | health-check probe |
| POST | `/tickets/{key}/transitions` | body: `{status, resolution, author, comment}` — flips `status=closed` and writes resolution + a comment in one call |

The CLI maps ActionContract `--reason` → upstream `resolution`,
`--documentation` → upstream `comment`. Other endpoints
(`GET /tickets`, `POST /tickets`, `POST /admin/reset`) are not used by the
adapter; they exist for test seeding.

## Not for production

This adapter exists for playground/CI validation only. Do not bind it to
`close_ticket` in `config/actions.yaml` outside the dev environment — there is
no auth and no upstream durability.
