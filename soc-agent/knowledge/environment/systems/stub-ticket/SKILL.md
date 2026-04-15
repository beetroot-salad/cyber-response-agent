---
name: stub-ticket
description: Reference ticketing connector — the canonical ActionContract example used by tests, preflight, and /connect as a template
---

# stub-ticket (reference ticketing connector)

This is a **stub** — it has no real upstream. It exists so that:

- `tests/test_close_ticket_action.py` can dispatch a real subprocess against
  an `ActionContract`-compliant CLI without needing a live ticketing system.
- `scripts/preflight.py` has a fixed target for its action-adapter dry-run
  probe (`close --dry-run`).
- `/connect` Phase 2 has a canonical template to copy when scaffolding a
  new vendor ticketing connector (jira_cli.py, servicenow_cli.py, etc.).

## CLI

See `scripts/tools/stub_ticket_cli.py`. Subcommands:

- `health-check` — always returns `connected: true`.
- `close --ticket-id ID --reason S --author S --documentation S [--dry-run|--execute]`
  — dry-run is the default; `--execute` appends an entry to
  `runs/stub_ticket_actions.jsonl` for audit visibility.

## Not for production

The stub intentionally has no auth, no upstream HTTP calls, no retries, and
no rate limiting. Do **not** bind it to a real signature via
`config/actions.yaml` outside of tests — use `/connect` to generate a real
vendor connector instead.
