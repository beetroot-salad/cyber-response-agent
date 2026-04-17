# Act Mode

How the plugin graduates mature signatures from "recommend" (the MVP default) to "act" — where the agent's grounded conclusion closes the originating ticket automatically.

## What act mode is

Out of the box every signature runs in `recommend` mode: the agent produces a `report.md` and stops. A human still closes the ticket. Mature signatures — the ones where confidence is consistently high, precedent matches are strong, and the Tier 2 judge has been reliable — can be graduated to `act` mode on a per-signature basis. In act mode, a grounded high-confidence `status=resolved` resolution triggers an automatic `close_ticket` action against the configured ticketing connector. The investigation agent itself is **mode-unaware** — it writes the same report regardless of mode, and dispatch happens downstream of the report.

## How it works

Mode is set per-signature in `config/signatures/{signature_id}/permissions.yaml` and checked at the Stop event by a deterministic Python hook, not by an LLM. That matters for three reasons: it's cheaper, it's faster, and there's no prompt-injection surface at dispatch time.

The Stop handler runs two steps in explicit order, composed in Python inside `hooks/scripts/stop_handler.py`:

1. `investigation_summary.main(payload)` — append the outcome row to `runs/audit.jsonl` (same as recommend mode).
2. `close_ticket_action.main(payload)` — the dispatcher described below.

The dispatcher:

1. Resolves the run directory via `resolve_run_dir(session_id, runs_dir)` (session-anchored — stable under concurrent runs).
2. Parses `report.md` frontmatter.
3. Evaluates the **precondition gate**. All must hold, or the action is skipped:
   - `status == "resolved"`
   - `confidence == "high"`
   - `matched_archetype` non-empty
   - `ticket_id` non-empty
   - `signature_id` non-empty
4. Loads the signature's `permissions.yaml` and confirms `mode.default == "act"` **and** `mitigation.actions.close_ticket == "auto"`.
5. Looks up `close_ticket` in `config/actions.yaml` to resolve which connector script to invoke.
6. Dispatches a subprocess: `<connector> close --ticket-id ... --reason ... --author ... --documentation ... --run-dir ... --execute`.

`--reason`, `--author`, and `--documentation` are constructed mechanically from frontmatter fields — `reason` is `"{disposition} ({matched_archetype})"`, `author` is `"soc-agent v{plugin_version}"`, `documentation` is a short string pointing at the run directory and the cited archetype.

## The dry-run-first contract

Every action connector must default to dry-run: omitting `--execute` is always a dry-run, and `--execute` must be passed explicitly for any upstream write. The Stop handler is the **only** code path in the plugin that passes `--execute`. `/connect`'s test phase, `preflight.py`'s action-adapter probe, and every manual invocation default to the dry-run path. This makes production writes unreachable until the production hook explicitly opts in.

See `schemas/adapter_contract.py` for the `ActionContract` ABC and the ticketing-family constants (`REQUIRED_TICKETING_SUBCOMMANDS`, `REQUIRED_TICKETING_CLOSE_FLAGS`). The reference implementation is `scripts/tools/stub_ticket_cli.py` — `/connect` copies it when scaffolding a new vendor connector.

## How to enable it for a signature

Two edits, both per-signature (global connector binding is separate):

1. In `config/signatures/{signature_id}/permissions.yaml`:

   ```yaml
   mode:
     allowed: [recommend, act]
     default: act

   mitigation:
     actions:
       close_ticket: auto
   ```

2. In `config/actions.yaml`, bind `close_ticket` to the vendor connector `/connect` generated:

   ```yaml
   actions:
     close_ticket:
       connector: scripts/tools/{vendor}_cli.py
       required_env_vars: [...]
   ```

Only signatures with both edits will dispatch close-ticket actions. Any signature still on the default template (`mode.default: recommend`, empty `mitigation.actions`) is unaffected.

## How to wire a ticketing connector

Use `/connect`. Pass the vendor name; the skill walks you through adapter generation, picks `ActionContract` as the contract shape, runs the dry-run test end-to-end, and updates `config/actions.yaml` at scaffold time.

**Hard prerequisite: a non-production ticketing sandbox.** The plugin does not provision one — that's out of scope. If you don't have an isolated non-prod Jira/ServiceNow/TheHive/etc. instance you can point the test phase at, you should not be running act mode. `/connect` refuses the test phase if it can't reach a sandbox.

## Audit trail

Every `close_ticket` decision — success, failure, or skip — appends one row to `runs/action_audit.jsonl`:

```json
{
  "timestamp": "2026-04-14T10:00:00+00:00",
  "run_id": "run-abc",
  "signature_id": "wazuh-rule-5710",
  "action": "close_ticket",
  "ticket_id": "SEC-42",
  "connector": "scripts/tools/jira_cli.py",
  "status": "success|failure|skipped",
  "skip_reason": "mode=recommend|action_not_enabled|no_connector_configured|preconditions_unmet|null",
  "dry_run": false,
  "exit_code": 0,
  "duration_ms": 1234,
  "response_summary": "<first 200 chars of stdout>",
  "error": "<first 200 chars of stderr or null>"
}
```

`grep '"status":"success"' runs/action_audit.jsonl` is the simplest way to see which tickets the agent actually closed; `skip_reason` tells you why a row that looks like a candidate didn't dispatch.

## Failure modes and safety rails

- **The hook always exits 0.** A broken connector, a stale `config/actions.yaml`, or an unexpected exception inside the dispatcher never crashes the agent session. Failures show up as `status: failure` rows in `action_audit.jsonl`.
- **Per-signature opt-in.** The signature template ships with `mode.default: recommend` and empty `mitigation.actions`. Existing signatures graduate one at a time, deliberately. No global flip.
- **Dry-run default.** Every caller except the production Stop hook uses dry-run. Production writes are reachable only through the one code path in `close_ticket_action.py` that passes `--execute`.
- **All CONCLUDE validation still runs first.** Act mode sits on top of the three-layer CONCLUDE validation (Layer 0 pre-close self-check, Tier 1 structural report check, Tier 2 semantic judge) plus `invlang_validate.py` on every investigation.md write. A report that fails any of those never reaches the dispatcher. See `content/validation.md`.

## What's not yet implemented

- **Auto-downgrade on >2% override rate** (design-v3-architecture.md §6.5). Graduation is a deliberate one-way toggle today; automatic demotion on observed regression is tracked in `tasks/p2-act-mode-auto-downgrade.md`.
- **Sampling and override-tracking infrastructure.** Tracked in `tasks/p2-act-mode-sampling.md`.
- **Action verbs beyond `close_ticket`.** The pattern is extensible (`block_ip`, `disable_user`, `isolate_host`, `revoke_session`), but only `close_ticket` is wired in v1.
- **Per-signature connector routing.** `config/actions.yaml` binds each action to one global connector. If you need different signatures to close tickets in different systems, that's a follow-up.
