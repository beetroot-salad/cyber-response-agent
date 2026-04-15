---
title: act mode: auto-close for mature signatures with high-confidence precedent matches
status: doing
groups: phase-2
---

MVP was recommend-only. Act mode graduates mature signatures so the agent's
grounded `status=resolved` conclusion auto-closes the originating ticket
without a human in the loop. Design has landed:

- **Post-investigation dispatch, not a mitigation skill.** The investigation
  agent stays mode-unaware — it writes the same `report.md` regardless of
  mode. A deterministic Python hook (`hooks/scripts/close_ticket_action.py`)
  fires at Stop, reads `report.md` frontmatter, checks the precondition
  gate, and dispatches to the connector bound in `config/actions.yaml`.
  No LLM at dispatch time — cheaper, faster, no prompt-injection surface.
- **ActionContract + dry-run-first.** `schemas/adapter_contract.py`
  declares the third contract shape. Only the Stop-stage hook passes
  `--execute`; everything else (preflight, `/connect` tests, manual use)
  runs in dry-run. Reference implementation:
  `scripts/tools/stub_ticket_cli.py`.
- **`/connect` owns creation + test-harness scaffolding** for novel
  ticketing vendors. Provisioning a non-prod ticketing sandbox is the
  user's responsibility — `/connect` refuses the test phase without one.
- **Per-signature opt-in.** `config/signatures/{sig}/permissions.yaml`
  with `mode.default: act` + `mitigation.actions.close_ticket: auto`
  graduates one signature at a time. The template ships in recommend mode.
- **Stop-handler composition.** `hooks/scripts/stop_handler.py` is the
  single Stop entrypoint, calling `investigation_summary.main(payload)`
  then `close_ticket_action.main(payload)` in order. Ordering is
  guaranteed in Python, not by harness semantics.
- **`runs/action_audit.jsonl`** logs every close-ticket decision —
  success, failure, or skip with reason — so operators have one
  grep-able source of truth.

Design reference: `docs/design-v3-architecture.md` §6.5, §7, §8; detailed
user-facing reference in `soc-agent/skills/handbook/content/act-mode.md`.

### Out of scope for this PR (follow-ups)

- Auto-downgrade on >2% override rate — tracked separately in
  `tasks/p2-act-mode-auto-downgrade.md`.
- Sampling / override tracking infrastructure — tracked in
  `tasks/p2-act-mode-sampling.md`.
- Additional action verbs beyond `close_ticket` (`block_ip`,
  `disable_user`, `isolate_host`, `revoke_session`). The pattern is
  extensible but only `close_ticket` lands in v1 as proof of concept.
- Multi-ticketing-vendor routing. v1 uses a single global
  `config/actions.yaml` binding per action.
