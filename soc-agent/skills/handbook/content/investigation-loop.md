# Investigation Loop and State Machine

How the agent moves through an investigation, and the guardrails that enforce it.

For per-phase detail, see `content/phases.md`.

## The loop

```
CONTEXTUALIZE ─┬─→ CONCLUDE                        (main-agent dedup on live repeat)
               ├─→ SCREEN ─┬─→ CONCLUDE            (pattern match)
               │           └─→ HYPOTHESIZE
               ├─→ HYPOTHESIZE ─→ GATHER ─┬─→ ANALYZE ─┬─→ HYPOTHESIZE  (loop)
               │                          │            └─→ CONCLUDE
               │                          └─→ HYPOTHESIZE  (fork opened mid-lead)
               └─→ GATHER                                (first lead is non-branching)
```

The loop is a finite-state machine with six phases and a hard limit on hypothesis cycles.

## Phases (one-line summary each)

| Phase | What happens | Can transition to |
|---|---|---|
| `CONTEXTUALIZE` | Load signature knowledge, parse alert, integrate inline ticket-context + archetype-scan, build resolution map | `SCREEN`, `HYPOTHESIZE`, `GATHER`, `CONCLUDE` |
| `SCREEN` *(optional)* | Cheap subagent attempts mechanical pattern match against known benign outcomes | `HYPOTHESIZE`, `CONCLUDE` |
| `HYPOTHESIZE` | Articulate a fork between competing explanations, select the discriminating lead | `GATHER` |
| `GATHER` | Execute the selected lead(s), characterize raw observations | `ANALYZE`, `HYPOTHESIZE` |
| `ANALYZE` | Weight evidence against each surviving hypothesis using `++ / + / - / --` | `HYPOTHESIZE`, `CONCLUDE` |
| `CONCLUDE` | Write `report.md` with structured frontmatter | *(terminal)* |

Full per-phase detail in `content/phases.md`.

## The paths out of CONTEXTUALIZE

CONTEXTUALIZE is the only legal initial phase, and it has four legal next-hops:

1. **CONCLUDE** — dedup / duplicate path. If ticket-context's `repeats` cluster shows the same alert firing minutes ago on the same entities (often with an already-open ticket), the main agent can transition straight to CONCLUDE with `status=duplicate` or transfer a recent disposition — after verifying the cited prior ticket/precedent still holds. The subagent does not recommend this; it only surfaces the repeats.
2. **SCREEN** — if the signature's playbook has a `## Screen` section, try the mechanical fast-path.
3. **HYPOTHESIZE** — articulate a fork between explanations, then pick the discriminating lead.
4. **GATHER** — direct entry when the first lead is purely mechanical or interpretive (no fork has opened yet). Invlang v2.7 made HYPOTHESIZE on-demand rather than a mandatory gate; a run that opens with a characterization lead may skip HYPOTHESIZE and enter the loop at GATHER.

Paths 1–2 exist to compress work for known patterns. Paths 3–4 are the full-loop entries; the agent picks between them based on whether the very next lead's value depends on which competing story is true.

## The hypothesis loop

`HYPOTHESIZE → GATHER → ANALYZE` is the core cycle. Each iteration picks one lead, runs it, weighs the result. ANALYZE decides whether to loop again (need more evidence) or conclude (mechanism confirmed and verified, or escalation triggered).

A **cycle** is counted by the state machine as the number of `HYPOTHESIZE` plus `ANALYZE` entries in the phase history. Counting both keeps the guardrail meaningful under invlang v2.7's on-demand `HYPOTHESIZE` — a run that keeps gathering without re-hypothesizing still accumulates cycles.

**Maximum cycles: `MAX_LOOPS = 12`** (from `schemas/state.py`). The next transition into `HYPOTHESIZE` or `ANALYZE` past the cap is rejected with a state machine error directing the agent to `CONCLUDE`. Most investigations resolve in 2–3 cycles; past 8 without convergence, the hypothesis space is probably incomplete and escalation is the right call anyway.

This hard limit exists for two reasons:
- It bounds the worst-case wall-clock time for a stuck investigation
- It forces escalation when the agent is wandering, which surfaces the problem to a human instead of letting it silently burn budget

## State machine enforcement

The loop is enforced by two hooks on `investigation.md` that together prevent illegal phase transitions.

**`infer_state_pre.py` (PreToolUse, Write|Edit)** fires *before* a write to `investigation.md` lands. It simulates the proposed post-write text (Write: `tool_input.content`; Edit: `old_string → new_string` against the on-disk file), extracts the `## PHASE` headers that would result, and rejects the write if any new transition is illegal or would exceed `MAX_LOOPS`. Because PreToolUse runs before the filesystem change, a rejected write never advances `state.json` — the agent fixes its plan and retries the same write from the same phase with zero recovery.

**`infer_state.py` (PostToolUse, Write|Edit)** fires *after* the write succeeds. On each Write/Edit to `investigation.md` it:

1. Extracts all `## PHASE` headers from the file
2. Compares against the recorded history in `state.json`
3. For each new phase, looks up `TRANSITIONS[current_phase]` in `schemas/state.py` to check whether the proposed transition is legal
4. Counts investigation cycles in the history (every `HYPOTHESIZE` and every `ANALYZE` entry); rejects the transition if it would exceed `MAX_LOOPS`
5. Writes the new state back to `state.json` with an updated timestamp and appended history

If any check fails either hook exits with code 2 — the Pre hook blocks the write outright, the Post hook signals failure to the agent after the write. The agent must then adjust its plan; you cannot "talk around" the state machine.

## Legal transitions

From `schemas/state.py` (`TRANSITIONS` dict):

```python
CONTEXTUALIZE → {SCREEN, HYPOTHESIZE, GATHER, CONCLUDE}
SCREEN        → {HYPOTHESIZE, CONCLUDE}
HYPOTHESIZE   → {GATHER}
GATHER        → {ANALYZE, HYPOTHESIZE}
ANALYZE       → {HYPOTHESIZE, CONCLUDE}
CONCLUDE      → {}                           # terminal
```

Things this explicitly forbids:

- Starting anywhere other than `CONTEXTUALIZE`
- Skipping from `CONTEXTUALIZE` directly to `ANALYZE` (no evidence yet to analyze)
- Skipping from `SCREEN` back to `CONTEXTUALIZE`
- Going from `HYPOTHESIZE` straight to `CONCLUDE` (you must run a lead first)
- Going from `GATHER` straight to `CONCLUDE` (you must ANALYZE the evidence first)
- Backtracking from `CONCLUDE` (once the report is being written, the investigation is over)
- Re-entering `SCREEN` after the loop has started

`GATHER → HYPOTHESIZE` exists so the agent can articulate a newly-opened fork mid-lead before ANALYZE, without pretending it already knew the fork. `CONTEXTUALIZE → GATHER` exists because HYPOTHESIZE is on-demand — a first lead that does not branch on competing stories can go directly to GATHER.

## `state.json` shape

Written by the `infer_state.py` hook, consumed by `validate_report.py` and by the agent when deciding whether it's in a new loop:

```json
{
  "run_id": "b5f8d2e1-...",
  "ticket_id": "ALERT-12345",
  "signature_id": "wazuh-rule-5710",
  "phase": "ANALYZE",
  "history": [
    "CONTEXTUALIZE",
    "SCREEN",
    "HYPOTHESIZE",
    "GATHER",
    "ANALYZE",
    "HYPOTHESIZE",
    "GATHER",
    "ANALYZE"
  ],
  "updated_at": "2026-04-11T14:32:08.401234+00:00"
}
```

`history` is an ordered list of every phase the investigation has entered. The validator checks this history at CONCLUDE time: for example, `validate_report.py` uses `SCREEN in history and HYPOTHESIZE not in history` to detect screen-resolved investigations, which are exempt from the playbook-has-Screen-section cross-check because a screen-resolved outcome is only legal against a playbook that declares one.

## Termination rules

An investigation can only terminate by transitioning to `CONCLUDE`. The three legal paths:

- From `CONTEXTUALIZE` — main-agent dedup when ticket-context surfaces a live repeat or an already-open ticket on the same entities
- From `SCREEN` — mechanical pattern match success
- From `ANALYZE` — normal convergence (mechanism confirmed + verified + scoped, or explicit escalation)

`CONCLUDE` writes `report.md`. The PostToolUse hook on `Write|Edit` (`validate_report.py`) fires automatically and runs Tier 1 + Tier 2 validation. If validation fails the agent sees the errors and must edit the report to fix them — the investigation is not truly over until a valid report is on disk. See `content/validation.md`.

## Why loops are capped instead of open-ended

Unbounded loops invite two failure modes:

1. **Drift** — the agent keeps pulling new leads that feel relevant but don't discriminate between surviving hypotheses. It burns budget without converging.
2. **Gaming the safety check** — if loops were unlimited, the agent could technically satisfy "pursued enough leads" by running many low-severity leads, none of which actually refute threat hypotheses.

The `MAX_LOOPS = 12` cap makes both impossible. Combined with the CONCLUDE-transition self-check (see `content/validation.md`) and legitimacy-gated disposition (every `legitimacy_contract` on a live-weight hypothesis must resolve `authorized` before `disposition: benign` is allowed), the loop has both a ceiling and a floor: you must articulate contract resolutions and grounding evidence before resolving, and you cannot run more than a bounded number of rounds before escalating.

## How `investigation.md` relates to the state machine

`state.json` is the structural record (what phase, history, counts). `investigation.md` is the agent's working log — a markdown document updated during each phase with the narrative: hypotheses, observations, assessments. The two are not redundant:

- `state.json` is what the hooks read to enforce safety
- `investigation.md` is what the Tier 2 judge reads to check semantic consistency
- `state.json` is machine-owned; `investigation.md` is agent-owned

Both live in the run directory. See `content/run-artifacts.md` for the full artifact layout.
