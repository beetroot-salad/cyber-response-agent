# Investigation Loop and State Machine

How the agent moves through an investigation, and the guardrails that enforce it.

For per-phase detail, see `content/phases.md`.

## The loop

```
       ┌──────────────────┐
       │  CONTEXTUALIZE   │
       └────────┬─────────┘
                │
      ┌─────────┼──────────┐
      │         │          │
      ▼         ▼          ▼
 ┌────────┐ ┌──────────┐ ┌──────────┐
 │ SCREEN │ │HYPOTHE-  │ │ CONCLUDE │ (ticket-context fast-resolve)
 └───┬────┘ │SIZE      │ └──────────┘
     │      └────┬─────┘
     ├──────────►│
     ▼           ▼
 ┌──────────┐ ┌────────┐
 │ CONCLUDE │ │ GATHER │
 └──────────┘ └───┬────┘
                  ▼
              ┌────────┐
              │ANALYZE │
              └───┬────┘
        ┌─────────┴─────────┐
        ▼                   ▼
  ┌──────────┐         ┌──────────┐
  │HYPOTHE-  │◄────────│ CONCLUDE │
  │SIZE      │  loop
  └──────────┘
```

The loop is a finite-state machine with six phases and a hard limit on hypothesis cycles.

## Phases (one-line summary each)

| Phase | What happens | Can transition to |
|---|---|---|
| `CONTEXTUALIZE` | Load signature knowledge, parse alert, spawn Explore + ticket-context subagents, build resolution map | `SCREEN`, `HYPOTHESIZE`, `CONCLUDE` |
| `SCREEN` *(optional)* | Cheap subagent attempts mechanical pattern match against known benign outcomes | `HYPOTHESIZE`, `CONCLUDE` |
| `HYPOTHESIZE` | Form or update candidate explanations, select the most diagnostic lead | `GATHER` |
| `GATHER` | Execute the selected lead(s), characterize raw observations | `ANALYZE` |
| `ANALYZE` | Weight evidence against each surviving hypothesis using `++ / + / - / --` | `HYPOTHESIZE`, `CONCLUDE` |
| `CONCLUDE` | Write `report.md` with structured frontmatter | *(terminal)* |

Full per-phase detail in `content/phases.md`.

## The three paths out of CONTEXTUALIZE

CONTEXTUALIZE is the only legal initial phase, and it has three legal next-hops:

1. **CONCLUDE** — ticket-context fast-resolve. If the ticket-context subagent finds a recent prior investigation of the same pattern with `status=resolved` and `confidence=high`, and the current alert's entities and behavior match, the main agent validates the match and jumps straight to CONCLUDE with the prior precedent.
2. **SCREEN** — if the signature's playbook has a `## Screen` section, try the mechanical fast-path.
3. **HYPOTHESIZE** — otherwise, enter the full loop directly.

The first two exist purely to compress work for known patterns. A signature with no playbook `## Screen` section and no prior matching investigation always enters the full loop via path 3.

## The hypothesis loop

`HYPOTHESIZE → GATHER → ANALYZE` is the core cycle. Each iteration picks one lead, runs it, weighs the result. ANALYZE decides whether to loop again (need more evidence) or conclude (mechanism confirmed and verified, or escalation triggered).

A **loop** is counted by the state machine as the number of `HYPOTHESIZE` entries in the phase history.

**Maximum loops: 7.** The 8th attempt to transition into `HYPOTHESIZE` fails with a state machine error telling the agent it must transition to `CONCLUDE`. Most investigations resolve in 2–3 loops; if you're past 5 without convergence, the hypothesis space is probably incomplete and escalation is the right call anyway.

This hard limit exists for two reasons:
- It bounds the worst-case wall-clock time for a stuck investigation
- It forces escalation when the agent is wandering, which surfaces the problem to a human instead of letting it silently burn budget

## State machine enforcement

The loop is enforced by `hooks/scripts/write_state.py`, which the agent must call at every phase transition:

```bash
python3 hooks/scripts/write_state.py <run_dir> <NEW_PHASE> [ticket_id] [signature_id]
```

On each call the script:

1. Loads `state.json` from the run directory (or initializes a fresh state if missing)
2. Looks up `TRANSITIONS[current_phase]` in `schemas/state.py` to check whether the proposed transition is legal
3. Counts hypothesis loops in the history; rejects the transition if it would exceed `MAX_LOOPS`
4. Writes the new state back to `state.json` with an updated timestamp and appended history

If any check fails the script prints the error to stderr and exits with code 1, which the agent sees as a tool failure. The agent must then adjust its plan — you cannot "talk around" the state machine.

## Legal transitions

From `schemas/state.py` (`TRANSITIONS` dict):

```python
CONTEXTUALIZE → {SCREEN, HYPOTHESIZE, CONCLUDE}
SCREEN        → {HYPOTHESIZE, CONCLUDE}
HYPOTHESIZE   → {GATHER}
GATHER        → {ANALYZE}
ANALYZE       → {HYPOTHESIZE, CONCLUDE}
CONCLUDE      → {}                           # terminal
```

Things this explicitly forbids:

- Starting anywhere other than `CONTEXTUALIZE`
- Skipping from `CONTEXTUALIZE` directly to `GATHER` or `ANALYZE`
- Skipping from `SCREEN` back to `CONTEXTUALIZE`
- Going from `HYPOTHESIZE` straight to `CONCLUDE` (you must run a lead first)
- Backtracking from `CONCLUDE` (once the report is being written, the investigation is over)
- Re-entering `SCREEN` after the loop has started

The `HYPOTHESIZE → GATHER → ANALYZE` sequence is locked — you cannot skip GATHER and pretend you have evidence. You cannot "just re-analyze" existing evidence without selecting a new lead first.

## `state.json` shape

Written by `write_state.py`, consumed by `validate_report.py` and by the agent when deciding whether it's in a new loop:

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

`history` is an ordered list of every phase the investigation has entered. The validator checks this history at CONCLUDE time: for example, `validate_report.py` uses `SCREEN in history and HYPOTHESIZE not in history` to detect screen-resolved investigations, which are exempt from the minimum-leads check because their safety comes from the pattern match rather than multi-lead evidence.

## Termination rules

An investigation can only terminate by transitioning to `CONCLUDE`. The three legal paths:

- From `CONTEXTUALIZE` — ticket-context fast-resolve (matching prior investigation)
- From `SCREEN` — mechanical pattern match success
- From `ANALYZE` — normal convergence (mechanism confirmed + verified + scoped, or explicit escalation)

`CONCLUDE` writes `report.md`. The PostToolUse hook on `Write|Edit` (`validate_report.py`) fires automatically and runs Tier 1 + Tier 2 validation. If validation fails the agent sees the errors and must edit the report to fix them — the investigation is not truly over until a valid report is on disk. See `content/validation.md`.

## Why loops are capped instead of open-ended

Unbounded loops invite two failure modes:

1. **Drift** — the agent keeps pulling new leads that feel relevant but don't discriminate between surviving hypotheses. It burns budget without converging.
2. **Gaming the safety check** — if loops were unlimited, the agent could technically satisfy "pursued enough leads" by running many low-severity leads, none of which actually refute threat hypotheses.

The 7-loop cap makes both impossible. Combined with the minimum-leads-by-severity check (see `content/validation.md`) and the adversarial hypothesis rule, the loop has both a ceiling and a floor: you must pursue enough evidence to justify a resolution, and you cannot run more than a bounded number of rounds before escalating.

## How `investigation.md` relates to the state machine

`state.json` is the structural record (what phase, history, counts). `investigation.md` is the agent's working log — a markdown document updated during each phase with the narrative: hypotheses, observations, assessments. The two are not redundant:

- `state.json` is what the hooks read to enforce safety
- `investigation.md` is what the Tier 2 judge reads to check semantic consistency
- `state.json` is machine-owned; `investigation.md` is agent-owned

Both live in the run directory. See `content/run-artifacts.md` for the full artifact layout.
