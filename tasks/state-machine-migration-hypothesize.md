---
title: Migrate HYPOTHESIZE to orchestrator handler
status: todo
groups: state-machine-migration, state
depends_on: state-machine-migration-screen
---

Replace the HYPOTHESIZE section of `skills/investigate/SKILL.md` with a handler that dispatches the `hypothesize` subagent (which folds the ASSESS decision per commit 8ae6f23).

Handler contract:

- Input: `Context` with CONTEXTUALIZE (+ optional SCREEN, prior ANALYZE) outputs
- Work: spawn `hypothesize` subagent — produces lean one-hop seeds with causal stories and a selected lead
- Output: `PhaseResult(next_phase=GATHER, payload={active_hypotheses, selected_lead})` — HYPOTHESIZE's only legal next move is GATHER per `TRANSITIONS` in `schemas/state.py`

On-demand re-entry: GATHER and ANALYZE handlers may return `next_phase=HYPOTHESIZE` when a new fork opens — the orchestrator already permits both. Counts toward `MAX_LOOPS` (HYPOTHESIZE entries plus ANALYZE entries).

Validate: no regression in hypothesis count / causal-story discipline against the `/testrun` suite. `invlang_validate.py` PreToolUse hook still passes on every `investigation.md` write.

## Candidate: attacker-mimic audit of predictions + refutation_shape

The ANALYZE-cutover stress tests ran an A/B/C framing experiment on a
Haiku sensitivity probe (see
`docs/experiments/analyze-subagent-pilot/stress-test/framing-ab/findings.md`
and `…/harder-round/findings.md`). Headline: ANALYZE is robust enough
on its own that the probe is not needed at ANALYZE time — 9/9 clean
on bias traps, 3/3 clean on a stacked-circumstantial-`++` trap it
hadn't seen.

The probe's real value surfaced somewhere else: it catches **naively-
formulated predictions** that assume attackers act crudely. Harder-
round trial 2 had a HYPOTHESIZE block where `?adversary-controlled-
service-principal`'s `p2` predicted "wide column selection, minimal
or absent WHERE filters" — ignoring that a compromised service
principal would inherit the legitimate service's existing query
templates (bounded SELECT with WHERE). The attacker-mimic probe caught
the mis-formulation and surfaced the bias correctly.

This is a HYPOTHESIZE-time concern, not an ANALYZE-time one. The
predictions + `refutation_shape` entries are declared at HYPOTHESIZE
time; any flaw there propagates forward and can't be fixed downstream
without rewriting those IDs (which rule #13 prevents — append-only).

### Shape of the probe as a HYPOTHESIZE audit

After the `hypothesize` subagent emits its hypotheses block, run a
Haiku audit pass with the attacker-mimic framing. For each
hypothesis, ask:

> "Roleplay an adversary. Could you produce the predicted-negative
> shape of this hypothesis while actually doing the adversarial thing?
> Name one concrete method."

If the audit returns a plausible concrete method for any hypothesis,
the prediction/refutation shape is too narrow — the hypothesis needs
refinement (split into sub-hypotheses, tighten the refutation shape
with a positive confirming anchor rather than a negative absence, or
declare the hypothesis observationally-indistinguishable and note it
in the causal story).

### Empirical basis

- N=3 per framing arm in the harder round; attacker-mimic framing
  outperformed adversarial and peer-audit on probe-quality axes
  (ranking: attacker-mimic ≥ peer-audit > adversarial).
- Critical prompt constraint observed: the probe must require a
  **concrete attacker method**, not "an attacker could have done
  something." Without that clause, the framing collapses into generic
  over-caution.
- The probe also must require a **counterfactual**, not a
  fact-assertion — adversarial-framing trials showed Haiku will
  fabricate supporting facts under pressure, inducing false
  revisions. The attacker-mimic framing did not show this failure.

### Scope for this task

Not required for the initial HYPOTHESIZE cutover. Ship the handler
first, observe real-run output for a short period, then decide
whether to add the audit as a post-hypothesize-subagent step in the
handler. Track separately if adopted. The `surviving_hypotheses`
field from rule 24 gives a natural hook: any hypothesis listed
there should have survived a prediction/refutation audit.
