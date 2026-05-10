# Investigation-Language Prior-Format Pilot

Empirical probe: does an invlang-structured prior help a downstream
HYPOTHESIZE/ANALYZE subagent produce better outputs than the same prior
rendered as natural-language prose?

## Claim under test

> Structuring prior investigation state in invlang improves the
> correctness and efficiency of the next hypothesize/analyze turn,
> relative to an equivalent natural-language log — and the advantage
> grows with investigation depth.

## Design

**3 arms** (prior-context format):
- **A — invlang**: full YAML companion (prologue + hypothesize + gather up to the cut)
- **B — NL log**: prose `investigation.md` carrying the same evidence
- **C — minimal** (control): alert + hypothesis list only, no gather history

**Variants** — each case is tagged on two orthogonal axes:

*Surface* (what a fast read of the alert + first lead suggests):
- `looks-benign` — surface reads as routine activity
- `looks-malicious` — surface reads as attack
- `mixed` — both interpretations plausible at the surface

*Truth* (ground-truth disposition):
- `benign`
- `malicious` — true positive
- `ambiguous` — genuinely inconclusive even after full investigation; escalate

The stress cells — where methodology matters most — are the mismatched
ones:
- `looks-benign × malicious` (**stealthy attack**) — methodology must
  resist closing early
- `looks-malicious × benign` (**noisy false-positive**) — methodology
  must resist escalating early
- `mixed × ambiguous` — methodology must know when to stop and escalate

**Synthesis is required for stealth.** The playground is a low-complexity
simulation — `looks-benign × malicious` cases at meaningful depth don't
exist in real runs. Any case claiming surface-vs-truth mismatch must be
hand-authored. Past-run cases are labeled honestly against this bar;
see `case-candidates.md` for which cells are filled from runs vs.
synthetic.

**Depths** (per variant):
- `shallow` — 2 leads into the loop
- `deep` — 5+ leads in

**Trial** = arm × variant × depth × case. Fresh session per trial so
context doesn't contaminate. Target ~9 cases → ~162 trials with the
single-turn proxy.

**Distribution is benign-skewed** to mirror real SOC volume (the vast
majority of alerts resolve benign or false-positive). The case set
weights toward benign outcomes without starving the stress cells:
target mix is roughly 6 benign / 2 malicious / 1 ambiguous. The goal
is not a balanced dataset but a realistic one — if structured prior
adds overhead on easy cases, that overhead matters, because easy cases
dominate real volume.

## What we measure (single-turn proxy)

Given the prior, the subagent emits one turn: pick next lead + record
assessments for any `--`-able hypotheses. Score:

- **Lead in gold set?** (discriminating / acceptable / trap)
- **Assessment agreement** with hand-labeled gold
- **Token cost** of the prior + output

End-to-end (full-loop) runs are out of scope for this round — rerun a
narrow slice only if the single-turn signal is ambiguous.

## Ground truth

Hand-labeled per case × depth — see `cases/_template/case.yaml` for
the schema. The author records:
- event timeline (source of truth; renderers derive each arm from this)
- active hypotheses at the cut
- **gold next-lead set** (1–2 acceptable discriminating leads)
- **trap leads** (plausible but wasteful)
- **gold assessment** at the cut (disposition belief + confidence)

## Layout

```
cases/
  _template/case.yaml     — fillable source schema
  case-{name}/case.yaml   — one per labeled case
rounds/
  round-{n}-{tag}/        — per-run outputs + comparison writeup
scripts/
  render_prior.py         — case + depth + arm → prior context
  run_arm.py              — invoke subagent on a trial, capture output
  score.py                — compare captured output to gold
```

## Status

Scoping. Schema + renderer + runner not yet written. No cases labeled.
