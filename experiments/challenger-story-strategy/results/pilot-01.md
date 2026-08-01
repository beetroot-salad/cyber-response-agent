# Pilot 01 — one fixture, one trial per arm

Fixture: `golden-case-018-squid-egress-officews1` (benign, 11 leads, 112K chars of payload).
Counter-direction: malicious. Model `glm-5.2`, effort `low`.

Scored twice: first by keyword heuristics (wrong — see below), then by a blind judge that
verified every claim against the real payloads. **The judge's classification is the result;
the heuristic numbers are kept only to show how they misled.**

## Result — judged

Ranking: **one-shot > iterative > lens.** Every claim in all three stories was verified against
a payload; nothing was unresolvable.

| arm | SETTLED | CONTESTABLE | **OPEN** | REFUTED | claims | calls | wall |
|---|---|---|---|---|---|---|---|
| one-shot | 2 | 2 | **2** | 0 | 6 | 1 | 158s |
| iterative | 42 | 0 | **0** | 0 | 42 | 4 | 474s |
| lens | 8 | 1 | **0** | 0 | 9 | 13 | 188s |

`OPEN` — no executed lead measures it — is the only class that can force a new query. One-shot
is the only arm that produced any, and the only one that admitted a claim it could not source.

## The mechanism, corrected

The first reading of this pilot — "refinement converges on transcription and therefore produces
nothing" — is **wrong on both refinement arms.**

**Iterative does not produce nothing. It produces findings and fails to promote them.** It was
the only arm to notice a second sshd running with a non-standard flag across 197 events, which
the defender had folded into "UDP traffic 198 — habitual" without ever reading the command line.
It was also the only arm to derive the container's real boot time from process elapsed-times,
which places the process tree the defender used to identify its "baseline scheduler" *after* a
nine-hour gap — so that tree says nothing about the 14 hours of probes the benign case rests on.
Both discoveries live in prose. Neither reached the claims block, which is 42 exact restatements
of payload values: a verification manifest, not a challenge.

So the defect is **promotion, not generation** — an output-shape problem, not a reason to
abandon the strategy.

**Lens fails structurally, in the opposite direction: it argues itself out of its own case.**
Each lens is asked what its lead forces and what it concedes; the fold accumulates the
concessions. The story ends with a section retracting its own initial access, persistence,
defense evasion, and camouflage, arriving back at the defender's conclusion with a hostile label
attached.

## What the keyword scoring got wrong

Kept as a caution. It ranked one-shot first for the right column (`unqueried`, a field the model
emits — no classifier involved) and was wrong about everything it inferred from free text:

- It scored lens as containing **zero** gap-language. Lens is the arm most full of concessions;
  the regex simply did not match the wording. The reading was inverted, not imprecise.
- Its bound/hedged split rewarded iterative's transcription as high-quality commitment and
  missed that iterative's only discriminating content was in prose the classifier never read.

`analyze.py`'s bound/hedged columns should not be used again. Replace with judge classification.

## Consequence for #774

The three strategies produce three *different* products, and the design wants all three:

- **one-shot → the challenge.** Claims that are open, and a next query.
- **iterative → the findings.** Defects in how the investigation read its own evidence —
  `lead-quality` and `analyze-discipline` in the existing taxonomy.
- **lens → the concession.** O8 wants the counter-story, the fact that kills it, and the
  inferences never tested. Concession accumulation is a defect in a challenger and exactly the
  behaviour a concession generator should have.

This also makes the critic load-bearing rather than decorative. The judge caught a category
error in iterative (asserting a host was "absent from the CMDB" when the CMDB has no IP field at
all, so no IP would ever be found) and a nine-hour timeline error in one-shot's prose. Both are
coherence defects a critic should catch before a gate acts on them.

## Do not over-read

n=1 fixture, 1 trial per arm, one direction (FN hunt). The lens intermediates were not persisted
on this run — the harness now saves them, so whether the per-lead lenses surfaced silence that
the fold discarded is answerable on the next run and is not yet answered.

## Next

1. Re-run lens with intermediates persisted; check whether silence was generated and dropped.
2. Test one-shot with an explicit instruction to emit only claims the executed leads do not
   settle — the pilot suggests the arms differ mostly in what reaches the structured tail.
3. Only then scale, with judge classification as the scorer.
