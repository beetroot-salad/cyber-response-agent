# predict-fastpath-ab — results (full sweep, 2026-04-26)

## Status

Full A/B sweep complete: 4 arms × 7 fixtures, including 1 adversarial
topology-collision fixture and 2 fall-through fixtures with no precedent.

## Headline numbers

| Arm | Description | Overall correct | Adversarial-collision correct |
|---|---|---|---|
| **A** | Sonnet, today-style priors | 6/7 (86%) | 0/1 ❌ |
| **B** | Sonnet, primed with strong-prior baseline | 5/7 (71%) | 0/1 ❌ |
| **C** | Haiku screen-predict (validate-or-escalate) | 3/7 (43%) | 0/1 ❌ |
| **D** | Handler-only IFF gate, no LLM | 7/7 (100%)\* | 1/1 ✅ |

\* D's 7/7 includes correct fall-through on cases where the gate honestly
returned `verdict=moderate` (sel=None). In production those cases route
to the existing PREDICT subagent, so D's contract is **"never pick a
wrong lead"** — not "always pick a lead." D never returned a wrong
fast-path lead in the experiment.

## Per-fixture detail

| Fixture | Expected | A (Sonnet) | B (primed) | C (Haiku) | D (gate) | GT |
|---|---|---|---|---|---|---|
| 5710-nagios-monitoring-probe | exact | ✅ | ✅ | ✅ | ✅ exact | approved-monitoring-sources |
| 5710-sensu-monitoring-probe | exact | ✅ | ✅ | ✅ | ✅ exact | approved-monitoring-sources |
| 5710-root-external | exact | ✅ | ✅ | ❌ ESCALATE | ✅ exact | external-bruteforce |
| 5710-admin-internal-collision (adversarial) | strong | ❌ aps | ❌ aps | ❌ aps | ✅ rejected | username-classification |
| 5710-novel-srcuser-internal | moderate | ✅ | ❌ source-class | ❌ ESCALATE | ✓ rejected | username-classification |
| 550-filebeat-inode-flap | exact | ✅ | ✅ | ✅ | ✅ exact | syscheck-db-state |
| 550-novel-opt-path | none | ✅ | ✅ | ❌ ESCALATE | ✓ rejected | file-classification |

(`aps` = "approved-monitoring-sources"; ✓ = correct fall-through, would
route to subagent in prod.)

## Key findings

### 1. The adversarial collision is the smoking gun

`5710-admin-internal-collision` has the **identical prologue topology +
identical vertex classifications** as SEED-5710-PROBE-001/002 — only the
`identifier` on the `monitoring-pattern` identity vertex differs
(`admin` instead of `nagios`/`sensu`). All three LLM arms — including
the strongest (Sonnet primed) — picked `approved-monitoring-sources`,
the historical lead. Only the deterministic IFF #5 key-attribute gate
caught it.

Why this matters: today's `_format_priors` block uses tier-1/2 prologue
matching that *also* misses this distinction. So the live PREDICT
subagent is currently being injected with monitoring-probe priors on
this kind of alert. The IFF #5 gate is doing work no existing component
does.

### 2. Priming Sonnet (arm B) hurts on ambiguous cases

B picked `source-classification` instead of `username-classification`
on the moderate-tier fixture (5710-novel-srcuser-internal). The
"treat the prior as your baseline" instruction nudges the model toward
the prior even when the gate reported only a moderate match — wrong
direction, since priors at moderate tier are exactly the ones we want
the model to reason past, not anchor to.

Implication: the production PREDICT prompt should **not** add a
"treat priors as baseline" line. The current neutral framing
("priors are sparse — scaffold from first principles") is correct.

### 3. Haiku screen-predict (arm C) escalates too readily

C correctly held the line on 3/4 exact-match cases but wrongly
escalated on `5710-root-external` (where the prior was actually
correct) and on both fall-through cases (where escalation is ok but
not the only correct answer). Haiku's conservative bias means C
captures the precision benefit of the IFF gate (never picks a wrong
lead on a precedent it accepts) but loses the recall benefit (often
escalates when fast-path was safe).

Implication: C is **not** a clear win over D. If the IFF gate already
caches the safety property, the marginal value of running Haiku as a
second-pass validator looks low. C might still earn its keep on
"strong but not exact" cases — but our experiment didn't include
enough strong-but-not-exact fixtures to prove it.

### 4. Arm A is the right baseline to keep

A got 6/7 with no priming, no extra subagent, no special routing —
just today's prompt. The one failure is the adversarial collision, and
the right fix for that is the IFF gate (D), not changing A's prompt.

## Recommendations

1. **Port D into production** as a pre-PREDICT gate in
   `scripts/handlers/predict.py:handle()`. On `verdict=exact`, skip the
   subagent and route directly to GATHER with a handler-authored
   `## PREDICT (loop N) — fast-path` marker. On any other verdict, run
   the existing subagent unchanged.
2. **Move `KEY_ATTRIBUTE_PATTERNS` into `playbook.md` frontmatter** as
   `discriminating_classifications:` — keep the gate data-driven and
   per-signature.
3. **Defer arm B's priming line.** The experiment shows it harms more
   than it helps.
4. **Defer arm C (Haiku screen).** Run a follow-up experiment on
   "strong but not exact" cases before committing engineering effort.
5. **Don't retire SCREEN.** Out of scope here, but D and SCREEN solve
   different problems — SCREEN bypasses the entire loop on pattern
   match; D only bypasses the predict subagent.

## Caveats

- Tiny corpus (4 seeded precedents, 7 fixtures). Conclusions are
  directional, not statistical.
- All "strong but not exact" cases were absent — couldn't measure C's
  best-case scenario.
- IFF #6 was tripped by an incomplete seed (the filebeat precedent
  didn't carry `syscheck.path` until we fixed it). In production,
  precedents come from real `runs/*/investigation.md` files which
  always carry the full alert — the seed limitation does not transfer.
- IFF #10 (consensus) was never exercised — no fixture had two
  precedents passing IFF #1–9 with different lead picks.

## Open follow-ups

- Build 2–3 "strong but not exact" fixtures (e.g. internal-monitoring
  source + service-account identity instead of monitoring-pattern
  identity) and re-run B/C/D to test the strong-tier zone.
- Wire token-cost capture into `_llm.invoke` (currently captures elapsed
  but not tokens — the runner row has a placeholder).
- Try a 5th arm: Haiku without the screen framing, just plain "pick a
  lead" — to isolate whether C's losses are about Haiku capability or
  about the validate-or-escalate prompt shape.
