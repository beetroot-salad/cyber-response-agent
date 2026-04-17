---
title: Model gathering leads as first-class citizens in invlang schema
status: backlog
groups: invlang, investigate, schema
---

## Problem

The current skill frames all leads as discriminating — HYPOTHESIZE asks "which lead is most diagnostic?" and Class 8 (`lead_effectiveness`) scores leads by hypothesis weight delta. Gathering leads (entity profiling, session reconstruction, timeline enrichment) don't change hypothesis weights but enrich the investigation graph. They are currently:

- Penalized by Class 8 (weight delta ≈ 0 → low effectiveness score)
- Excluded from lead selection guidance ("pick the most diagnostic lead")
- Recorded as low-value leads even when they meaningfully expanded the investigation context

The diagnostic-first framing also produces sham hypotheses for scoping questions. Example: "file X was accessed — which identity accessed it?" Under the current framing the agent must enumerate `?user-A`, `?user-B`, … as competing hypotheses and then "discover" that an identity lookup discriminates them. The hypothesis layer adds no value — the same lead was inevitable — and the companion ends up cluttered with nominal forks.

## Reframing: what hypotheses are actually for

Hypotheses serve two functions that are normally conflated:

1. **Pre-registration / objectivity** — committing to predictions before the outcome is observed prevents post-hoc rationalization.
2. **Lead derivation** — providing a principled way to choose the next lead by its discrimination power.

The tight reformulation that makes the framing elegant:

> **A hypothesis is a fork in the investigation plan, not a description of a possible world.**

A hypothesis earns its keep iff committing to it would change (i) which lead you run next, or (ii) how you'd interpret the outcome of a lead you were going to run anyway. Enumerating possible worlds without a fork is ceremonial.

This makes the two motivations above **orthogonal axes**, not a single concept:

- **Branching** — does next-lead choice depend on which explanation is true?
- **Interpretation-vulnerability** — would reading the outcome post-hoc risk rationalization?

Evaluated per loop iteration:

| Branching? | Interpretation-vulnerable? | What the agent does |
|---|---|---|
| yes | yes | Articulate hypotheses AND pre-register predictions |
| yes | no | Articulate hypotheses, skip prediction blocks (mechanical fork, e.g. identity lookup that decides a branch) |
| no | yes | Skip hypotheses, pre-register predictions at the **lead** level (e.g. narrative reputation read) |
| no | no | Gather mechanically, no ceremony |

The current schema forces everything into the top-left cell. This task is about modelling the other three.

## Failure modes this criterion prevents

**Narrative drift during enrichment.** Alert: SSH invalid-user from an IP. Pure-gathering agent runs reputation lookup, geolocation, prior-alert counts — gradually constructs a "looks like a scan" story. Evidence was interpretation-vulnerable at every step and the conclusion sediments before a verdict was ever committed. Pre-registering "I'll read this as confirming `?opportunistic-scan` iff reputation ≤ 2 AND ≥5 unrelated targets in 24h" lands the same mixed signal honestly as `+` rather than `++`. Predictions earn their keep on interpretive leads *even when lead choice is obvious*.

**Missing leads that no gathering would surface.** Alert: file X read by identity I. Gathering-only agent resolves I, recent activity, file sensitivity — concludes "normal access." The lead that catches exfil (session freshness + geography anomaly) is only obvious once `?credential-compromise` predicts "the session used is recent and anomalous." Hypotheses generate leads that mechanical graph-painting does not.

**Cargo-cult enumeration.** Alert: unknown process on a server. Over-hypothesizing agent writes `?malware-dropper`, `?legit-patch`, `?misconfig-cron`, `?admin-debug`, `?supply-chain` — five prediction blocks. First lead (parent process = `cron`) collapses four instantly. Under the branching criterion, `?admin-debug` vs `?legit-patch` fold into one because the parent-process lead doesn't distinguish them at this resolution.

## Consequences for the schema

- Do **not** add a `lead_kind` enum. `lead.tests` already carries the branching signal truthfully: present ⇒ fork-collapsing, absent ⇒ not. A categorical label on top of this would re-introduce the diagnostic-vs-gathering dichotomy we're trying to dissolve.
- `hypothesize` stays optional. Its meaning shifts from "initial enumeration of possible worlds" to **"the lead space branched here"**. It remains re-entrant via `new_hypotheses` inside subsequent leads.
- **Add `predictions` at the lead level** for interpretation-vulnerable leads that are not branching. Covers the narrative-reputation case without forcing sham hypotheses. Structure mirrors hypothesis predictions (id + claim + what-would-refute).
- Class 8 becomes two orthogonal scores, not one: (fork-collapse weight delta) + (prediction-match fidelity). Mechanical non-branching leads score zero on both — correctly — without being penalised as *bad* diagnostics.
- `_infer_lead_type` in `queries.py` goes away; the existence/absence of `tests` and lead-level `predictions` is the ground truth.

## Consequences for the investigation loop

HYPOTHESIZE becomes **on-demand**, not a mandatory gate:

```
CONTEXTUALIZE
  │
  ▼
TRIAGE ◀─────────────────────────────────┐
  │                                      │
  ├─ branching? ── yes ──▶ HYPOTHESIZE   │
  │                (articulate the fork) │
  │        no                            │
  ▼        ▼                             │
GATHER (pre-register predictions iff     │
        outcome is interpretation-       │
        vulnerable)                      │
  │                                      │
  ▼                                      │
ANALYZE ─────────────────────────────────┘
  │
  ▼
CONCLUDE
```

HYPOTHESIZE may be re-entered any time ANALYZE reveals a new fork. Termination rules (trust-root / adversarial-refuted / severity-ceiling / exhaustion) are unchanged.

The current state machine encoded in `infer_state.py` must be revisited — the fixed CONTEXTUALIZE→HYPOTHESIZE→GATHER→ANALYZE sequence no longer holds. At minimum, HYPOTHESIZE headers become optional and may appear mid-loop.

## Open questions (blocking skill-side work)

These are the hard parts and need a second pass before the skill guidance can be written:

1. **Self-subject judgement of branching.** "Would the next lead differ if I committed?" requires imagining counterfactual leads. Agents may under-branch (laziness — skip the fork, drift narratively) or over-branch (anxiety — cargo-cult enumeration). The criterion needs operable guidance, probably worked examples, not a rule.
2. **Interpretation-vulnerability is a spectrum.** Every lead has some interpretive surface. "Pre-register when the outcome is one step more ambiguous than a field lookup" is fuzzy. Possibly want a third question on top ("could a reviewer reasonably disagree with my reading?") or a staged threshold.

Both are live topics — continue design discussion before implementing schema or skill changes.

## Implementation order (once design lands)

1. Schema: add lead-level `predictions` block; keep `hypothesize` optional; drop plans for `lead_kind` enum.
2. Validator: prediction-match rules mirror existing hypothesis prediction rules; `tests` absence is no longer penalised.
3. `queries.py`: retire `_infer_lead_type`; split Class 8 into branching-delta + prediction-fidelity.
4. Skill prose: on-demand HYPOTHESIZE phrasing; worked examples for each of the four cells in the branching × interpretation table.
5. State machine: loosen `infer_state.py` to allow HYPOTHESIZE mid-loop; reconsider whether phase headers still carry their current meaning.

## Related work

- `invlang-structured-observations.md` — graph-model refinements in flight
- `invlang-canonicalize-hypotheses.md` — hypothesis identity/deduplication, affected by this reframing
- `state-transition-criteria.md` — state machine work this directly impacts
