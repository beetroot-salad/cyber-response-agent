---
title: Model gathering leads as first-class citizens in invlang schema
status: doing
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
- **Add `predictions` at the lead level** for interpretation-vulnerable leads that are not branching. Structure them as **conditional branch plans**, not as flat "how I'd read this" notes:

  ```yaml
  lead:
    predictions:
      - if: <outcome pattern>
        read_as: <interpretation>
        advance_to: <next lead | CONCLUDE | HYPOTHESIZE>
  ```

  Empirical finding (Alert D probe, see §Empirical validation): agents naturally produce predictions in this triple form. A prediction is not just an interpretation commitment — it is simultaneously a pre-committed routing decision. Making this structure explicit makes it auditable at commit time (did the agent route per their rule?) and forces the agent to write predictions that are actually decision-consequential.

- Lead-level predictions and hypothesis-level predictions are **not isomorphic**. They are two distinct shapes of pre-commitment:

  | Form | Commits to | When to use |
  |---|---|---|
  | Hypothesis + predictions (per-hypothesis) | Named world models; predictions test them | Multiple plausible explanations, analytically distinct, divergent step-1 leads |
  | Lead + predictions (conditional branches) | Decision rules on a shared next-step lead | Same step-1 lead regardless; the *reading* determines step-2 |

  The first is **ontological** (asserting worlds exist), the second is **procedural** (asserting decision rules). Case D (DLP volume anomaly) shows the procedural form — `authorized / not-authorized / partial` aren't worlds, they're readings of a fuzzy outcome each opening a different step-2. Forcing it into hypothesis form would be backwards.

- Class 8 becomes two orthogonal scores, not one: (fork-collapse weight delta) + (prediction-match fidelity). Mechanical non-branching leads score zero on both — correctly — without being penalised as *bad* diagnostics.
- `_infer_lead_type` in `queries.py` goes away; the existence/absence of `tests` and lead-level `predictions` is the ground truth.

- **Unit of interpretation-vulnerability is the outcome field, not the lead.** A single lead can mix mechanical fields (UID, count) with interpretive ones (process-name plausibility, threshold judgment). The schema doesn't need a per-field vulnerability flag, but the skill guidance does — agents should pre-register readings on the *specific fields* where the judgment lives, not on "the lead."

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

## Empirical validation (sonnet agent probes)

Two rounds of sonnet-agent probes against the revised philosophy + a dummy alert, planning phase only (no tool execution). Each agent asked to classify the first lead in the branching × interpretation-vulnerability matrix, name the lead, and pre-register hypotheses/predictions per the cell.

**Round 1 — three alerts designed to cover three cells:**

| Case | Designed cell | Agent's call | Observation |
|---|---|---|---|
| A — FIM sudoers modified | no/no (mechanical actor lookup) | yes/yes | Reasoned forward to step-2 fork; pre-allocated hypotheses before step-1 outcome |
| B — SSH invalid user | no/yes (narrative drift risk) | yes/no | Reframed first lead from interpretive reputation → mechanical volume count |
| C — Prod DB outbound to low-rep IP | yes/yes | yes/yes | Correctly enumerated three hypotheses with concrete predictions |

**Round 2 — targeted probes against the failures from Round 1:**

| Case | Target | Agent's call | Observation |
|---|---|---|---|
| D — DLP access-volume anomaly | Force bottom-left (no/yes) | no/yes | Landed in bottom-left; produced three conditional-branch predictions |
| E — Same FIM alert as A, with explicit one-ply lookahead guidance | Test whether horizon guidance binds | no/no | Clean shift from Case A's yes/yes → no/no |

**Findings:**

1. **"Branching" was silently overloaded on lookahead horizon.** Without explicit guidance, agents evaluated forks at the whole-plan level (Case A → yes/yes because step-2 forks). Adding an explicit one-ply rule ("branching is evaluated on the very next lead only; pre-registering step-2 forks before step-1's outcome is over-branching") fixed this decisively (Case E → no/no).
2. **Agents reframe leads to dodge interpretation-vulnerability when they can** (Case B). This is a win for investigation quality (the mechanical volume count is a better first lead than the interpretive reputation read). But it means the narrative-drift failure mode is rarer in practice than feared — competent agents route around it.
3. **The bottom-left cell is reachable and productive when forced** (Case D). Agent pre-registered three readings with concrete routing consequences. The lead-level prediction slot is *not* vestigial — but its content is conditional branch plans, not flat reading rules (see schema revision).
4. **Interpretation-vulnerability is per-field, not per-lead.** Case A's agent correctly treated `process-name plausibility` as interpretive but `UID match` as mechanical within the same lead. The matrix's binary lead-level classification is too coarse; skill prose should direct pre-registration to the specific fields where judgment lives.

## Open questions — status after probes

1. **Self-subject judgement of branching — largely resolved.** Explicit **one-ply lookahead** rule binds cleanly. Skill prose must include: "*Branching is evaluated on the very next lead only. If the immediate next lead is the same regardless of which explanation is true, you are NOT in a branching regime — even if step-2 might later diverge. Hypothesize when the fork opens, not before.*" Plus a reclassification cue: name what outcome would open the fork. Promote this from open question to skill-prose requirement.

2. **Interpretation-vulnerability spectrum — refined, not closed.** Two clarifications fall out of Round 2:
   - The unit of vulnerability is the **outcome field**, not the lead. Pre-register on the field that carries the judgment (process-name plausibility, threshold call, reputation weighting), not on "the lead is interpretive."
   - Lead-level predictions are **conditional branch plans** (`if <pattern> → read_as <interpretation> → advance_to <next>`), not flat reading rules. This is auditable at commit time: did the agent actually route per their pre-committed rule? Build the schema and skill guidance around this triple form.

   Still open: the "reviewer test" question (could a reviewer reasonably disagree with my reading?) would help agents self-diagnose *which* fields need pre-registration. Worth piloting in skill prose as a concrete operable heuristic.

## Implementation order (once design lands)

1. **Skill prose** (can land first; unblocks live corpus observation of the new regime):
   - On-demand HYPOTHESIZE phrasing (HYPOTHESIZE enters by fork, not by phase gate).
   - Explicit one-ply lookahead rule with reclassification cue ("the fork opens when…").
   - Worked examples for each of the four cells, drawn from probe alerts (A/E = no/no, B = yes/no, C = yes/yes, D = no/yes).
   - Per-field pre-registration guidance: name the specific outcome fields where judgment lives.
2. **Schema:** add lead-level `predictions` block in conditional-branch-plan form (`if / read_as / advance_to`); keep `hypothesize` optional; drop plans for `lead_kind` enum.
3. **Validator:** check prediction structural validity (triple form); verify agent routed per their pre-committed rule (the `advance_to` next-lead matches what was actually run); `tests` absence is no longer penalised.
4. **`queries.py`:** retire `_infer_lead_type`; split Class 8 into branching-delta + prediction-fidelity (including route-compliance fidelity).
5. **State machine:** loosen `infer_state.py` to allow HYPOTHESIZE mid-loop; reconsider whether phase headers still carry their current meaning, or whether the triage-in-line model deprecates them.

## Related work

- `invlang-structured-observations.md` — graph-model refinements in flight
- `invlang-canonicalize-hypotheses.md` — hypothesis identity/deduplication, affected by this reframing
- `state-transition-criteria.md` — state machine work this directly impacts