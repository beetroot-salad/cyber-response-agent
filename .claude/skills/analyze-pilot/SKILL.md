---
name: analyze-pilot
description: Probe the extraction of the ANALYZE phase into a dedicated subagent. Empirically determines what context is load-bearing for weighted-assessment work and whether the subagent should own routing (HYPOTHESIZE|CONCLUDE) or produce assessment only. Project-level dev skill — not part of the production soc-agent plugin.
argument-hint: "[status | next | method | launch <round>]"
---

# ANALYZE Subagent Extraction — Pilot Experiment Skill

Part of the subagent-extraction workstream (sibling to the existing
CONTEXTUALIZE, SCREEN, GATHER subagents). Token pressure in the main
investigation loop is dominated by repeated ANALYZE entries; ANALYZE has
a relatively clean I/O boundary (evidence in → weighted assessment +
route out) and is called every loop iteration, so extraction savings
compound.

**Pilot lives at:** `docs/experiments/analyze-subagent-pilot/`
**Working directory assumption:** all paths relative to `/workspace/`.

---

## The two questions this pilot answers

1. **What context is load-bearing?** ANALYZE's rules are state-bearing
   in ways that look invisible from the outside — prior grade history,
   named refutation checks, pre-registered lead predictions, adversarial
   status, archetype/anchor gate. The pilot probes this by varying the
   context bundle across arms and observing which items a subagent
   silently needs vs. hallucinates vs. ignores.

2. **Who owns the routing decision?** ANALYZE ends with a transition:
   HYPOTHESIZE (need another lead) | CONCLUDE (done). Two candidate
   contracts:
   - **Decision-owning contract** — subagent emits weighted assessment
     *and* routing decision; main agent routes directly on the verdict.
   - **Assessment-only contract** — subagent emits only the weighted
     assessment; main agent reads it and routes in its own context.

   The decision-owning contract gives bigger token savings but demands
   more context (archetype anchors, adversarial status, loop budget).
   The assessment-only contract is cheaper per invocation but risks the
   main agent re-deriving context — partially defeating the goal.

The trust-check round (Round C below) is the primary signal for
question 2: given subagent output, does the main agent route directly
or re-read the log / re-query?

---

## Current state

**Phase:** Round 1 complete. One fixture run; signal too weak to lock contract.
**Fixtures:** `case-rule5710-loop1` (real rule-5710, loop 1, escalation shape).
**Rounds:** `round-1/` (A/B/C on case-rule5710-loop1).
**Locked contract:** None.

**Round 1 headline findings** (see `rounds/round-1/comparison.md`):
- Arm A (minimal context) graded 5/5 exact; Arms B and C graded 4/5, both
  drifting `?monitoring-loop-broken` from ground-truth `-` to `+`.
- Drift traces to the structured pre-commitments format biasing toward
  checklist-counting over mechanism-refutation reasoning.
- Routing varied (A→HYPOTHESIZE, B→CONCLUDE, C→HYPOTHESIZE) but the
  fixture has ambiguous routing ground truth — original investigation's
  ANALYZE text said CONCLUDE but then ran loop 2 anyway.
- Adversarial preservation (`?compromise` stays live at `-`) worked in
  all arms, including Arm A from raw prose — this rule is robust.
- No arm used signature threat model, loop budget, or lead `definition.md`
  pitfalls in its reasoning.

**Provisional bundle verdict** (one fixture — weak signal):
- **Necessary:** truncated investigation log + lead output. That's it.
- **Harmful on the margin:** structured pre-commitment extraction
  (biases toward checklist tabulation).
- **Nice-to-have:** archetype/anchor gate context (sharpens routing
  rationale, doesn't change grades).
- **Ignored:** threat model, loop budget, lead pitfalls.

**Round 2 priorities:**
1. Fixture with crisp routing ground truth (fast-resolve SCREEN match,
   or a loop that CONCLUDEd without follow-on).
2. Arm B′ variant: pre-commitments as mechanism statements rather
   than prediction checklists (tests the checklist-bias hypothesis).
3. Mid-loop fixture with prior ANALYZE grade history (tests
   rollup-drift dimension Round 1 could not exercise).

---

## Candidate context bundle (what an arm might receive)

Derived from a close reading of `soc-agent/skills/investigate/SKILL.md`
§ANALYZE and `docs/investigation-language.md`. Items 1–6 live in the
invlang companion and can be extracted from `investigation.md`;
items 7–11 need out-of-band sourcing.

| # | Item | Source | Why ANALYZE needs it |
|---|------|--------|---------------------|
| 1 | Observations from the just-run lead | `gather:` lead block `outcome` | The evidence being weighed |
| 2 | Active hypotheses + their predictions + refutation_shape | `hypothesize:` block and per-lead `new_hypotheses` | The claims being tested |
| 3 | Prior grade history per hypothesis | Prior `gather:` blocks' `resolutions[].after` | Prevent rollup-across-siblings drift |
| 4 | Pre-registered lead-level `predictions` | Current lead's `predictions` triples | Route-compliance check |
| 5 | Entity graph / pre-existing relationships | `prologue:` vertices+edges; earlier lead `outcome.observations` | Assess evidence in context |
| 6 | Adversarial hypothesis status | Hypothesis `status` field + concerns | CONCLUDE-eligibility gate |
| 7 | Signature threat model / target sensitivity | `knowledge/signatures/{id}/context.md` | `++` threshold; high-sensitivity escalate rule |
| 8 | Lead `definition.md` pitfalls | `knowledge/common-investigation/leads/{lead}/definition.md` | Severity-of-test calibration |
| 9 | Data-source health / preflight gaps | Run-time preflight output (env-level) | Can't grade absence as `--` over a dark system |
| 10 | Loop count + budget proximity | `state.json` + constant | Termination-category choice |
| 11 | Invlang schema (focused ANALYZE excerpt) | `knowledge/invlang/schema.md` subset | Valid `gather:` block emission |
| 12 | Archetype match + `required_anchors` + `trust_anchors_consulted` so far | CONTEXTUALIZE output + running report state | Verify/scope gate for `++` mechanism |
| 13 | Past-investigation calibration priors | Corpus query subagent | "Has this assessment pattern reversed before?" — optional |

The pilot's job is to sort these into **load-bearing / nice-to-have /
ignored** by varying which ones each arm sees.

---

## Experimental method

Each pilot round selects **one fixture** (a real past run with a clean
ANALYZE boundary) and runs 3–4 arms in parallel. All arms are **Sonnet**
— Haiku is not the model under test here; the question is what context
Sonnet needs, not whether Haiku can do the work.

### Fixture shape

From a completed run at `soc-agent/runs/{run-id}/`, extract:

1. **Truncated `investigation.md`** — cut immediately before a real
   ANALYZE entry. Include CONTEXTUALIZE, HYPOTHESIZE, and all prior
   GATHER/ANALYZE blocks; exclude the ANALYZE we're asking the subagent
   to reproduce and everything after.
2. **The lead output being analyzed** — the raw `gather:` block that
   preceded the held-out ANALYZE (query, query_details, outcome
   observations; NOT the resolutions — those are part of the held-out
   work).
3. **Ground-truth ANALYZE** — what the original run produced. Not shown
   to subagents; used for scoring.

Save fixture as
`docs/experiments/analyze-subagent-pilot/fixtures/{fixture-id}/`:
- `truncated-investigation.md`
- `lead-output.yaml`
- `ground-truth-analyze.md` (the held-out block)
- `signature-context.md` (for arms that get it)
- `notes.md` (what shape the fixture exercises — mid-loop reversal,
  clean archetype match, escalation, etc.)

Prefer **3 fixtures spanning shapes**: one clean archetype match, one
escalation (adversarial remains live), one mid-loop reversal or grade
downgrade. A single fixture gives anecdotes; 3 gives weak patterns.

### The arms — progressive context expansion

Each round runs the same fixture through arms with progressively
richer context bundles. The gap between arms is the load-bearing signal.

**Arm A (minimal)** — invlang schema excerpt + truncated
`investigation.md` + lead output. Nothing else.
> Probes: can a subagent derive everything it needs from the log?
> Watch: does it re-derive prior grades correctly? does it hallucinate
> refutation checks that were never named?

**Arm B (+ hypothesis pre-commitments)** — Arm A + explicit extraction
of pitfalls, named refutation checks (the `++ requires attempted
refutation` rule), pre-registered lead `predictions`, and adversarial
status flags.
> Probes: do these items actually catch errors Arm A made, or was the
> subagent already handling them from the raw log?

**Arm C (+ org context)** — Arm B + signature threat model / target
sensitivity, archetype match + `required_anchors` + anchors consulted
so far, data-source health, loop count + budget.
> Probes: does org context change the grade or the routing decision?
> Watch specifically for the verify/scope gate — does the subagent
> correctly demand anchor confirmation before awarding `++`?

**(Round C only) Trust-check arm** — feed Arm-B or Arm-C output into a
fresh main-agent invocation (Sonnet, `subagent_type=general-purpose`)
and instruct it to decide next action. **Primary signal is its tool
calls**, not its prose. If it silently re-reads `investigation.md`,
re-queries the SIEM, or re-derives grades, the handoff contract is
insufficient. If it routes directly on the subagent's verdict, the
assessment-only contract is viable.

### Launch mechanics

Arms per round launch in parallel via the Agent tool:

- `subagent_type: "general-purpose"`, `model: "sonnet"`
- `run_in_background: true`, one Agent call per arm
- All Agent calls in a **single message** so they run concurrently
- Arms must not read each other's artifacts; the prompt lists forbidden
  paths explicitly (other arms' outputs, the ground-truth file)
- Output goes to `rounds/{round-id}/arm-{A,B,C,trust}.md`

### Scoring dimensions

Grade each arm's output against these dimensions (binary or 0/1/2):

| Dimension | What to check |
|-----------|---------------|
| Grade correctness | Does `after` per hypothesis match ground-truth within ±1 step? |
| Rollup drift | Did the subagent upgrade a hypothesis on evidence supporting a sibling? |
| Refutation-attempt discipline | For any `++`, was a concrete refutation check named or cited? |
| Adversarial preservation | Is the adversarial hypothesis status correctly carried forward? |
| Route compliance | If the lead had pre-registered `predictions`, did the next-step match an `advance_to`? |
| Archetype/anchor gate | For `++` mechanism under an archetype with `required_anchors`, did the subagent demand anchor confirmation? |
| YAML well-formedness | Is the emitted `gather:` block schema-valid (invlang validator passes)? |
| Hallucinated context | Did the subagent cite predictions, refutations, or pitfalls that don't exist in the input? |

For the trust-check arm, the dimensions are different:

| Dimension | What to check |
|-----------|---------------|
| Handoff acceptance | Did the main agent route directly on the subagent's verdict, or re-derive? |
| Re-query behavior | Did the main agent issue any tool calls that duplicate the subagent's work? |
| Disagreement shape | If the main agent overrode the subagent, what context pulled it to a different decision? |

### Deliverables per round

`rounds/{round-id}/comparison.md`:
- Headline (1 paragraph): what the gap between arms revealed
- Per-arm scoring table across the dimensions above
- Load-bearing classification: **necessary** (missing it broke arms),
  **nice-to-have** (arms without it succeeded but with caveats),
  **ignored** (arms with it behaved identically to arms without)
- Trust-check observations (if applicable): routing acceptance rate,
  re-query behavior, disagreement cases
- Recommendation: which contract to lock (decision-owning /
  assessment-only / hybrid), and which context items the bundle must
  include

---

## Contract decision criteria

After 3 fixtures run through all arms, decide the fork:

**Lock decision-owning contract if:**
- Arm-C output reliably matches ground-truth routing, AND
- Trust-check arm routes directly without re-deriving in ≥2/3 cases, AND
- The minimum context bundle is narrow enough to be cheaper than just
  letting the main agent do ANALYZE inline.

**Lock assessment-only contract if:**
- Arm-C produces reliable weighted assessment but routing varies, OR
- Trust-check arm consistently re-queries or re-reads the log, OR
- The required context bundle for decision-owning is so wide that
  token savings evaporate.

**Hybrid / abort if:**
- No arm reliably matches ground-truth → ANALYZE may be too
  context-entangled to extract; revisit the assumption that extraction
  saves tokens.

---

## Argument handling

- **`status`** (default) — summarize phase, which fixtures exist, which
  rounds have run, which contract is locked (if any).
- **`next`** — recommend the next concrete action. Usually "select
  fixture N" or "run round M on fixture X".
- **`method`** — print the experimental method section verbatim.
- **`launch <round>`** — set up a new round. Walks through: confirm
  fixture, draft the per-arm prompts, launch the Agent calls in
  parallel, write comparison. Ask user to confirm fixture + arm set
  before spending tokens.

If the arg is unclear, default to `status`.

---

## How to continue

### Select fixtures (first priority)

Read `soc-agent/runs/` for completed runs. Pick 3 spanning:

- **Clean archetype match** — ends in `resolved`, archetype matched,
  anchors confirmed, benign disposition.
- **Escalation** — adversarial hypothesis remains live, `escalated` /
  `inconclusive`, loop budget meaningfully consumed.
- **Mid-loop grade reversal** — a hypothesis went `+` → `-` or `++` →
  `+` across loops. Rarer but especially informative for rollup-drift
  testing.

For each, run `bash soc-agent/scripts/invlang/run.sh --ids {run_dir}/investigation.md`
to verify invlang validity (sanity check — a fixture that doesn't
validate is not a useful baseline). Copy into
`fixtures/{fixture-id}/` with the shape listed under "Fixture shape".

### Run round 1 on fixture 1

Launch Arm A, B, C in parallel. Do NOT run the trust-check arm yet —
it only makes sense once we know which bundle produces reliable output.
Score against ground truth. Write `rounds/round-1/comparison.md`.

If Arm A already matches ground truth: the invlang log carries enough
context unaided; extraction is easier than expected. If Arm C fails:
we're missing a context item not on the candidate list — expand.

### Run round 2 + 3 on remaining fixtures

Same arms, different fixture shapes. Look for **which items
consistently matter across shapes** — those are load-bearing. Items
that matter on one fixture but not another may be shape-dependent.

### Run trust-check round

Pick the best arm (likely Arm C) from the fixture that gave the
cleanest output. Feed its result into a fresh main-agent and score
handoff acceptance.

### Write contract decision

Per the criteria above. Commit the decision and the load-bearing
context bundle spec to `docs/experiments/analyze-subagent-pilot/contract.md`.

If decision-owning: draft the ANALYZE subagent prompt and bundle
composition, mirroring the shape of `soc-agent/skills/investigate/gather.md`.

If assessment-only: draft the shorter prompt + define the return
envelope the main agent consumes.

---

## File map

```
docs/experiments/analyze-subagent-pilot/
├── README.md                 # Short pointer to this skill
├── fixtures/
│   └── {fixture-id}/
│       ├── truncated-investigation.md
│       ├── lead-output.yaml
│       ├── ground-truth-analyze.md
│       ├── signature-context.md
│       └── notes.md
├── rounds/
│   └── round-{N}/
│       ├── arm-A.md
│       ├── arm-B.md
│       ├── arm-C.md
│       ├── arm-trust.md       # round-C only
│       └── comparison.md
└── contract.md                # written after all rounds; the locked decision
```

---

## Key files to read in a fresh session

Ordered by signal density:

1. **This skill file** — state, method, open questions.
2. **`soc-agent/skills/investigate/SKILL.md` §ANALYZE** — the phase under
   test; specifically lines 466–538 for rules and output contract.
3. **`docs/investigation-language.md` §Lead** — the invlang shape the
   subagent emits (`resolutions`, `severity_of_test`, etc.).
4. **Latest `rounds/round-{N}/comparison.md`** if any rounds have run.
5. **`contract.md`** if it exists — the locked decision.
