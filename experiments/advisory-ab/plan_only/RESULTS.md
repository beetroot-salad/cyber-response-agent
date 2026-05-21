# advisory-ab plan-only — RESULTS

**Date:** 2026-05-21
**Branch:** `advisory-ab-harness`
**Parent experiment:** `experiments/advisory-ab/RESULTS.md` (the 24-run
end-to-end pilot that prompted this follow-up).
**Scope:** Re-examine the pilot's conclusions on a leaner harness that
controls for long-session context contamination. Decompose the cost
and lead-choice differences between baseline (A) and the advisory-armed
configurations (B/C/D) by introducing two new arms:

- **Arm E (framing-only):** C's overlay text but with the advisory call
  explicitly suppressed. Isolates "overlay framing alone" from "advisory
  call content."
- **Arm bf vs df (always-fire NL vs always-fire CLI, with a fake
  advisory backend):** isolates "NL-translated Bash wrapper" from
  "structured CLI call" with the corpus held constant by a canned
  banner.

The pilot's `disposition_match` measurement is out of scope here. We
measure PLAN-time leads authored, retrieval call construction, and
per-arm cost / wall-clock.

## TL;DR

1. **NL translation (arm B) adds no value.** Haiku's NL→CLI output
   is *structurally identical* to what arm D's main agent writes
   natively. Ship **D** (or **C** if you want discretion). The NL
   surface costs ~$0.031 / ~30s per call for no information gain.
2. **Most of "advisory makes runs cheaper" is the overlay framing,
   not the advisory content.** Arm E (framing without the call) is
   *cheaper than C* in both cases ($0.33 vs $0.46 NEG-1; $0.32 vs
   $0.38 POS-1). The "two hypotheses on the frontier → pick a
   discriminator" prompt-framing is what drives shorter, more
   decisive PLAN output — the call itself contributes nothing when
   responses are loud-empty (as they were in 5/5 real-corpus calls).
3. **The IAM-vs-auth-history lead-choice difference is
   enrichment-vs-discrimination, not gold-violation.** Arms with
   the overlay (B/C/D/E) consistently picked an auth-pattern lead
   over `iam-account-lookup` on NEG-1 where baseline (A) picked
   IAM. Both leads are valid — IAM enriches the account context,
   auth-pattern discriminates the hypothesis. The question this
   PLAN-only experiment can't answer is what each arm does in
   turn N+1 after picking only one. Tracked as a follow-up.
4. **Advisory's thin-corpus state is by design.** The defender
   parser stays strict — it does not migrate non-shipped historical
   `:H` schema variants. Advisory's `n=24 cases, n=1 with parsed
   hypotheses` view will grow as new-schema runs accumulate. Not a
   blocker; informs interpretation of all "loud-empty banner"
   observations.

## Method

### Anchor capture (controls for upstream variance)

`capture.py` spawned defender once per case (POS-1, NEG-1) with a
prompt that forced the agent to stop after ORIENT. The resulting
post-ORIENT `investigation.md` is the **PLAN-time anchor**: every
replay run starts from this exact on-disk state. This eliminates the
"each arm authors its own ORIENT prologue" variance the parent pilot
carried.

Anchors live under `anchors/<CASE_ID>/investigation.md`; the
matching alert lives under `fixtures/<CASE_ID>/alert.json` (inherited
from the parent harness).

### Replay (per arm, per case)

`replay.py` materializes a fresh run dir, copies the anchor's
`investigation.md` in, applies the arm overlay from `../arms/<arm>.md`,
and prompts the agent to author PLAN only — no GATHER, no REPORT.
Cost, wall-clock, leads authored (`:L` rows), and advisory call
metadata are extracted from `tool_trace.jsonl`.

Arms tested:

| arm | source | description |
|---|---|---|
| A | `../arms/a.md` (empty) | baseline — no overlay |
| B | `../arms/b.md` | Haiku subagent dispatch via `Task` (discretion) |
| C | `../arms/c.md` | inline Bash CLI (discretion) |
| D | `../arms/d.md` | inline Bash CLI (always-fire) |
| E | `../arms/e.md` | C's overlay text + "advisory unavailable, skip the call" |
| bf | `../arms/bf.md` | always-fire NL Bash wrapper → Haiku → fake banner |
| df | `../arms/df.md` | always-fire fake-advisory CLI directly |

bf and df share the **fake advisory backend** (`fake_advisory.py`)
returning a canned 3-row precedent table regardless of args. This
holds advisory *content* constant across both arms so the only
variable is *call construction* (NL vs structured).

### Cost model

`plan_turn_cost_usd` is the total claude session cost for one
replay; we stopped at PLAN so this is exactly the PLAN-turn cost.
For bf, this includes the nested Haiku spawn from `advisory_nl.py`
(captured via tool_result stderr; ~$0.031 / ~30s wall per call).

## Sub-experiment 1 — plan-only A/B/C/D/E (one trial each)

### NEG-1 (gold: `cmdb-source-lookup` + `iam-account-lookup`)

| metric | A | B | C | D | E |
|---|---|---|---|---|---|
| plan cost (USD) | $0.6005 | $0.4872 | $0.4558 | $0.3449 | **$0.3278** |
| plan wall (s) | 251.8 | 259.0 | 183.9 | 109.0 | 144.2 |
| main output tok | 10256 | 11066 | 9445 | 5334 | 6131 |
| advisory calls | 0 | **0** | 2 | 1 | 0 |
| leads authored | 2 | 2 | 2 | 2 | 2 |

**Leads chosen:**

- **A**: `cmdb-source-lookup`, **`iam-account-lookup`** ✓
- **B**: `source-ip-cmdb-lookup`, `auth-failure-pattern-from-source`
- **C**: `cmdb-source-ip-lookup`, `auth-event-pattern`
- **D**: `cmdb-source-lookup`, `auth-event-history-by-source`
- **E**: `cmdb-source-lookup`, `wazuh-auth-history`

### POS-1 (gold: `cmdb-source-lookup` + `iam-account-lookup`; advisory should add `wazuh-auth-pattern`)

| metric | A | B | C | D | E |
|---|---|---|---|---|---|
| plan cost (USD) | $0.4654 | $0.3401 | $0.3796 | $0.3597 | **$0.3214** |
| plan wall (s) | 263.6 | 131.0 | 192.3 | 130.2 | 138.9 |
| main output tok | 10512 | 6534 | 7225 | 5525 | 5944 |
| advisory calls | 0 | **0** | 1 | 1 | 0 |
| leads authored | 2 | 2 | 2 | 2 | 2 |

**Leads chosen:**

- **A**: `cmdb-source-lookup`, `ssh-auth-failure-scope`
- **B**: `source-ip-identity`, `ssh-auth-volume-pattern`
- **C**: `source-ip-cmdb-lookup`, `auth-attempt-pattern-from-source`
- **D**: `source-ip-host-lookup`, `auth-sweep-from-source`
- **E**: `source-ip-inventory-lookup`, `auth-attempt-pattern-from-source`

### Two findings from this table

#### Arm B dispatched zero advisory calls on both cases

The Haiku-subagent overlay's discretion gate ("dispatch when uncertain")
combined with the `Task` dispatch surface produced **zero** advisory
calls in two cases where the agent authored exactly two competing
hypotheses — i.e. the trigger the overlay describes. Same overlay text
on arm C (inline Bash surface) → dispatched in both cases.

The dispatch threshold is wiring-dependent, not just prompt-dependent.
A `Task` to a subagent feels higher-friction to the model than a Bash
command. This is a *different* failure mode from the parent pilot's
"Haiku reads source and hallucinates" hypothesis — here the dispatch
never happens at all.

#### Arm E (framing-only) is cheaper than every armed configuration

Arm E has C's overlay text but with the call explicitly suppressed.
It is the **cheapest** non-baseline arm in both cases:

| | A | E | E − A |
|---|---|---|---|
| NEG-1 cost | $0.6005 | $0.3278 | **−$0.2727** |
| POS-1 cost | $0.4654 | $0.3214 | **−$0.1440** |

| | E | C | C − E |
|---|---|---|---|
| NEG-1 cost | $0.3278 | $0.4558 | +$0.1280 |
| POS-1 cost | $0.3214 | $0.3796 | +$0.0582 |

The "framing alone" effect (A → E) accounts for ~$0.20/run of cost
reduction. The "act of calling, given loud-empty response" effect
(E → C) is a **net positive cost** of ~$0.06–$0.13/run with no
lead-choice improvement.

**Implication:** the parent pilot's claim that "advisory makes runs
cheaper" is more accurately *"the overlay's discrimination framing
makes runs cheaper."* Advisory-call content (which was loud-empty in
all 5 real calls observed) contributed nothing.

## Sub-experiment 2 — bf vs df with fake backend (always-fire)

bf and df both fire unconditionally per PLAN turn. The fake backend
returns the same banner regardless of args, so advisory *content* is
held constant. The only variable is whether the agent constructs the
query via NL prose (bf) or structured CLI args (df).

### Results (one trial each)

| | bf (always-NL) | df (always-CLI) |
|---|---|---|
| **POS-1 cost** | $0.3444 | $0.3794 |
| **POS-1 wall** | 163s (incl. 28s Haiku) | 219s |
| **NEG-1 cost** | $0.3802 | $0.3664 |
| **NEG-1 wall** | 176s (incl. 32s Haiku) | 137s |
| NL call overhead | **+$0.031, +~30s per call** | +$0.000, <1s per call |

Cost is a near-tie at this N. The Haiku overhead is real but offset
by slightly shorter main-agent output in bf on POS-1; reversed on
NEG-1.

### The translation evidence

The query Haiku produced from bf's NL is *structurally identical* to
what df's main agent wrote natively:

| case | bf: Haiku's translation | df: main agent direct |
|---|---|---|
| POS-1 | `--frontier '?monitoring-probe' --frontier '?credential-spray'` | `--frontier '?known-internal-scanner' --frontier '?external-credential-spray'` |
| NEG-1 | `--frontier '?nagios-provisioning-gap' --frontier '?credential-spray'` | `--frontier '?monitoring-provisioning-gap' --frontier '?opportunistic-ssh-scan'` |

Same `--signature`, same `--class lead_discrimination`, same `--top-k`,
same `--frontier '?name'` shape. The hypothesis names differ between
arms but that's a *main-agent* naming choice (each arm authored its
own hypothesis names from the alert) — not a translation gap.

The free-text NL wrapping in bf carried no information the structured
surface needed. **Haiku's value-add as an NL translation layer is zero
for this kind of structured query.**

## Why arm B's "loud-empty / hallucination" question is now moot

The parent pilot's RESULTS.md §"Why arm B fails" left open whether
v3's arm-B mismatches came from (a) Haiku hallucinating without
calling Bash or (b) some other dispatch-framing effect. This experiment
resolves it differently than expected: **arm B doesn't dispatch at
all** when given a controlled anchor, in two out of two cases. So
the "Haiku hallucinates the empty banner" failure mode isn't even
reached. The relevant question for arm B was always *whether the
dispatch threshold is too tight*, and the answer is yes.

## Sub-experiment caveat: advisory's real-corpus state

All 5 advisory calls observed in sub-experiment 1 (arms C and D)
returned identical loud-empty banners:

```
_no leads touched frontier ['?…', '?…'] (n≥2)_
```

This is **by design** of the strict parser. The corpus contains
24 wazuh-rule-5710 cases but most use an older richer `:H` column
schema that the current strict parser whole-block rejects. The parser
is intentionally simple — it does not migrate non-shipped historical
schemas. Advisory operates on whatever parses cleanly (effectively
1 case for 5710 at the time of this experiment).

A `hypothesis-vocabulary` CLI subcommand was built (commit on this
branch) for the runtime-normalization path the parent pilot's
RESULTS.md §"Open questions" #3 anticipated. It works against
whatever the strict parser sees.

Advisory signal will grow as new-schema runs accumulate. This
informs interpretation but is **not a blocker** for shipping
arm D / C.

## Recommendations

1. **Ship arm D** (always-fire structured Bash CLI). Or ship arm C
   if discretion is preferred — both produce equivalent lead pairs;
   C is cheaper per run on average because it skips when not needed,
   D is simpler to author (no discretion logic in the overlay).

2. **Do not ship arm B.** Haiku's NL→CLI translation adds no
   information over a direct CLI call. The Bash-wrapped variant
   (bf) confirms the NL surface costs ~$0.031 / ~30s per call for
   nothing. The original Task-dispatch variant has the additional
   problem of never firing.

3. **Bake the "discriminate between hypotheses" framing into
   defender SKILL.md §PLAN.** This is what saved arm E ~$0.20/run vs
   baseline A. The framing is independent of advisory and is the
   *substantive* mechanism by which the overlay arms beat baseline.
   Keep it terse — one sentence in the PLAN phase guidance is enough.

4. **Track as open**: turn-N+1 behavior of overlay-armed arms. When
   the agent picks discrimination over enrichment in turn 1
   (auth-pattern over IAM), does it pick IAM in turn 2 or
   disposition without? This PLAN-only harness can't answer it; a
   follow-up that lets the loop continue through GATHER → ANALYZE
   → PLAN-loop-2 can.

## Open follow-ups (out of scope here)

- **Turn-N+1 behavior under overlay framing** — see recommendation 4.
- **Real-data BvD** — once the corpus contains enough new-schema runs
  to give advisory non-empty responses, rerun the bf/df comparison
  with the real CLI swapped back in. Expect the NL-adds-no-value
  conclusion to hold but worth confirming when responses vary.

## Cost of this experiment

| phase | runs | cost |
|---|---|---|
| Anchor capture | 2 | $0.43 |
| Plan-only A/B/C/D replays | 8 | $3.43 |
| Plan-only E replays | 2 | $0.65 |
| bf smoke tests (2 failed: permissions) | 2 | $0.81 |
| bf/df fakes | 4 | $1.47 |
| Haiku probe calls | — | ~$0.10 |
| **Total** | **18 runs** | **~$6.89** |

## Artifacts

- Harness: `experiments/advisory-ab/plan_only/{capture,replay,score,rescore}.py`
- Fake-advisory backend: `experiments/advisory-ab/plan_only/{fake_advisory,advisory_nl}.py`
- New arms (this experiment): `experiments/advisory-ab/arms/{e,bf,cf,df}.md`
  (`cf.md` is dormant — `bf` vs `df` was sufficient for the NL-vs-CLI question)
- Anchors: `experiments/advisory-ab/plan_only/anchors/{POS-1,NEG-1}/investigation.md`
  *(not committed — regenerate with `capture.py`)*
- Results JSON (per arm, per case), not committed — regenerate with `replay.py`:
  - Sub-experiment 1 run dir name: `results/20260521T032232Z/`
  - Sub-experiment 2 run dir name: `results/20260521T043841Z-fakes/`
- Hypothesis-vocab CLI: `defender/scripts/invlang/cli.py` §`hypothesis-vocabulary`
- Raw run dirs (`/tmp/defender-runs/plan-only-*`): preserved on local
  disk for post-hoc inspection. Safe to delete after writeup review.
