# `defender/evals/oracle_golden/` — oracle calibration golden set

The versioned evaluation suite for the telemetry **oracle** (issue #693). The
oracle is a learned simulator: the enterprise loop substitutes *actor story →
oracle projection* for executing an attack, so oracle error is a first-order
source of false learning (a mis-projection can manufacture an apparent evasion
or an apparent catch). This suite calibrates the oracle against operations that
**actually happened**, where the story, the query envelope, and the complete
observed telemetry are all known.

Motivating probe + method write-up: `experiments/oracle-telemetry-fidelity/`
(PR #707). This directory is the durable, reusable form of that probe.

## The one hard rule: hidden vs. oracle-visible

Each case splits its files so a projection **cannot** peek at the ground truth
it is scored against:

```
cases/<case-id>/
  manifest.yaml            # provenance, split, unit, lead_source, recorded projections
  oracle_visible/          # ← the ONLY thing a projection may read
    story.md               #   ground-truth story (the oracle's story input)
    leads.jsonl            #   per lead: {lead_id, goal, what_to_summarize, queries[{query_id, params}]}
    samples/<lead>.txt     #   the redacted sample skeleton the production oracle sees
  hidden/                  # ← the scoring target; never an oracle input. OBSERVED CASES ONLY
    observed/<lead>/<seq>.json   #   full observed query payloads (ground truth)
    controls/<lead>/<seq>.json   #   per-query baseline: the SAME query, bounds moved
    controls.yaml          #   provenance of that measurement (see below)
  environment.yaml         # facts that change how a cross-window difference reads —
                           #   an input to BOTH judge passes, not documentation
  expected.yaml            # OPTIONAL. Hand labels, kept only by the four seed cases;
                           #   the label pass's calibration set, not a scoring contract
  projections/<tag>.yaml   # oracle output for a given model/prompt (tag = <model>_effort-<e>)
  labels/<judge-tag>.json  # the label pass's measurement of hidden/ — projection-independent
  scores/<oracle>__<judge-tag>.json   # one projection graded against that measurement
```

`expected.yaml` is optional per case and that is the redesign, not an omission. It used
to hold the authoritative per-lead class, which made it the scoring contract — and every
defect the pilot campaign found was that contract being wrong. Ground truth is now the
telemetry itself: the judge's label pass measures what an envelope did, and the surviving
hand labels are what that pass is *calibrated against* (`audit_judge.py`). A recruited
case carries none, because inventing the answers is the thing the suite exists to avoid.

Two details the layout does not show:

- `leads.jsonl` stores `goal` for a human reader; `build_lead_user_prompt` does
  **not** pass it to the oracle (prompt.md: "You are NOT given the defender's
  prose goal"). Only `what_to_summarize`, the queries, and the sample reach the
  model. Do not add it to a replay path — that would diverge from production.
- A **zero-byte** `observed/<lead>/<seq>.json` is an **errored** query, not an
  empty result: `query_tool.py` writes `""` when `exit_code != 0`. Case-001's
  `l-004/0.json` (bad zeek field names) and `l-008/0.json` (identity 404, "user
  root not found") are both of these. The hidden tree does not carry the
  `payload_status` that says so — check the source run's `executed_queries.jsonl`.

**A story is an oracle input, so it may never state or justify the expected
result.** That is the one leak the file-level split cannot catch, because
`story.md` is deliberately visible. `test_no_story_states_the_expected_result`
pins it. Rationale goes in `manifest.yaml`, which the oracle never reads.

`replay.py` reads only `oracle_visible/`. `score.py` reads `hidden/` — it must, since
that is the `y` it grades against — and it is not the thing the boundary protects. The
boundary is structural, not a matter of discipline: `test_oracle_golden_693.py` pins that
no code literal in `replay.py` names the hidden tree, and the judge is invoked with an
empty tool allowlist from a neutral temp directory so it cannot reach the case tree by a
second route.

The derived kinds (negative-control, mutation) carry **no `hidden/`**: nothing
new was captured, so their ground truth is definitional rather than measured.
Every case carries a `manifest.yaml`, and a derived one records its `base_case`
and exactly what the derivation changed.

### Why a control-window baseline is stored

The oracle emits a **signed diff over baseline**, so "distinguishable event
(`present`)" vs "additive baseline noise (`indistinguishable`)" is undecidable from the
attack window alone. `hidden/controls.yaml` records the same query over
shape-matched control windows (e.g. the same clock window on prior weekends,
where the Poisson baseline generators produce a fair routine sample). A row is a
genuine `present` only if the attack window has it and every live control does not.

**Measure a control with the lead's own predicate.** A control taken on a broader
filter than the lead runs does not describe the lead's envelope, and the mismatch
is silent. Case-003 recorded "44 auth docs in the control window" measured over
*all* dev-ws-1 auth docs, while its lead filters `event.outcome IS NOT NULL`;
under that filter the control is **0**, there was no baseline for the suppression
to remove, and the `suppressed` reading it justified was wrong. Likewise, control a
`present` candidate on the **fields that distinguish it**, not on the rule that fired:
case-002's Falco rule has a routine ~hourly baseline (`config-mgmt-key-rotate`
rotates `svc.config-mgmt` keys and fires the same rule), so its three zero-count
windows only say the baseline action missed those windows.

## `delta_kind` — the stratification axis

The oracle emits telemetry, so the suite grades telemetry against telemetry (`y'` vs
`y`). The old four-way class is gone as a *contract*; it comes back as `delta_kind`, a
label the judge tags each lead with so the report can stratify. The difference is
load-bearing: a wrong class used to be a wrong score, and now it only moves a lead
between report slices.

| `delta_kind` | meaning | band |
|---|---|---|
| `present` | the activity writes rows these queries distinguish from baseline | active |
| `indistinguishable` | it lights the stream, but only with baseline-shaped rows in the fields these queries surface | active |
| `suppressed` | it **removes** a baseline this envelope was carrying — the stream goes dark | active |
| `absent` | an event stream the activity never touches (wrong system, window, or filter) | quiet |
| `state-only` | a lookup/state system: current configuration, no stream, no window to diff | quiet |
| `undecidable` | the telemetry does not settle it — an abstention, never a score | — |

**The report headlines the active band.** On the seed data 27 of 36 dev leads were
`quiet`, so a single pooled number was three-quarters correctly-said-nothing. Both bands
are printed and neither is pooled into a headline.

## Scoring (`score.py`) — mechanical checks first, then two judge passes

Three things run **in code**, before any model call:

1. **Lead-set integrity** — leads the case has but the projection omits, leads it
   projects that the case does not have, repeated `lead_id`s. Any mismatch reports,
   scores nothing, and exits non-zero: a truncated projection is not a result, and
   without this it scores perfectly against an all-quiet case.
2. **Grammar** — the oracle's output grammar is closed (event mappings, or exactly one
   of the two marker strings, never mixed). Out-of-grammar output is `C-MALFORMED`,
   decided deterministically. case-005 `l-002` emitted a prose paragraph whose *content*
   was correct; a judge asked to grade that would be tempted to be generous.
3. **Leak check** — for a mutation case, the pre-mutation entities must appear nowhere
   in the projection. Matched against whole emitted values and their
   whitespace-delimited tokens, never as bare substrings: `/root/.ssh/authorized_keys`
   is case-002's real output and must not read as a leak of the user `root`.

Then the judge (`judge.py`, `prompts/`), in two separate calls:

- the **label pass** reads the telemetry alone — never the story, never the projection —
  and returns the `delta_kind` this envelope actually carried, plus its evidence;
- the **verdict pass** grades the projection against that measurement and returns
  `faithful: true | false | null`, a `cause` when false, and a rationale.

The split is what keeps the measurement honest: merging the passes would let a confident
projection colour the reading of the telemetry, and the label pass's calibration set
(hand labels, none derived with a projection in view) would stop being like-for-like.

A lead the label pass calls `undecidable` **never reaches the verdict pass** — there is
nothing to grade against. It is recorded with `faithful: null`, excluded from every
denominator, and counted in the per-slice abstention tally. A slice that abstains at
least as often as it decides is reported as *not a measurement*, not as a rate.

The label pass is a function of (case, lead) and nothing else, so it is cached per case
in `labels/<judge-tag>.json`. Two oracle tags are then graded against **one** measurement
rather than two independent readings of the same telemetry, and a re-score costs only the
verdict pass. Editing either prompt changes the judge tag and invalidates the cache by
construction.

**Derived cases never reach the judge.** A mutation or negative-control case reuses its
base's envelopes and changes only the story, so the story it tells was never fired and no
telemetry exists for it — there is no `y`. They are scored by the mechanical checks alone,
contribute no judged rows, and the roll-up names them rather than dropping them silently.

## Case kinds

- **observed** — a real captured operation (the core: story + hidden telemetry).
- **negative-control** — an *unrelated* story shown to another case's leads;
  ground truth is all-`0`. Detects a projection copied from the query
  window/salience rather than caused by the story. Needs **no env** — it reuses
  captured leads and only re-runs the oracle.
- **mutation** — a captured case with one causal action/entity removed or
  altered; the projection must change accordingly (drop the events, or move a
  field). Also **no env** — a story edit + an oracle re-run. Scored by the mechanical
  checks only: the mutated story was never fired, so no telemetry exists to grade it
  against.
- **spec-probe** — a story written so that `oracle/prompt.md` already settles the
  correct handling, over another case's envelopes. **No env, no telemetry, no judge**,
  and that is the point rather than a limitation.

### Spec probes — the axis that needs no ground truth

Every observed case measures **retrodiction**: given a story describing an operation that
really ran, does the oracle reproduce the telemetry that was really captured? Production
asks for something else — the actor synthesizes an attack that was **never executed** and
the oracle projects what it *would* have written. That quantity has no ground truth, which
is exactly why this suite grades the proxy instead.

A spec probe attacks the gap from the other side. `oracle/prompt.md` is a specification,
and much of it is decidable **from the story alone**: an unrelated story touches nothing,
suppression is earned by an explicit blinding action, a value the story never states must
stay a placeholder, an event outside a query's filter does not surface in it. Write a
story that puts one of those rules under load and the correct answer is knowable without
capturing anything. A probe costs one oracle replay and no judge call.

`expectation:` in the manifest is that rule made executable. `score.py` **fails the score
and exits non-zero** on a violation:

| clause | asserts |
|---|---|
| `empty_leads` | `all`, or a list — the activity touches none of these envelopes |
| `no_suppression` | no `<suppressed: …>` marker; the story blinds nothing |
| `must_emit` | values the story states that the projection must carry |
| `must_not_emit` | values it must not — a mutation's originals, or a withdrawn entity |

**This existed only as prose until 2026-07-27, and the gap was real.** A forged `neg-001`
projection copying the base case's brute-force burst into all nine of its leads — the
precise window-copying that case exists to catch — scored **clean and exited 0**. Its
`class: "0"` rows live in `expected.yaml`, and the judge redesign had moved the contract
to *the judge's measurement of the telemetry*; a derived case has no telemetry, so the
judge never runs and nothing was left checking. `validate_cases.py` now fails any derived
case that declares no `expectation:`, because a derived case that asserts nothing passes
no matter what the oracle emits.

### `lead_source` — where the envelope came from

Orthogonal to case kind, and recorded per case in `manifest.yaml`:

| `lead_source` | meaning |
|---|---|
| *(absent)* | the leads are a real `defender/run.py` gather, captured by `build_case.py` (case-001 only) |
| `authored` | the lead envelopes were hand-written for a realistic investigation surface (case-002/003/004) |
| `inherited from <case>` | a derived case reusing another case's envelopes byte-for-byte |

This matters because the calibration premise is *the envelope production gather
actually issues*. An authored envelope is still scored against real captured
telemetry — the observed payloads under `hidden/` are genuine — but the choice of
what to query was the case author's, not the runtime's, so it can make a case
easier or harder than the live surface. Cases 002–004 are authored because no
catalog scenario covered the activity; each manifest says so and why. Treat
`lead_source` as a stratification axis once enough cases accumulate to support
one.

## Tools

```bash
# Capture an observed case from a defender run + ground-truth story + controls.
# The out dir's NAME is the case id — there is no separate id argument to drift
# from it. Re-capturing clears oracle_visible/samples/ and hidden/observed/ so a
# lead dropped since the last capture leaves no stale file behind; hand-authored
# siblings (manifest.yaml, environment.yaml, projections/, scores/) are untouched.
python3 defender/evals/oracle_golden/build_case.py \
    <run_dir> <story.md> <controls.yaml> cases/<case_id>

# Re-run the production oracle over a case (reads ONLY oracle_visible/):
python3 defender/evals/oracle_golden/replay.py cases/<case_id> [--tag <model>_effort-<e>]

# Score a projection. Writes cases/<case_id>/scores/<oracle-tag>__<judge-tag>.json.
# Exits non-zero on a lead-set mismatch — a partial projection is not a result.
# --dry-run runs the mechanical checks only and calls no model.
python3 defender/evals/oracle_golden/score.py cases/<case_id> \
    cases/<case_id>/projections/<tag>.yaml [--jobs 4] [--relabel] [--dry-run]

# Roll every case's scores up per tag, split dev / held-out, never pooled.
python3 defender/evals/oracle_golden/report.py [--tag <tag>] [--target-lower-bound 0.90]

# Calibrate the label pass against the hand labels + measure its own noise floor.
python3 defender/evals/oracle_golden/audit_judge.py --repeats 5 --out audits/<name>.json

# Append a held-out result. Refuses a second entry per (case, tag), and refuses any
# score whose tag does not name the judge recorded inside it.
python3 defender/evals/oracle_golden/record_held_out.py cases/<case_id> <tag>
```

`replay.py` drives the exact production seam (`invoke_oracle_lead` →
`_run_oracle_pydantic`), so a projection is production-identical; only its input
source (the case's `oracle_visible/`) differs.

**`score.py` is not deterministic, and that is the cost of this design.** The judge runs
at score time, so it is part of the tag:

```
<oracle-model>_<oracle-effort>[_<oracle-prompt>]__judge-<judge-model>-<effort>_<sha8 over BOTH prompts>
```

Three consequences, all enforced rather than documented:

- Editing either prompt is a **new tag requiring a full re-score**, exactly like an
  oracle change. `test_every_checked_in_score_names_the_judge_in_its_tag` fails every
  committed score the moment a prompt's bytes change.
- The tag records the **resolved** judge, read back from the runner, never the
  configured default — `JUDGE_MODEL`/`JUDGE_EFFORT` have fallbacks, so two machines
  could otherwise mint identically-named tags from different judges.
- **The artifact is the verdict, not the number.** `faithful`, `cause`, `rationale` and
  the label pass's `evidence` are committed per lead. A verdict you cannot read is not
  evidence.

The judge is `claude-opus-5` at effort `high`, deliberately **not** the oracle's own
`glm-5.2`: a same-lineage judge shares the failure modes the suite exists to catch
(inferring suppression from absence, accepting a plausible-shaped event the telemetry
does not carry). It is reached through `claude -p` with an empty tool allowlist, an
explicit denylist, `--strict-mcp-config`, a neutral temp working directory, and
`ANTHROPIC_API_KEY` stripped from the child environment.

## Capturing a new observed case (needs the env)

> **Only against `playground-v2`.** `build_case.py` performs no scrubbing: every
> observed payload is committed verbatim under `hidden/`. That is correct for a
> synthetic stack and only for one — never point the capture path at a run over
> real telemetry.

1. Lever up `playground-v2` (`infra/bin/up.sh`) and install detection rules.
2. Fire a catalog attack (`playground-v2/attacks/runner.py run <scenario>`); the
   per-run metadata record it writes under `runs/<id>/` is the ground truth.
3. When the rule fires, project the alert to fixture shape and run
   `defender/run.py <alert.json> --run-id <slug> --no-learn`.
4. Author `story.md` from that record — state **only what happened** (an invented
   step makes the oracle "wrong" for a story reason), and **nothing about the
   evaluation**: no result class, no "a faithful oracle would…", no mention of
   controls or leads. The story is an oracle input.
5. Measure the control windows **with each lead's own query predicate**, and on the
   field that distinguishes the event rather than on the rule/stream that carries it;
   write `controls.yaml`. `controls.py` records `window_live` per control, and a window
   where the stack was not running is **not** an empty baseline — the judge is required
   to abstain on it rather than read absence into it. Record counts per distinct ingest
   (see the re-ingest hazard above).
6. `build_case.py` to assemble the case; write `manifest.yaml` (split, unit,
   `capture_environment`, `lead_source`) and `environment.yaml` from the capture. Do
   **not** author labels: the label pass measures `hidden/` at score time, and inventing
   the answers is the thing this redesign exists to avoid. `generate_case.py` does all
   of this end to end.

A **derived** case declares its mutation in `must_not_emit` (its manifest, or
`expected.yaml` where a seed case already keeps it). Re-read every query predicate when
authoring one: changing an entity that appears in a *filter* moves the activity out of
the envelope entirely, not just out of a field.

## Trust / abstention resolver (policy)

Calibration exists to gate learning. A **slice** = (system × `delta_kind`). `report.py`
certifies each one against a stated lower bound, computed at the **unit** count rather
than the lead count, and refuses to publish an interval below `MIN_UNITS = 3`:

- **trusted** — the Wilson lower bound at `n_units` clears the target;
- **no-update** — it does not, and the report says how many more units it would take (or
  that the bound is unreachable at the observed rate, so recruiting cannot fix it);
- **insufficient** — below the unit floor; a point estimate is not published at all;
- **not-a-measurement** — the judge abstained at least as often as it decided. A rate
  over one decided lead beside two abstentions is arithmetic, not evidence.

A judge abstention is **never charged to the oracle**: `faithful: null` is excluded from
every denominator and counted beside the rate. Any score whose `missing_leads` /
`unscored_leads` / `duplicate_leads` is non-empty is not a measurement at all and must
not feed the resolver.

Downstream contract (to be wired into the loop as follow-up): the learning loop
**must not** apply a positive/negative lesson-score update when the oracle slice
the judgment depended on is `no-update`. Model-reported confidence is **not**
calibration and must not substitute for a trusted slice.

## Current coverage

Scored 2026-07-27 under judge tag `judge-claude-opus-5-high_47d6044a`. Every slice is
`insufficient` or `no-update` at the unit floor — these are the *first* measurements
under this design, not a certification. `report.py` prints the full breakdown.

| split | oracle tag | active | quiet | abstained | units |
|---|---|---|---|---|---|
| dev | `glm-5.2_effort-none` | **4/7** | 9/10 | 1 | 4 |
| dev | `glm-5.2_effort-none_prompt-711` | **8/13** | 18/19 | 4 | 6 |
| held-out | `glm-5.2_effort-none_prompt-711` | **9/17** | 8/8 | 1 | 3 |

The active band is the headline and the quiet band is reported beside it, never pooled
into one number. Only the `_prompt-711` tag carries the three units recruited on
2026-07-27 (case-011/012/013); the older tag is still the 4-unit seed set, which is why
its denominators are smaller.

**Held-out cleared the unit floor on 2026-07-27** when case-008 and case-010 — captured
2026-07-26 and held unscored since — were replayed and scored, taking it from 1 unit to
3. Its active band publishes an interval for the first time: **0.53 [0.21, 0.94]**, and
`elastic x present` is **0.54 [0.21, 0.94] over 3 units** beside dev's 0.71 [0.30, 0.95]
over 4. Read the change to the *story* before the change to the number: on one unit
held-out read 2/8, which is the evidence §Status called "the first evidence for what #711
suspected". Across three it reads 0.53 against dev's 0.61, and the gap is inside one
lead of the judge's own noise floor. **case-005 was an outlier, not a trend** — and the
two cases that show it were assigned held-out by the generator before any replay, so
neither the split nor the order of scoring was chosen after seeing a result.

`C-MISSED-DELTA` is the leading cause on both sides and is now **4 instances across 3
units** on held-out — meeting the unit half of the ≥5-across-≥3-units bar that makes a
cause *established*, and one instance short of the other half. It is the cause to watch.

**The judge's own noise floor is one lead** (`audits/verdict-selfagreement_*`, 0.988
self-agreement over 5 repeats). Against a 13-lead active band that is ~8 points, so a
prompt change has to move 2 leads before it is distinguishable from the judge re-running
on an unchanged projection. That measurement was taken on the 17 seed-case leads; the
rate is assumed to carry to the new units rather than re-measured.

Two findings survive the architecture change and are worth naming, because the new
measurement re-derived them from telemetry rather than inheriting them from the labels:

- **case-002 `l-001` is `C-FABRICATED-VALUE`** — the projection emits `evt.type: write`
  where the captured Falco row says `openat`. The old volunteered-value check found the
  same thing from a hand-authored `observed_fields`; the judge found it by reading the
  payload.
- **case-003 `l-001` is `C-SUPPRESS-UNBASELINED`** — a `<suppressed: …>` marker over an
  envelope whose own baseline is empty. Suppression earned from the *story* is not
  suppression visible in the *envelope*, and only the second is ground truth.

`case-003 l-003` is the set's single abstention (`insufficient-baseline`), and it is the
same lead the label-pass calibration abstained on. It is adjudicated by **re-measurement**
on a lever-up against snapshot `412421678` — never by tuning the prompt until it decides.

**`delta_kind` coverage** over the 62 labelled leads — `state-only` 25, `present` 24,
`undecidable` 5, `indistinguishable` 4, `suppressed` 2, `absent` 2. All five deciding
kinds are exercised, but the distribution is the thing to read: the active band is 77%
`present`, and the two kinds that actually gate learning — `indistinguishable` (do not
manufacture a catch out of routine traffic) and `suppressed` (do not read absence as a
detection) — carry 4 and 2 leads. One of the two `suppressed` leads is the set's chronic
abstention. **Those are the least-sampled cells and the most consequential ones**, so
recruitment should target them rather than another brute-force unit.

Every case that can be replayed now has been: the only two without a projection are
case-006 and case-007, which are `defective:` and unscoreable. Still pending: a
suppression capture on a stream with a measured non-zero baseline in its own envelope;
routine **benign** observed cases; more mutation entities; and wiring the trust resolver
into lesson scoring.

### What the spec probes found (2026-07-27, `glm-5.2_effort-none_prompt-711`)

Six probes over case-001's envelopes, one oracle replay each, no judge, no capture:

| probe | rule under test | result |
|---|---|---|
| `probe-001-unearned-suppression` | suppression is earned by an explicit story action | **pass** |
| `probe-002-causal-step-removed` | stay inside the envelope | **fail** — `l-006` |
| `probe-003-ungrounded-entities` | ground every value in the story | **pass** |
| `probe-004-suppression-without-baseline` | suppression *also* requires a baseline to remove | **pass** |
| `probe-005-unsatisfiable-summary` | `what_to_summarize` guides completeness, not invention | **fail** — `l-001` |
| `probe-006-window-bound-timestamps` | a timestamp never comes from a query's window bound | **pass** |

#### Both failures are the same marker, used in opposite directions

`<standard environment noise>` means *the activity lights this envelope and only looks
routine*. It is the oracle's fallback whenever the envelope is hard to reason about, and
it is wrong at both ends:

- **probe-002 `l-006`** — the activity is **outside** the envelope (destination `web-2`,
  filter `host.name == "canary-1"`). Emitting the marker asserts presence where there is
  none. Manufactures a **catch**.
- **probe-005 `l-001`** — the activity is **inside** the envelope and distinguishable.
  Emitting the marker denies a delta that is really there. Manufactures an **evasion**.

The README's opening names exactly these two as the reason the suite exists: *"a
mis-projection can manufacture an apparent evasion or an apparent catch."* One marker,
reached for under uncertainty, produces both.

**probe-005 is the sharper of the two.** Its story is case-001's **byte-for-byte** and its
queries are identical; only `what_to_summarize` differs, by two added items presupposing a
successful login the story explicitly denies. case-001's `l-001` projects the failed-auth
events and the judge measured that envelope over real telemetry as `present` / `faithful:
true`. Adding a salience hint — which `prompt.md` calls "**NOT** an assertion that any
particular event occurred" — collapsed a verified catch into an apparent evasion. The
defender's leads are written by a runtime agent pursuing a hypothesis, so they routinely
presuppose what they are trying to confirm; this is production's ordinary condition, not
a contrived one.

#### The passes are informative too

**probe-004** is the one worth reading. Its story performs a textbook blinding action
(`pkill -TERM elastic-agent` on `canary-1`) on the very host the leads investigate, so
everything invites the suppression marker. The oracle refused it on all five state and
lookup leads — correct, since stopping a log shipper removes nothing from a CMDB record or
an identity authorization — and it even spared `l-004`, whose zeek data is not shipped by
the stopped agent. That is a real distinction, drawn correctly.

What it did **not** do is distinguish among the canary-shipped elastic leads: `l-001`,
`l-002` and `l-006` are all marked suppressed identically. `l-006` is narrowed to a single
source address, which is the "filter narrow enough that it rarely matches" that
`prompt.md`'s second suppression clause is about. Nothing here fails — whether that
envelope had a baseline is a measured property this file may not assert — but it is
evidence that the oracle applies the *action* test and not the *baseline* test, which is
the open mechanism behind `C-SUPPRESS-UNBASELINED` and its null-result prompt fix.

**probe-002 is the finding, and it is a new failure mode.** The story is case-001's
operation with one token moved: the target is `web-2`, not `canary-1`. Same actor, same
source host, same account, same password list, same burst structure, same clock window —
so every salience cue still points at "brute force, now, these leads". `l-006` filters
`host.name == "canary-1"` **and** `source.ip == "172.18.0.15"`. The source matches; the
destination cannot. The oracle emitted `<standard environment noise>`.

That marker means *the activity lights this envelope and only looks routine*. The activity
cannot light it at all. So this is a **partial entity match read as presence** — the mirror
of `C-SUPPRESS-UNBASELINED`: that one asserts absence-as-signal, this asserts
presence-as-noise, and both manufacture a delta the envelope cannot carry.

`l-004` in the same projection is the control that makes it a finding rather than a
mood: it is source-scoped (`source.ip == "172.18.0.15"`, no destination filter), the
activity genuinely falls inside it, and the projection tracked the retarget correctly —
`destination.ip: 172.18.0.22` (web-2), **zero** occurrences of canary-1's `172.18.0.9`,
volatile fields placeholdered. The oracle read that envelope's predicate correctly and
`l-006`'s incorrectly, in one document.

**One probe was wrong and the oracle was right**, which is worth recording because the
artifact is what settled it. `probe-003` originally asserted that no value anywhere be
concrete. The oracle placeholdered both withdrawn entities (`<attacker-workstation-ip>`,
`<target-account>`) and recovered neither from the query predicates that carry them —
correct — while keeping `host.name: canary-1` and `event.outcome: failure` concrete, both
of which its story states outright. `prompt.md` says to placeholder what the story does
*not* state; the clause was reading a rule that is not there. `placeholder_only` was
removed from the vocabulary rather than narrowed, and the contract is now value-specific.

### Notes surfaced by these cases

- **Projections track the story, not the window:** `neg-001` (unrelated story →
  all-`0`) and `mut-001` (mutated entities → emitted verbatim, originals never
  leaked) both hold. neg-001 holds *after* the answer was removed from its story:
  the de-leaked replay is the recorded projection.
- **`indistinguishable` is the strongest case in the set.** case-004's is fully
  earned: `sre-multihop-ssh` is a scheduled baseline action (jump-box →
  `trust_edges_out`, which includes db-1, as `sre.*`, running `uptime && df -h /`),
  sre.alice→db-1 accepted logins are dense across the whole corpus and in the same
  clock hour on prior days, and the captured aggregate row folds in a genuine
  concurrent baseline login alongside the four generated ones. An accepted login
  by a real SRE account on its routine path must NOT read as a catch, and it does
  not.
- **The oracle over-suppresses when the story says "the host goes dark".** In
  case-003 the story performs an explicit blinding action, and the oracle emitted
  `<suppressed: …>` for both dev-ws-1 leads. For `l-002` that is right; for `l-001` the
  envelope had no baseline to remove, so it is a false suppression — the error
  error that turns ordinary silence into a detection (`C-SUPPRESS-UNBASELINED`).
  Suppression earned from the
  *story* is not the same as suppression visible in the *envelope*, and only the
  second is ground truth.
- **Stopping a shipper delays telemetry; it does not remove it.** dev-ws-1's
  in-window auth lines were ingested at 09:47:04, right after the agent restarted,
  with their original timestamps — so the same query run three minutes later
  returns them. Only telemetry the agent *generates* (`elastic_agent*`) is
  permanently gone. A durable `suppressed` capture needs a stream of that kind, or an
  action that destroys data at source (clearing the log, disabling auditd). Until
  then, a `suppressed` ground truth is a claim about the moment of capture.
- **A mutation must be re-derived, not inherited.** mut-001's labels were copied
  from case-001 and swapped field values, missing that the mutation moves two
  leads outside their query filters entirely. Whenever a mutation changes an
  entity that appears in a query *predicate*, expect the lead to leave its envelope
  altogether, not just to change a field.

### Environment hazards that reach the ground truth

The stack is levered up and down between snapshots, and two of its properties
leak into captured telemetry. Both were confirmed on 2026-07-25.

- **Re-ingest duplication.** Every lever-up re-ships each host's on-disk logs, so
  a doc is re-indexed once per restore and any raw count is multiplied by the
  number of restores since the event. case-001's attack window appears three
  times over (ingested 07:00, 09:00, 11:00). No current label depends on a count
  — but grading counts would be measuring the lever cycle. (case-001's `96` is
  *not* a duplicate: it is 48 attempts × 2 sshd log lines.)
- **IP identity rotates.** Container addresses are assigned in start order, so the
  same address is a different host after a restore: `172.18.0.15` was db-1 through
  2026-07-13 and office-ws-1 from ~07-17. IP-scoped envelopes therefore mix hosts
  — which is why case-001's defender run looked up **db-1** in CMDB and asked
  change-mgmt about brute-force testing "from db-1". Label from `host.name`, and
  treat historical rows in an IP-scoped payload as unattributed.

### The exemplar channel is empty everywhere

Every case's `samples/<lead>.txt` reads `(no schema sample available for this
lead)`, and that is **production-faithful, not a gap in the cases**:
`redact_exemplar` looks for a `### Raw Sample Events` markdown header, and
`query_tool.py` writes raw JSON payloads that never carry one, so
`lead_sample_text` returns the placeholder for every lead of every playground-v2
run — confirmed in the #707 probe's own request trace. The seed README asked for
"a doc-returning case" to exercise the channel; case-002 already is one
(`KEEP … SORT`) and still has no exemplar. Exercising it needs a payload-format
change, not another case.

- **One recorded projection predates the harness:** case-001's
  `glm-5.2_effort-none` was produced by the #707 probe driving the production
  path directly, not by `replay.py` (its manifest flags
  `reproducible_by_replay_py: false`). Same seam, same oracle-visible inputs, so
  it is comparable — but it is the one tag the documented command will not
  re-derive. Every other tag came from `replay.py`.

Reports are keyed by projection tag (`<model>_effort-<effort>`) so results stay
versioned by oracle model + prompt.
