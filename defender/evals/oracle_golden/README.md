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

**This README is the format reference — file layout, tools, current coverage.
The procedure that produces and verifies a case lives in
`defender/docs/oracle-calibration.md`**: how to capture, how to measure a control
so the class is right, how to derive a mutation without inheriting its labels,
how to read a score, and how the result gates learning.

## The one hard rule: hidden vs. oracle-visible

Each case splits its files so a projection **cannot** peek at the ground truth
it is scored against:

```
cases/<case-id>/
  manifest.yaml            # provenance, split, unit, capture_environment, state_classes
  oracle_visible/          # ← the ONLY thing a projection may read
    story.md               #   ground-truth story (the oracle's story input)
    leads.jsonl            #   per lead: {lead_id, goal, what_to_summarize, queries[{query_id, params}]}
    samples/<lead>.txt     #   the redacted sample skeleton the production oracle sees
  hidden/                  # ← the scoring target; never an oracle input. OBSERVED CASES ONLY
    observed/<lead>/<seq>.json   #   full observed query payloads (ground truth)
    controls/<lead>/<seq>.json   #   PER-QUERY controls: the lead's own query, bounds moved
    controls.yaml          #   the capture session's control notes / provenance
  expected.yaml            # authoritative labels: per-lead 4-way class + key fields
  projections/<tag>.yaml   # oracle output for a given model/prompt (tag = <model>_effort-<e>)
  scores/<tag>.json        # scored dimensions for that projection
  scores/<tag>.causes.yaml # cause code per lead the score reports an error on
held_out_ledger.yaml       # append-only: sha256 of every held-out score, once per (case, tag)
```

`manifest.yaml` carries the three fields the reporter reads (#711):

| field | why |
|---|---|
| `split: dev \| held-out` | case-level; a derived case inherits its base's |
| `unit: {activity_family, host_pair}` | the independent unit the interval is computed at; seeds pool within it |
| `capture_environment` | two cases from one restored snapshot are ONE environment |
| `state_classes` | declared class per state/lookup system — undeclared is `needs-label`, never `0` |

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
pins it. Rationale goes in `expected.yaml` / `manifest.yaml`, which the oracle
never reads.

`replay.py` reads only `oracle_visible/`; `score.py` reads `expected.yaml` (which
was authored from `hidden/`) and never `hidden/` itself. The boundary is
structural, not a matter of discipline — `test_oracle_golden_693.py` pins that
no code literal in `replay.py` names the hidden tree.

The derived kinds (negative-control, mutation) carry **no `hidden/`**: nothing
new was captured, so their ground truth is definitional rather than measured.
Every case carries a `manifest.yaml`, and a derived one records its `base_case`
and exactly what the derivation changed.

### Why a control-window baseline is stored

The oracle emits a **signed diff over baseline**, so "distinguishable event
(`+event`)" vs "additive baseline noise (`+noise`)" is undecidable from the
attack window alone. `hidden/controls.yaml` records the same query over
shape-matched control windows (e.g. the same clock window on prior weekends,
where the Poisson baseline generators produce a fair routine sample). A row is a
genuine `+event` only if the attack window has it and every control does not.

**Measure a control with the lead's own predicate.** A control taken on a broader
filter than the lead runs does not describe the lead's envelope, and the mismatch
is silent. Case-003 recorded "44 auth docs in the control window" measured over
*all* dev-ws-1 auth docs, while its lead filters `event.outcome IS NOT NULL`;
under that filter the control is **0**, there was no baseline for the suppression
to remove, and the `-noise` label it justified was wrong. Likewise, control a
`+event` on the **fields that distinguish it**, not on the rule that fired:
case-002's Falco rule has a routine ~hourly baseline (`config-mgmt-key-rotate`
rotates `svc.config-mgmt` keys and fires the same rule), so its three zero-count
windows only say the baseline action missed those windows.

## The four result classes (the oracle's own vocabulary)

| class | meaning |
|---|---|
| `+event` | a distinguishable event the activity writes (attacker src, off-baseline dest, …) |
| `+noise` | activity lights the stream but only with baseline-shape events — net observable delta 0 |
| `-noise` | activity **removes** the baseline stream (kills the sensor, clears the log) — goes dark |
| `0` | the activity never touches this lead (wrong system/window/filter, or a state/lookup query) |

## Scoring dimensions (`score.py`) — not one accuracy number

- **four-way class agreement**, stratified **by system** (and extensible to
  template / activity-family as cases accumulate);
- **field/value grounding** on `+event` leads (`expected.yaml: fields`): `correct`
  / `wrong` / `unknown` (emitted only as a `<placeholder>`) / `missing`. `wrong`
  is the dangerous error; placeholders are *never* `wrong` — the prompt mandates
  them for values the story does not state;
- **the volunteered-value check** (`expected.yaml: observed_fields`): ground truth
  for fields the labels do *not* require, graded **only** where the projection
  emitted a concrete value for that key — never `missing`, never `unknown`.
  `fields` asks "did you commit to the distinguishing values?"; this asks the
  separate question "is anything else you made up refuted by the capture?".
  Without it, grading is confined to the fields the author chose and a projection
  invents refuted values for free: case-002 emits `evt.type: write` where the
  capture says `openat`, and mut-001 emits an alert row (`alerts: 1`) for a rule
  its story never fires. Both used to score a clean `0 wrong`. Contradictions
  count into `wrong_concrete_fields` — the grade that gates a slice;
- **occurrence precision/recall**: `+event` recall (emitted where expected) and
  `0` precision (stayed empty where expected). A case with no lead of that class
  reports `null`, **never `0.0`** — the resolver below aggregates these slices,
  and "unexercised" must not read as "worst possible";
- **false suppression**: any `-noise` predicted where the stream is actually
  alive — the error that turns ordinary silence into a false detection;
- **malformed**: events outside the oracle's closed grammar (an unrecognized
  marker string, or a marker mixed with event mappings). Counted as a
  disagreement, never folded into a real class — otherwise a degraded model
  emitting prose scores as a clean `+noise`;
- **lead-set integrity**: leads the labels cover but the projection omits
  (`missing_leads`), leads it projects that the labels do not cover
  (`unscored_leads`), and repeated `lead_id`s. A missing lead is scored
  `missing`, **not** the empty `0` it would otherwise impersonate, and any
  mismatch exits non-zero — without this, a projection truncated to one lead
  scores a perfect 9/9 against the all-`0` negative control.

Score is per-query/per-lead against the **envelope truth** in `expected.yaml`
(what the queries physically surface). A lead's stated *intent* is recorded to
*explain* divergence (an intent-scoped `[]`), never to excuse it.

## Case kinds

- **observed** — a real captured operation (the core: story + hidden telemetry).
- **negative-control** — an *unrelated* story shown to another case's leads;
  ground truth is all-`0`. Detects a projection copied from the query
  window/salience rather than caused by the story. Needs **no env** — it reuses
  captured leads and only re-runs the oracle.
- **mutation** — a captured case with one causal action/entity removed or
  altered; the projection must change accordingly (drop the `+event`, or move a
  field). Also **no env** — a story edit + an oracle re-run.

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
# siblings (expected.yaml, manifest.yaml, projections/, scores/) are untouched.
python3 defender/evals/oracle_golden/build_case.py \
    <run_dir> <story.md> <controls.yaml> cases/<case_id>

# Re-run the production oracle over a case (reads ONLY oracle_visible/):
python3 defender/evals/oracle_golden/replay.py cases/<case_id> [--tag <model>_effort-<e>]

# Score a projection against the case's labels, emit the dimensions.
# Exits non-zero on a lead-set mismatch — a partial projection is not a result.
python3 defender/evals/oracle_golden/score.py cases/<case_id> \
    cases/<case_id>/projections/<tag>.yaml --json cases/<case_id>/scores/<tag>.json

# ---- #711 ------------------------------------------------------------------

# Generate a whole case against the LIVE stack: fire -> capture -> investigate ->
# story -> assemble -> controls. `--split` is set BEFORE the first replay, which
# is what makes held-out honest.
python3 defender/evals/oracle_golden/generate_case.py \
    --scenario <id> --case-id cases/<case_id> --split held-out \
    --activity-family <family> [--target <host>] [--user <identity>]

# Measure per-query controls for an existing case: each control IS the lead's own
# query with only its two @timestamp bounds moved.
python3 defender/evals/oracle_golden/controls.py cases/<case_id>

# Calibrate the LABELER against the hand-derived labels before trusting it.
# Non-zero on a class divergence — which is resolved by re-measuring the
# environment, never by adjusting the labeler until it agrees.
python3 defender/evals/oracle_golden/audit_labels.py

# Lint the case tree: split present and inherited, heterogeneous matching the
# envelope, cause sidecars covering exactly the reported errors, held-out scores
# matching their ledger hashes, no story leaking the answer. Non-zero on any.
python3 defender/evals/oracle_golden/validate_cases.py

# Roll up: intervals at n_units, dev and held-out kept apart, `insufficient`
# below the unit floor.
python3 defender/evals/oracle_golden/report.py [--target-lower-bound 0.90]
```

`replay.py` drives the exact production seam (`invoke_oracle_lead` →
`_run_oracle_pydantic`), so a projection is production-identical; only its input
source (the case's `oracle_visible/`) differs.

`score.py` is pure — a function of (`expected.yaml`, `projections/<tag>.yaml`),
no clock, no network, no model. `defender/tests/test_oracle_golden_693.py` uses
that to assert every checked-in `scores/<tag>.json` still reproduces from its
projection, so the artifacts cannot drift away from the scorer that made them.
**Re-run the `score.py` line above for every case after changing `score.py`.**

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
5. Measure the control windows for each `+event` candidate **with that lead's own
   query predicate**, and on the field that distinguishes the event rather than on
   the rule/stream that carries it; write `controls.yaml`. For a `-noise`
   candidate, first confirm the envelope has a non-zero baseline to remove —
   otherwise the class is `0`. Record counts per distinct ingest (see the
   re-ingest hazard above).
6. `build_case.py` to assemble the case; author `expected.yaml` and
   `manifest.yaml` from `hidden/`. Set `lead_source` in the manifest if the
   envelopes were authored rather than captured. Put every concrete value the
   capture carries but the labels do not require into `observed_fields`, so
   fabrication in those fields is graded.

A **derived** case (mutation, negative control) re-derives its labels from its own
story: re-read every query predicate, because changing an entity that appears in a
filter changes the lead's class, not just its field values.

## Trust / abstention resolver (policy)

Calibration exists to gate learning. A **slice** = (system × template ×
result-class). A slice is:

- **trusted** — the slice's Wilson **lower bound** at `n = n_units` clears the
  stated threshold, with **zero** wrong concrete fields, **zero** false
  suppression, and **zero** malformed projections on that slice;
- **no-update** — below the bound, or any wrong-field / false-suppression /
  malformed output observed, or the slice is simply unexercised.

`N` is no longer a stub. It is **derived** from the interval width the policy
needs (`stats.py:required_n`): a ≥0.90 lower bound at 95% confidence takes **35
units at a perfect observed rate**, 69 at 0.97, 127 at 0.95, and is unreachable
below 0.90 because the bound converges to the rate. Units, not leads and not
runs — see `defender/docs/oracle-calibration.md`.

A slice is unexercised when the metric is `null`, not when it is `0.0` — the two
are different states and `score.py` keeps them distinct. Any score whose
`missing_leads` / `unscored_leads` / `duplicate_leads` is non-empty is not a
measurement at all and must not feed the resolver.

On the current scores that policy gates three slices to **no-update**:
elastic × `falco-alerts` × `+event` and elastic × `sshd-auth-history` × `+event`
(wrong volunteered values in case-002 and mut-001) and elastic ×
`sshd-auth-history` × `-noise` (case-003's false suppression). The `-noise` slice
should be treated as **unexercised as well as untrusted** until a case with a
measured non-zero baseline in its own envelope replaces case-003's.

Downstream contract (to be wired into the loop as follow-up): the learning loop
**must not** apply a positive/negative lesson-score update when the oracle slice
the judgment depended on is `no-update`. Model-reported confidence is **not**
calibration and must not substitute for a trusted slice.

## Current coverage

Results below are `glm-5.2_effort-none`.

> **Read the per-case results as description, not certification.** Run
> `report.py` for the number that counts: it computes at `n_units`, and the six
> seed cases are **4 units across 3 environments**, all of them `dev`. Overall
> class agreement is 33/36 = 0.92, whose 95% interval at 4 units is
> **[0.51, 1.00]** — every slice reads `insufficient` or `no-update`. That is the
> honest state of the suite, and #711 AC 9 is answered by the reporter saying so.
>
> **And the first held-out case says the dev number is optimistic.**
> `case-009-bruteforce-baseline-id` (generated, held-out, a new unit) scores
> **3/6 class agreement and `+event` recall 0.25**, against 0.92 and 0.71 on dev.
> One case at one unit is `insufficient` and the reporter refuses to publish an
> interval for it — but the direction is exactly what a held-out set is for, and
> it is the first evidence that iterating the prompt against the seed six left a
> mark on them.

| case | kind | classes | lead_source | system(s) / template(s) | result |
|---|---|---|---|---|---|
| `case-001-ssh-bruteforce-canary` | observed | `+event`, `0` | captured | elastic sshd-auth + zeek; cmdb; identity; threat-intel; change-mgmt | 7/9 class; +event recall 0.50; 0 wrong; 0 false-suppress |
| `case-002-authorized-keys-falco` | observed | `+event`, `0` | authored | elastic **falco-alerts**; cmdb | 2/2 class; recall 1.00; **2 wrong volunteered values** (`evt.type`, `proc.cmdline`) |
| `case-003-suppression-devws` | observed | `-noise`, `0` | authored | elastic sshd-auth + syslog; cmdb | **3/4** class; **1 false suppression** (l-001) — slice is `no-update` |
| `case-004-noise-stolen-cred` | observed | `+noise`, `0` | authored | elastic sshd-auth; cmdb | **3/3** class; correctly `+noise`, no over-projection to `+event` |
| `neg-001-unrelated-story` | negative-control | `0` | inherited (case-001) | (case-001 leads) | 9/9 — oracle abstained; no window-copying (re-earned on the de-leaked story) |
| `mut-001-source-identity` | mutation | `+event`, `0` | inherited (case-001) | (case-001 leads) | **9/9** class; recall 1.00; originals **CLEAN**; 1 wrong volunteered value |
| `case-009-bruteforce-baseline-id` | observed, **held-out** | `+event`, `0` | **captured, generated** | elastic sshd-auth + ip-to-host; cmdb; identity | **3/6** class; recall **0.25**; 0 wrong; 0 false-suppress — 3 under-projections |

`+event recall` is `null` in `scores/*.json` for case-003, case-004 and neg-001 —
those cases label no `+event` lead, so the metric is undefined, not zero.

**Units, not cases (#711).** The six rows above are four independent units:
`case-001`, `mut-001` and `neg-001` share one capture (brute-force ×
office-ws-1→canary-1), and `case-002`/`case-003` share one restored snapshot.
Adding a seventh case that reuses an existing envelope would add a row here and
nothing to `n_units`.

**One hand-set flag was corrected on 2026-07-26** by mechanical derivation:
`case-001 l-001` was marked `heterogeneous: true` with the note "3 surface the
burst, 1 is empty", but all four of its sub-queries carry byte-identical `WHERE`
clauses over the same window and all four surface the burst (95 / 48 / per-minute
13-32-28 / 95). Nothing in that lead is empty. The derived heterogeneous set is
`{l-002, l-006}` — which is exactly the set of `+event` misses, and exactly the
set carrying `intent_note`.

**These numbers were revised on 2026-07-25** by re-measuring every control against
the restored capture snapshot (hcloud image `412461512`) and re-deriving the
derived cases from their own mutated/replaced stories. Three of the seed results
did not survive:

| was | is | why |
|---|---|---|
| mut-001 7/9 | **9/9** | l-004 (6/6 queries) and l-006 (7/7) filter `source.ip == 172.18.0.15`; the mutation moves the attacker to `.30`, so their class is `0`, not `+event`. The labels had been inherited from case-001 rather than re-derived — a mutation case that did not itself mutate. The projection was right; the seed manifest blamed "heterogeneous-lead jitter". |
| case-003 4/4 | **3/4 + false suppression** | l-001's control, re-measured under l-001's own predicate, is 0 — no baseline to remove, so the label is `0` and the recorded `<suppressed: …>` is a false suppression. |
| case-002 `0 wrong` | **2 wrong** | the volunteered-value check now grades concrete values the labels did not require. |

Two claims were withdrawn rather than re-scored: case-002's "authorized_keys
modification never occurs in baseline" (the baseline fires that rule about hourly
in work hours) and case-003's "dev-ws-1 dark / web-1 alive" contrast (under each
lead's own predicate, neither host reports in the window).

**Result-class coverage: all four — `+event`, `0`, `-noise`, `+noise` — exercised**
(the #693 "exercises all four result classes" criterion), plus negative-control
and mutation. `-noise` is exercised by **one lead** (case-003 `l-002`) after the
relabel, and that lead's darkness is partial (see below), so treat the class as
touched rather than calibrated.

Still pending: a `-noise` re-capture on a stream with a measured non-zero baseline
in its own envelope (a weekday, or an action that destroys data at source);
routine **benign** observed cases; host-state / identity as `+event` surfaces;
more mutation entities; and wiring the trust resolver into lesson scoring.

### Notes surfaced by these cases

- **Projections track the story, not the window:** `neg-001` (unrelated story →
  all-`0`) and `mut-001` (mutated entities → emitted verbatim, originals never
  leaked) both hold. neg-001 holds *after* the answer was removed from its story:
  the de-leaked replay is the recorded projection.
- **`+noise` is the strongest case in the set.** case-004's `+noise` is fully
  earned: `sre-multihop-ssh` is a scheduled baseline action (jump-box →
  `trust_edges_out`, which includes db-1, as `sre.*`, running `uptime && df -h /`),
  sre.alice→db-1 accepted logins are dense across the whole corpus and in the same
  clock hour on prior days, and the captured aggregate row folds in a genuine
  concurrent baseline login alongside the four generated ones. An accepted login
  by a real SRE account on its routine path must NOT read as a catch, and it does
  not.
- **The oracle over-suppresses when the story says "the host goes dark".** In
  case-003 the story performs an explicit blinding action, and the oracle emitted
  `-noise` for both dev-ws-1 leads. For `l-002` that is right; for `l-001` the
  envelope had no baseline to remove, so it is a false suppression — the error
  class that turns ordinary silence into a detection. Suppression earned from the
  *story* is not the same as suppression visible in the *envelope*, and only the
  second is ground truth.
- **Stopping a shipper delays telemetry; it does not remove it.** dev-ws-1's
  in-window auth lines were ingested at 09:47:04, right after the agent restarted,
  with their original timestamps — so the same query run three minutes later
  returns them. Only telemetry the agent *generates* (`elastic_agent*`) is
  permanently gone. A durable `-noise` capture needs a stream of that kind, or an
  action that destroys data at source (clearing the log, disabling auditd). Until
  then, a `-noise` ground truth is a claim about the moment of capture.
- **A mutation must be re-derived, not inherited.** mut-001's labels were copied
  from case-001 and swapped field values, missing that the mutation moves two
  leads outside their query filters entirely. Whenever a mutation changes an
  entity that appears in a query *predicate*, expect class changes, not just
  field changes.

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
