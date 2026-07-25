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
  manifest.yaml            # provenance, classes covered, lead_source, recorded projections
  oracle_visible/          # ← the ONLY thing a projection may read
    story.md               #   ground-truth story (the oracle's story input)
    leads.jsonl            #   per lead: {lead_id, goal, what_to_summarize, queries[{query_id, params}]}
    samples/<lead>.txt     #   the redacted sample skeleton the production oracle sees
  hidden/                  # ← the scoring target; never an oracle input. OBSERVED CASES ONLY
    observed/<lead>/<seq>.json   #   full observed query payloads (ground truth)
    controls.yaml          #   shape-matched control-window baseline (see below)
  expected.yaml            # authoritative labels: per-lead 4-way class + key fields
  projections/<tag>.yaml   # oracle output for a given model/prompt (tag = <model>_effort-<e>)
  scores/<tag>.json        # scored dimensions for that projection
```

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
- **field/value grounding** on `+event` leads: `correct` / `wrong` / `unknown`
  (emitted only as a `<placeholder>`) / `missing`. `wrong` is the dangerous
  error; placeholders are *never* `wrong` — the prompt mandates them for values
  the story does not state;
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
   step makes the oracle "wrong" for a story reason).
5. Measure the control windows for each `+event` candidate; write `controls.yaml`.
6. `build_case.py` to assemble the case; author `expected.yaml` and
   `manifest.yaml` from `hidden/`. Set `lead_source` in the manifest if the
   envelopes were authored rather than captured.

## Trust / abstention resolver (policy)

Calibration exists to gate learning. A **slice** = (system × template ×
result-class). A slice is:

- **trusted** — enough calibrated cases (≥ N, currently a stub threshold) with
  class agreement ≥ threshold, **zero** wrong concrete fields, **zero** false
  suppression, and **zero** malformed projections on that slice;
- **no-update** — below threshold, or any wrong-field / false-suppression /
  malformed output observed, or the slice is simply unexercised.

A slice is unexercised when the metric is `null`, not when it is `0.0` — the two
are different states and `score.py` keeps them distinct. Any score whose
`missing_leads` / `unscored_leads` / `duplicate_leads` is non-empty is not a
measurement at all and must not feed the resolver.

Downstream contract (to be wired into the loop as follow-up): the learning loop
**must not** apply a positive/negative lesson-score update when the oracle slice
the judgment depended on is `no-update`. Model-reported confidence is **not**
calibration and must not substitute for a trusted slice.

## Current coverage

Results below are `glm-5.2_effort-none`.

| case | kind | classes | lead_source | system(s) / template(s) | result |
|---|---|---|---|---|---|
| `case-001-ssh-bruteforce-canary` | observed | `+event`, `0` | captured | elastic sshd-auth + zeek; cmdb; identity; threat-intel; change-mgmt | 7/9 class; +event recall 0.50; 0 wrong; 0 false-suppress |
| `case-002-authorized-keys-falco` | observed | `+event`, `0` | authored | elastic **falco-alerts**; cmdb | 2/2 class; +event recall 1.00; 0 wrong |
| `case-003-suppression-devws` | observed | `-noise`, `0` | authored | elastic sshd-auth + syslog; cmdb | **4/4** class; correct suppression + no over-suppression; 0 false-suppress |
| `case-004-noise-stolen-cred` | observed | `+noise`, `0` | authored | elastic sshd-auth; cmdb | **3/3** class; correctly `+noise`, no over-projection to `+event` |
| `neg-001-unrelated-story` | negative-control | `0` | inherited (case-001) | (case-001 leads) | 9/9 — oracle abstained; no window-copying |
| `mut-001-source-identity` | mutation | `+event`, `0` | inherited (case-001) | (case-001 leads) | 7/9 class; forbidden originals **CLEAN**; mutated src/user emitted correctly |

`+event recall` is `null` in `scores/*.json` for case-003, case-004 and neg-001 —
those cases label no `+event` lead, so the metric is undefined, not zero.

**Result-class coverage: all four — `+event`, `0`, `-noise`, `+noise` — exercised**
(the #693 "exercises all four result classes" criterion), plus negative-control
and mutation. Still pending: routine **benign** observed cases, host-state /
identity as `+event` surfaces, more mutation entities, and wiring the trust
resolver into lesson scoring.

### Notes surfaced by these cases

- **Suppression discrimination is real:** in case-003, `l-001` (`-noise`) and
  `l-003` (`0`) both have *empty* observed results — the oracle told them apart
  from the story alone (dev-ws-1 blinded, web-1 not), and did not over-suppress.
- **Projections track the story, not the window:** `neg-001` (unrelated story →
  all-`0`) and `mut-001` (mutated entities → emitted verbatim, originals never
  leaked) both hold.
- **The two noise classes are mirror-imaged correctly:** case-003 emits `-noise`
  where a stream is blinded, case-004 emits `+noise` where a stolen-credential
  login is shape-identical to routine access — and neither over-projects a
  `+event`. The `+noise` case is the sharp anti-over-projection test: an accepted
  login by a real SRE account on its routine path must NOT read as a catch.
- **Heterogeneous-lead emission has run-to-run variance:** across case-001 and
  mut-001 (same leads), *which* of the borderline heterogeneous leads emit
  `+event` vs `0`/`+noise` shifts between runs. The disposition-bearing leads are
  stable; the borderline ones are a jitter source worth tracking per model/prompt.

- **One recorded projection predates the harness:** case-001's
  `glm-5.2_effort-none` was produced by the #707 probe driving the production
  path directly, not by `replay.py` (its manifest flags
  `reproducible_by_replay_py: false`). Same seam, same oracle-visible inputs, so
  it is comparable — but it is the one tag the documented command will not
  re-derive. Every other tag came from `replay.py`.

Reports are keyed by projection tag (`<model>_effort-<effort>`) so results stay
versioned by oracle model + prompt.
