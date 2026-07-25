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
  manifest.yaml            # provenance, classes covered, recorded projections
  oracle_visible/          # ← the ONLY thing a projection may read
    story.md               #   ground-truth story (the oracle's story input)
    leads.jsonl            #   per lead: {lead_id, goal, what_to_summarize, queries[{query_id, params}]}
    samples/<lead>.txt     #   the redacted sample skeleton the production oracle sees
  hidden/                  # ← the scoring target; never an oracle input
    observed/<lead>/<seq>.json   #   full observed query payloads (ground truth)
    controls.yaml          #   shape-matched control-window baseline (see below)
  expected.yaml            # authoritative labels: per-lead 4-way class + key fields
  projections/<tag>.yaml   # oracle output for a given model/prompt (tag = <model>_effort-<e>)
  scores/<tag>.json        # scored dimensions for that projection
```

`replay.py` reads only `oracle_visible/`; `score.py` reads `expected.yaml` (which
was authored from `hidden/`). The boundary is structural, not a matter of
discipline.

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
  `0` precision (stayed empty where expected);
- **false suppression**: any `-noise` predicted where the stream is actually
  alive — the error that turns ordinary silence into a false detection.

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

## Tools

```bash
# Capture an observed case from a defender run + ground-truth story + controls:
python3 defender/evals/oracle_golden/build_case.py \
    <case_id> <run_dir> <story.md> <controls.yaml> cases/<case_id>

# Re-run the production oracle over a case (reads ONLY oracle_visible/):
python3 defender/evals/oracle_golden/replay.py cases/<case_id> [--tag <model>_effort-<e>]

# Score a projection against the case's labels, emit the dimensions:
python3 defender/evals/oracle_golden/score.py cases/<case_id> \
    cases/<case_id>/projections/<tag>.yaml --json cases/<case_id>/scores/<tag>.json
```

`replay.py` drives the exact production seam (`invoke_oracle_lead` →
`_run_oracle_pydantic`), so a projection is production-identical; only its input
source (the case's `oracle_visible/`) differs.

## Capturing a new observed case (needs the env)

1. Lever up `playground-v2` (`infra/bin/up.sh`) and install detection rules.
2. Fire a catalog attack (`playground-v2/attacks/runner.py run <scenario>`);
   its `runs/<id>/meta.json` is the ground truth.
3. When the rule fires, project the alert to fixture shape and run
   `defender/run.py <alert.json> --run-id <slug> --no-learn`.
4. Author `story.md` from the manifest — state **only what happened** (an invented
   step makes the oracle "wrong" for a story reason).
5. Measure the control windows for each `+event` candidate; write `controls.yaml`.
6. `build_case.py` to assemble the case; author `expected.yaml` from `hidden/`.

## Trust / abstention resolver (policy)

Calibration exists to gate learning. A **slice** = (system × template ×
result-class). A slice is:

- **trusted** — enough calibrated cases (≥ N, currently a stub threshold) with
  class agreement ≥ threshold, **zero** wrong concrete fields, and **zero** false
  suppression on that slice;
- **no-update** — below threshold, or any wrong-field / false-suppression
  observed, or the slice is simply unexercised (e.g. `-noise` today).

Downstream contract (to be wired into the loop as follow-up): the learning loop
**must not** apply a positive/negative lesson-score update when the oracle slice
the judgment depended on is `no-update`. Model-reported confidence is **not**
calibration and must not substitute for a trusted slice.

## Current coverage

Results below are `glm-5.2_effort-none`.

| case | kind | classes | system(s) / template(s) | result |
|---|---|---|---|---|
| `case-001-ssh-bruteforce-canary` | observed | `+event`, `0` | elastic sshd-auth + zeek; cmdb; identity; threat-intel; change-mgmt | 7/9 class; +event recall 0.50; 0 wrong; 0 false-suppress |
| `case-002-authorized-keys-falco` | observed | `+event`, `0` | elastic **falco-alerts**; cmdb | 2/2 class; +event recall 1.00; 0 wrong |
| `case-003-suppression-devws` | observed | `-noise`, `0` | elastic sshd-auth + syslog; cmdb | **4/4** class; correct suppression + no over-suppression; 0 false-suppress |
| `neg-001-unrelated-story` | negative-control | `0` | (case-001 leads) | 9/9 — oracle abstained; no window-copying |
| `mut-001-source-identity` | mutation | `+event`, `0` | (case-001 leads) | forbidden originals **CLEAN**; mutated src/user emitted correctly |

**Result-class coverage: `+event`, `0`, `-noise` exercised; `+noise` (stealthy —
malice in baseline-shape events) is the remaining gap.** Also pending: routine
**benign** observed cases, host-state / identity as `+event` surfaces, and more
mutation entities. `+noise` and benign need an env; more mutations are offline.

### Notes surfaced by these cases

- **Suppression discrimination is real:** in case-003, `l-001` (`-noise`) and
  `l-003` (`0`) both have *empty* observed results — the oracle told them apart
  from the story alone (dev-ws-1 blinded, web-1 not), and did not over-suppress.
- **Projections track the story, not the window:** `neg-001` (unrelated story →
  all-`0`) and `mut-001` (mutated entities → emitted verbatim, originals never
  leaked) both hold.
- **Heterogeneous-lead emission has run-to-run variance:** across case-001 and
  mut-001 (same leads), *which* of the borderline heterogeneous leads emit
  `+event` vs `0`/`+noise` shifts between runs. The disposition-bearing leads are
  stable; the borderline ones are a jitter source worth tracking per model/prompt.

Reports are keyed by projection tag (`<model>_effort-<effort>`) so results stay
versioned by oracle model + prompt.
