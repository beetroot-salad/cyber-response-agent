# Experiment: lead-classifier ablation

## Question
**Engineering** — Does the `composite_kind` / `co_dispatched_with` classification
metadata in the lead-author handoff actually change the lead-author LLM's
decisions, or does the agent reach the same lift/discard/skip/mint verdict from
the rest of the handoff (`neighbors` scores + `executed_query` + payload)? If it
changes nothing, delete the classifier (`lead_classifier.py`) outright rather
than refactoring it per #457.

## Key prior finding
The metadata only carries signal when a template appears in a **multi-query
pattern** (sweep / join / baseline_shift). On atomic single-query leads it is
inert (`composite_kind="atomic"`, `co_dispatched_with=[]`). The sole existing
eval scenario is atomic, so it cannot test this — new multi-query fixtures are
required.

## Variants
One variable: presence of classifier output. Both the handoff JSON keys **and**
the prompt guidance that references them move together (removing one without the
other is a strawman).

### current (regression)
HEAD. `build_handoff` computes and emits:
```python
composite_kind = lead_classifier.infer_composite_kind(entry, query, entries)
co_dispatched  = lead_classifier.co_dispatched_template_paths(entry, lead.query_index, template_path_by_id)
...
"composite_kind": composite_kind,
"co_dispatched_with": co_dispatched,
```
and `lead_author.md` instructs the agent to read `composite_kind` (lines ~38, 44, 75, 155).

### proposed (classifier removed)
- `build_handoff`: drop both key assignments and the `infer_composite_kind` /
  `co_dispatched_template_paths` calls (and the `entries`/`template_path_by_id`
  reconstruction that exists only to feed them).
- `lead_author.md`: delete the `composite_kind` bullet/distribution guidance
  (lines ~38, 44, 75, 155) so the agent isn't told to read a field that's gone.
- `lead_classifier.py` stays on disk during the experiment (deleted only if
  proposed wins); harness wiring is identical.

Variant is applied as a small patch the harness materializes onto the temp tree
(see `variants/`), so `current` and `proposed` run the same code path otherwise.

## Fixtures
All under `fixtures/`, same shape as `scenarios_lead/underfold-sshd-narrowing`
(run/<id>/executed_queries.jsonl + gather_raw sidecars + payloads, expect.json).
Each multi-query fixture pairs a non-atomic pattern with a synthesized draft the
agent could be tempted to promote as a narrow sibling — the metadata's claimed
job is to suppress that.

Each multi-query fixture executes the established **wide** `elastic.sshd-auth-history`
in a real pattern (so its handoff carries the non-atomic `composite_kind`) PLUS a
separately-coined narrow query that is a **borderline** narrowing — genuine
ground-truth=discard, but wearing a surface that could read as a new measurement
from `neighbors` alone, so `composite_kind` is the tiebreaker. Verified to
classify as intended (deterministic classifier check).

- `sweep-srcip-host/` — `sshd-auth-history` dispatched 3× in one lead, narrowed
  per `source.ip` (`composite_kind=sweep`). Coined `sshd-failed-rate-by-srcip`
  adds a `DATE_TRUNC(1 hour)` bucket → looks like a "rate trend", but the
  template's own note cites that bucket as a narrowing. Discard expected.
- `join-cross-system/` — `sshd-auth-history` co-dispatched with
  `identity.user-authorization` in one lead (`composite_kind=join`, non-empty
  `co_dispatched_with`). Coined `sshd-failed-by-suspect-user` (named user set +
  `last_seen` + multi-key BY) → looks like triage, is a subset. Discard expected.
- `baseline-shift-two-window/` — `sshd-auth-history` same shape over two windows
  (`composite_kind=baseline_shift`). Coined `sshd-failed-burst-profile`
  (`COUNT_DISTINCT` + first/last BY user) → looks like a novel anomaly metric, is
  the wide template scoped to one window. Discard expected.
- `atomic-control/` — single coined `sshd-failed-by-srcip` (atomic), clone of
  `underfold-sshd-narrowing`. **Control:** metadata is inert; removal MUST be
  neutral. If the arms diverge here, the harness/variant is confounded, not the
  metadata.

## Run mechanics
Two committed worktrees avoid patch-thrash and allow parallel arms:
`.claude/worktrees/lead-classifier-ablation` (current/HEAD) and
`…-proposed` (patch committed). `run_trial.sh <arm> <fixture> <trial>` runs that
arm's worktree harness against the fixture (passed by absolute path) and writes
`runs/<arm>/<fixture>/<trial>/verdict.txt`. `run_batch.sh <N> <parallelism>`
fans out all arms×fixtures×N. `defender` is a PEP420 namespace package with no
editable `.pth`, so the harness's `sys.path[0]` temp tree authoritatively
shadows `/workspace` — the worktree's (patched) code is what runs.

## Trials
Validation: 1 trial per variant per fixture (8 runs) — confirm fixtures parse,
the verdict fires, and the variant patch applies cleanly.

Scale-up: **N=10 trials per variant per multi-query fixture** (the 3 load-bearing
ones) + N=10 per arm on the atomic control = 80 live `claude -p` runs total.
Mid-run analysis at **3 trials/arm/fixture (~30%)**: if the atomic control already
diverges, abort and fix the harness; if the multi-query arms show a large gap,
we can stop early.
Analysis script written before scale-up: `analyze.py` — parses each run's
`verdict.txt`, aggregates {FAIL, WEAK-PASS, PASS} counts per (variant, fixture),
reports underfold rate (FAIL/N) and clean-discard rate (PASS/N) with n as support.

## Decision criteria
Underfold rate = FAIL/N is the headline metric (promoting a narrow sibling is the
failure the loop exists to prevent).

- **proposed wins (delete classifier)** if, on the multi-query fixtures, the
  proposed arm's underfold rate is within noise of current (Δ ≤ ~10pp, no fixture
  where proposed is clearly worse) AND clean-discard rate doesn't drop materially.
  i.e. the agent reaches the same verdicts from neighbors+executed_query alone.
- **current retained (keep, then refactor per #457)** if removing the metadata
  raises the underfold rate or collapses discards into weak-pass/skip on any
  multi-query fixture beyond noise — the signal is doing real work.
- **harness invalid** if the atomic control diverges between arms.

## Layout
experiments/lead-classifier-ablation/
  plan.md
  variants/remove-classifier.patch
  fixtures/{sweep-srcip-window,join-cross-system,baseline-shift-two-window,atomic-control}/
  runs/<variant>/<fixture>/<trial>/
  analyze.py
  results/{midrun.md,final.md}

Execution runs in a git worktree (per repo convention); fixtures + temp trees
live outside the repo checkout the agent edits.
