# defender/evals/

The **measurement layer** for the defender. This is the eval home — separate
from `defender/tests/` on purpose: tests are deterministic CI gates that assert
invariants; evals run on a researcher's cadence, make LLM calls, and emit
*scores/trends* rather than pass/fail. Nothing here is collected by CI.

The split is by *what a file is*, not by what it covers: the unit tests of this
tooling ARE deterministic CI gates, so #720 moved them to `defender/tests/evals/`
with the rest of the suite. They had been sitting here uncollected, because
`evals/` was missing from the workflow's collection roots. A test in the source
tree is a test nobody is running.

Everything here measures the defender or its learning loop. The dependency
direction is one-way: `evals/` imports/invokes `learning/` and `runtime/`,
never the reverse.

## The metrics

| File | Metric | Question it answers |
|---|---|---|
| `held_out.py` | **Primary** — disposition accuracy | Does the *current* defender's disposition match ground truth on the labeled held-out alerts? This is the loop's north-star metric. |

Run it by hand:

```bash
# Primary: score against ground truth (runs dir defaults to $DEFENDER_RUNS_BASE).
# It walks fixtures/held-out/ and finds each fixture's run by run-id, so launch
# scored runs as: run.py <fixture>/alert.json --run-id <slug> --no-learn
python3 defender/evals/held_out.py "$DEFENDER_RUNS_BASE"
```

**There used to be a second metric here.** `secondary.py` scored a *frozen-actor
replay* catch rate — would the current defender's lead sequence refute stories a
gen-(N−K) actor writes? — and it was read against the primary as a divergence
signal. #791 took the offline oracle out of the loop, which left that harness
structurally unable to produce a number: its catch-rate denominator was always
zero and it printed `n/a (0 executed)` while still paying for a full HEAD
investigation, a pinned worktree and a replay per fixture. It has been retired,
along with the judge A/B comparison harness (`judge_equivalence.py` /
`run_judge_ab.py`), which could no longer reach any branch but "NOT MEASURED".
`learning/ops/replay_actor.py` stays — the live loop uses it too.

## The harness-on-the-harness

`harness.py` / `harness_lead.py` (+ `_harness_util.py`) materialize a temp
working tree and run the author / lead-author stages against the scenarios in
`scenarios/` and `scenarios_lead/`, to evaluate the *loop machinery itself*
(not the runtime agent). They run as standalone scripts — `evals/` is on
`sys.path[0]`, so `_harness_util` imports sibling-style. Scratch + result dirs
(`_tmp/`, `_tmp_lead/`, `results/`, `results_lead/`) are gitignored.

```bash
defender/.venv/bin/python defender/evals/harness_lead.py \
    defender/evals/scenarios_lead/underfold-sshd-narrowing
```
