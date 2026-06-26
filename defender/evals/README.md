# defender/evals/

The **measurement layer** for the defender. This is the eval home — separate
from `defender/tests/` on purpose: tests are deterministic CI gates that assert
invariants; evals run on a researcher's cadence, make LLM calls, and emit
*scores/trends* rather than pass/fail. They are not collected as part of the
CI gate (except `test_secondary.py`, which unit-tests the harness logic and is
deterministic).

Everything here measures the defender or its learning loop. The dependency
direction is one-way: `evals/` imports/invokes `learning/` and `runtime/`,
never the reverse.

## The metrics

| File | Metric | Question it answers |
|---|---|---|
| `held_out.py` | **Primary** — disposition accuracy | Does the *current* defender's disposition match ground truth on the labeled held-out alerts? This is the loop's north-star metric. |
| `secondary.py` | **Secondary** — frozen-actor replay catch rate | Would the current defender's lead sequence refute stories an *older* (gen N−K) actor writes? |

Run them by hand:

```bash
# Primary: score a runs dir against ground truth (defaults to $DEFENDER_RUNS_BASE)
python3 defender/evals/held_out.py "$DEFENDER_RUNS_BASE"

# Secondary: frozen-actor replay, pinned K generations back (default 3)
python3 defender/evals/secondary.py [--k 3] [--out <dir>]
```

**Read them together.** The primary plateauing *while* the secondary climbs
across consecutive checkpoints is the divergence signal — the defender is
gaining curriculum-distribution fit (beating the actor it co-trains against)
without target-distribution fit (real ground truth). Neither number means much
alone. Design rationale: `defender/docs/learning-loop.md` §Secondary.

`secondary.py` writes its summary + per-alert detail under
`defender/evals/results/secondary/` (gitignored). It shells out to
`defender/learning/ops/replay_actor.py` inside a worktree pinned to gen-(N−K); that
script stays in `learning/` because the live loop uses it too.

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
