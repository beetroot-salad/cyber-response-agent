# evaluations/

The **measurement layer** for the defender. This is the eval home — separate
from `defender/tests/` on purpose: tests are deterministic CI gates that assert
invariants; evals run on a researcher's cadence, make LLM calls, and emit
*scores/trends* rather than pass/fail. The evals themselves are never run by CI.

The tooling's own unit tests are the exception, and they live in `tests/` here, beside what they
cover. They are deterministic CI gates — no model calls — and CI collects them in a step of their
own (`pytest evaluations/tests`), because the defender suite's `tests/` root does not reach this
tree. That step is load-bearing: before #720 these tests sat here with no CI step naming them and
ran nowhere, and a test nobody is running is not a test. `tests/conftest.py` borrows the defender
suite's data-root and deployment isolation, so no test here can touch a real data root.

Everything here measures the defender or its learning loop. The dependency
direction is one-way: `evals/` imports/invokes `learning/` and `runtime/`,
never the reverse.

## The metrics

| File | Metric | Question it answers |
|---|---|---|
| `held_out.py` | **Primary** — disposition accuracy | Does the *current* defender's disposition match ground truth on the labeled held-out alerts? This is the loop's north-star metric. |

Run it by hand. Every run names its tenant, and there is no default (#1078). Create the tenant
through the lifecycle service's admin API (see "Creating a tenant" in
[development operations](../defender/docs/development-operations.md)); it records the tenant in
PostgreSQL, so set `DEFENDER_DATABASE_DSN` and `DEFENDER_DATA_ROOT` for the run, and use the tenant's
UUID. A run works only for an `active` tenant. For an existing named tenant, follow the offline
identity migration in
[development operations](../defender/docs/development-operations.md#migrating-named-tenants-to-uuids-1187);
`tenant.py migrate` does not convert tenant IDs and is retired.


Run every tool here as a module from the repository root (`defender/.venv/bin/python -m evaluations.held_out ...`); by filename it fails with `No module named 'defender'`.

Every held-out case is frozen (#1347): it carries a confirmed `freeze.yaml`, and every scored
run of it is launched by the held-out launcher, which serves the run the lab as of the freeze,
checks the freeze afterwards and appends the run's row to the index. Rows are never written by
hand; a row without the launcher's `freeze` digest and `verdict` never counts.
`playground-v2/docs/runbook.md` §Frozen held-out cases has capture and labelling.

```bash
# Launch each case against its freeze (on a machine with the lab's docker context). Pin every
# run of one index to one knowledge revision (--knowledge-commit K, #1108 P4) so its scores are
# comparable. A run that dies before announcing its run id leaves no row: launch it again.
defender/.venv/bin/python playground-v2/scripts/launch_frozen.py \
    evaluations/fixtures/held_out/<slug> --tenant "$TENANT_ID" --index F \
    --parts-dir <lab disk path> --knowledge-commit K
# Primary: score against ground truth. It walks fixtures/held_out/ and scores each case from
# the newest row in F (outside every runs and episodes tree) bound to its current freeze. A
# case with no such row, a stale verdict, or a run that read Elasticsearch's own clock is
# listed with its reason; the set is then INCOMPLETE and the exit is non-zero.
defender/.venv/bin/python -m evaluations.held_out "$DEFENDER_DATA_ROOT/$TENANT_ID/runs" --index F
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
The standalone actor replay command was also retired; no scheduled driver remains.

## The harness-on-the-harness

`harness.py` / `harness_lead.py` (+ `_harness_util.py`) materialize a temp
working tree and run the author / lead-author stages against the scenarios in
`scenarios/` and `scenarios_lead/`, to evaluate the *loop machinery itself*
(not the runtime agent). They run as standalone scripts — `evals/` is on
`sys.path[0]`, so `_harness_util` imports sibling-style. Scratch + result dirs
(`_tmp/`, `_tmp_lead/`, `results/`, `results_lead/`) are gitignored.

```bash
defender/.venv/bin/python -m evaluations.harness_lead \
    evaluations/scenarios_lead/underfold-sshd-narrowing
```
