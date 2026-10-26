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

Run it by hand. Every run names its tenant, and there is no default (#1078) — clone your
tenant's knowledge repo into the data root and set the tenant up once:

```bash
export DEFENDER_DATA_ROOT=/path/outside/the/checkout
export TENANT_ID=$(python3 defender/cli/tenant.py new-id)  # save this UUID
git clone <tenant repo> "$DEFENDER_DATA_ROOT/$TENANT_ID/knowledge"
python3 defender/cli/tenant.py setup "$TENANT_ID"
```

Clone with a credential helper or an ssh agent (never a credential in the URL), and run setup
once the clone has exited 0; setup adopts the placed folder and copies nothing.
A data root made before #1120 (no `<id>/knowledge/`) has no repo to clone: build the folder
once with `tenant.py migrate <id> <root>/<id>/knowledge`, then run setup.

For an existing named tenant, follow the offline identity migration in
[development operations](../defender/docs/development-operations.md#migrating-named-tenants-to-uuids-1187);
`tenant.py migrate` does not convert tenant IDs.

Run `tenant.py setup` once, from the main checkout, with `DEFENDER_DATA_ROOT` set (there is no
default data root) and no run, fork or drain in flight on any checkout of the host, as the same
user that runs defender; a destination already occupied makes setup refuse, naming it in the
message. (Adopting an existing (B)/(C) installation whose old entries are root-owned may need
setup run as root — that adoption case only.)

```bash
# Primary: score against ground truth. It walks fixtures/held_out/ and finds each
# fixture's run through the held-out index F you name (outside every runs and episodes
# tree), one {"slug", "run_id"} row per run, which you append yourself. run.py's first
# stdout line names the run id: run_id=<uuid>. A run that crashes before it leaves no row,
# and the slug's older row (if any) is scored instead. Pin every run of one index to one
# knowledge revision (--knowledge-commit K, #1108 P4) so its scores are comparable.
python3 defender/run.py evaluations/fixtures/held_out/<slug>/alert.json --tenant "$TENANT_ID" --no-learn --knowledge-commit K
python3 evaluations/held_out.py "$DEFENDER_DATA_ROOT/$TENANT_ID/runs" --index F
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
defender/.venv/bin/python evaluations/harness_lead.py \
    evaluations/scenarios_lead/underfold-sshd-narrowing
```
