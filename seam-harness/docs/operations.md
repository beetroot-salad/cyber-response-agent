# Operating the harness

## Natural-language intake

The normal entry point is an ordinary request, not hand-authored JSON:

```bash
PYTHONPATH=src python -m seam_harness intake tasks/my-task.json \
  --request-file request.md \
  --title "Optional title hint" \
  --material architecture.md \
  --material observed-behavior.txt
```

A short request can be passed directly with `--request`. Repeat `--decision` for explicit choices already made in conversation. The intake agent compiles this source envelope into a proposed `HarnessSpec` while preserving all of the following in the same file:

- the verbatim request, decisions, and text materials;
- the proposed frame and numbered demands;
- derivation links marked explicit, inferred, or defaulted;
- assumptions, unresolved issues, and consequential clarification questions;
- an intake readiness state and model-usage metadata.

The source envelope is not replaced by the frame. Independent questioners receive both, allowing them to probe for important nuance lost during compilation. Planners and leaves still operate through controlled frame and dossier boundaries. Source and frame digests bind the derivation record; corrections should be supplied as decisions and recompiled rather than silently editing stale provenance.

If intake reports `needs_clarification` or `exploratory`, normal dispatch stops. Add decisions and compile the draft again:

```bash
PYTHONPATH=src python -m seam_harness intake tasks/my-task.json \
  --request-file request.md \
  --decision "The migration must preserve active sessions" \
  --force
```

`--allow-unresolved-intake` exists for deliberate experiments, not routine bypass. The output JSON should be treated as a reviewable dispatch artifact rather than the natural user interface.

## Adaptive solving

For work that should produce a deliverable, pass the ready intake artifact to `solve`:

```bash
export FIREWORKS_API_KEY="..."
PYTHONPATH=src python -m seam_harness solve tasks/my-task.json \
  --workspace path/to/relevant/source \
  --output outputs/result.txt \
  --runs-dir runs
```

The workspace is snapshotted read-only. Each recursive participant sees a compact posterior summary rather than full documents or the full graph, and can query immutable question/answer threads and bounded source excerpts. A turn may publish the participant's current synthesis and then delegate, verify, continue, or finish. Parallel delegates share one frozen initial snapshot; their parent is re-invoked after returned answers reshape the forum.

The root participant, subtree-synthesis tier, and finalizer use Kimi K3 by default. Fresh descendants use the smaller DeepSeek V4 Flash model by default; `--research-model` changes that cost/capability tier without changing the participant contract. Bound total turns with `--max-adaptive-steps`, recursive depth with `--max-depth`, parallel waves with `--max-adaptive-wave` and `--max-concurrency`, work with `--max-nodes`, retrieval/tool turns with `--adaptive-request-limit`, and verification with `--max-experiment-seconds`. `pytest` and model-authored `python_checker` require explicit enablement.

`solve` records every public model dossier, pull query, returned entry ID, participant turn and rejection, natural knowledge post and read set, seam signal, verification request and result, operational failure, graph update, action read/write set, participant depth, snapshot transition, timing, usage, and final artifact. `inspect` verifies the journal chain; `postmortem` reconstructs the action DAG and query behavior. See `adaptive-harness.md`.

The fixed recursive comparator remains available with `--execution recursive`. Its node-tree budgets, `--require-root-expansion`, and verified `--replay-run` behavior are documented in `recursive-solver.md`.

## Expert-authored specs

For reproducible or programmatic use, a spec can still be authored directly. Start a skeleton with:

```bash
PYTHONPATH=src python -m seam_harness init tasks/my-task.json \
  --title "My task" \
  --task "Describe the work product" \
  --intent "Describe why the product exists" \
  --demand "Name one whole-task obligation" \
  --demand "Name another whole-task obligation"
```

Then edit the stable context, external referents, and constraints. Demands should be independently identifiable whole-task obligations. In adaptive mode they remain coverage and retrieval anchors rather than assignments in a predeclared tree.

Use `solve` for adaptive posterior inquiry and a final deliverable; pass `--execution recursive` for the fixed-tree comparator. The legacy high-instrumentation seam experiment remains available with `run`; its intake, root, and leaf roles default to `fireworks:accounts/fireworks/models/kimi-k3`, with `--intake-model`, `--model`, and `--leaf-model` overrides.

## Run record and post-mortem

Each run gets its own directory. It contains:

- the submitted spec;
- the validated dependency context disclosed to every model call, including calls that later fail;
- every typed role output and leaf-product digest;
- knowledge queries, returned IDs, snapshot transitions, and action dependencies in adaptive runs;
- the blind-subject map in legacy diagnostic runs, written only after blind interpretation;
- timing, token usage, role, model, call ID, and input digest metadata;
- the terminal result or failure;
- a manifest linking events and file hashes.

Verify the record chain:

```bash
PYTHONPATH=src python -m seam_harness inspect runs/<run-id>
```

Build a human-readable investigation report:

```bash
PYTHONPATH=src python -m seam_harness postmortem runs/<run-id>
```

Use `--format json` for analysis tooling. `inspect ... --format markdown` is equivalent to the human-readable post-mortem.

The report surfaces the final decision, topology, model-call trace, usage, knowledge-graph counts, relation frequencies, multi-answer, contradicted, and unanswered questions, likely learning, handoff loss, silent coupling, correlated assumptions, missing evidence, and unresolved questions. The underlying JSON records remain the source of truth; the report is deterministic and does not ask another model to narrate the run.

## Audit boundary

“Recorded and audited” has a precise, limited meaning here:

- The harness records the contexts and typed artifacts it controls. It does not record hidden chain-of-thought, and it does not store API keys.
- The hash chain detects missing or edited records if the manifest is left intact. It is not externally signed or anchored, so someone able to rewrite the entire directory can recompute the chain.
- The blind interpreter, topology diagnosis, opposing advocates, and adjudicator constitute a semantic audit. They improve discrimination; they do not prove truth. Artifact execution and external referents remain stronger evidence.
- Run directories contain the task material sent to models and may be sensitive. They are local JSON without encryption or redaction in this version.

## User interface

There is no chat UI in this version. The CLI intake pass provides natural-language framing before run submission. Pydantic AI's built-in `Agent.to_web()` page exposes one agent; attaching it directly to the planner or another role would bypass the visibility boundaries and orchestration being tested.

A proper web UI should therefore be harness-aware: submit or edit a `HarnessSpec`, show stage and cost progress, browse per-call disclosed contexts and outputs, and render the deterministic post-mortem. A conversational task-framing assistant can sit before submission, but its output should still freeze into a visible spec before dispatch.
