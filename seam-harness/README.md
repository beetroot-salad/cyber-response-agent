# Seam Harness

Seam Harness treats work shape as a hypothesis about an unknown dependency graph. Its default executor observes, queries, investigates, synthesizes, and revises one bounded action at a time instead of asking a planner to predict the whole tree in advance.

The project is standalone under `/workspace/seam-harness`. It has no integration with `defender`, does not import from it, is not a Git repository, and has not been committed to any version control.

## Execution paths

- `solve` defaults to the recursive participant harness. Every node uses the same query-capable participant contract to publish a synthesis and then delegate, verify, continue, or finish. Delegates may recurse; returned answers and verification results reshape the next parent turn.
- `solve --execution recursive` runs the earlier fixed recursive context compiler. It remains a useful comparator and supports replay of completed plans and packets.
- `run` runs the original high-instrumentation seam experiment with independent questioners, held-out audits, blind interpretation, diagnosis, advocacy, and adjudication.

All paths use Pydantic AI typed boundaries and append-only hash-linked journals. Types protect identity, evidence, visibility, and permissions; semantic compatibility remains a model judgment checked against artifacts where possible.

## Task and run it

The ordinary front door is a natural request:

```bash
PYTHONPATH=src python -m seam_harness intake tasks/my-task.json \
  --request "Describe the work you want done" \
  --material relevant-context.md
```

The intake agent preserves the request and produces a reviewable frame with product intent, numbered obligations, stable context, assumptions, derivations, clarifications, and readiness. This frame is a routing and audit intermediate representation, not a decomposition plan and not a claim that the solution naturally has a schema.

Run the adaptive harness through Fireworks:

```bash
export FIREWORKS_API_KEY="..."
PYTHONPATH=src python -m seam_harness solve tasks/my-task.json \
  --workspace path/to/relevant/source \
  --output outputs/result.txt \
  --runs-dir runs
```

Kimi K3 is the default root, posterior-synthesis, and final model. Fresh descendants default to the smaller DeepSeek V4 Flash model; after a descendant delegates, the same participant contract can use the synthesis tier when integrating its subtree. To use Kimi K3 everywhere, pass its Fireworks model name to `--research-model` as well.

A research-grade fixture is included:

```bash
PYTHONPATH=src python -m seam_harness solve \
  tasks/research-adaptive-communication.json \
  --workspace research-kb-workspace \
  --output outputs/research-note.md \
  --runs-dir runs \
  --max-adaptive-steps 14
```

A deterministic wiring smoke test makes no external requests:

```bash
PYTHONPATH=src python -m seam_harness solve \
  examples/idempotency_service/spec.json \
  --workspace examples/idempotency_service/workspace \
  --test-model \
  --runs-dir /tmp/seam-harness-runs
```

`TestModel` validates wiring only; its content is meaningless.

## Queryable shared knowledge

Questions and answers are separate addressable objects with many-to-many mappings and typed question-question, answer-question, and answer-answer links. Models do not receive the whole graph. They get a digest and compact summary, then search questions, search answers, open threads or neighbors, and pull bounded source excerpts. Every query and returned ID is audited against the immutable snapshot used by that call.

The runtime freezes parallel waves and validates IDs; models choose meaningful questions, reformulate searches, interpret analogies and conflicts, and decide whether a result changes the inquiry. This division deliberately exploits model adaptability instead of turning research judgment into a brittle rules engine.

`text_statistics` is the only default verification adapter. `pytest` executes existing workspace code; `python_checker` executes bounded model-authored code. Both require explicit `--enable-experiment-adapter` permission, and `python_checker` is auditable but not a security sandbox.

## Audit and post-mortem

```bash
PYTHONPATH=src python -m seam_harness inspect runs/<run-id>
PYTHONPATH=src python -m seam_harness postmortem runs/<run-id> --format json
```

Every model call records its public dossier, model, role, input digest, typed output or error, timing, and provider usage. Adaptive runs additionally record knowledge queries, rejected participant turns, natural posts and their complete read sets, seam signals, verification artifacts, operational failures, graph commits, participant depth, and action records with before/after snapshot digests and read/write entry IDs. The post-mortem reconstructs the action DAG deterministically. The local hash chain is tamper-evident, not externally signed.

There is no chat UI yet. The CLI intake pass is the natural-language front door. A future UI should be harness-aware: conversational intake, visible freeze, live action/cost status, forum browsing, and whole-run post-mortem. Exposing one internal agent as a chat page would bypass the orchestration and visibility boundaries.

## Project map

- `docs/design.md` — original seam-discovery design and implementation decisions
- `docs/adaptive-harness.md` — adaptive action loop, forum retrieval, experiments, audit, and limits
- `docs/recursive-solver.md` — fixed recursive comparator
- `docs/operations.md` — task submission and audit workflow
- `src/seam_harness/adaptive.py` — recursive participant and action-DAG scheduler
- `src/seam_harness/adaptive_agents.py` — the shared participant contract and presentation-only finalizer
- `src/seam_harness/adaptive_models.py` — KnowledgePost, ParticipantTurn, verification, retrieval, and result contracts
- `src/seam_harness/knowledge_tools.py` — snapshot-scoped forum and source queries
- `src/seam_harness/experiments.py` — permissioned experiment adapters
- `src/seam_harness/recursive.py` — shared evidence/graph layer and recursive comparator
- `src/seam_harness/journal.py` — immutable stage records and hash chain
- `tasks/research-adaptive-communication.json` — research-level stress test
- `tests/` — contracts, visibility, feedback, persistence, audit, and smoke tests

## Current boundary

The adaptive path can query sources and run registered verification adapters, but it emits a text artifact and does not apply code patches. Its retrieval index is lexical and run-local. Runtime validation catches invalid identities, permissions, and visibility—not poor research taste. The harness cannot manufacture external evidence where none exists. See `docs/adaptive-harness.md` for the precise architecture and limits.
