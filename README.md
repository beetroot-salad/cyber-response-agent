# soc-agent

This repository centers on `soc-agent`, a hypothesis-driven security alert triage agent built as an applied AI / systems engineering project.

The core idea is simple: do not let an LLM "wing it" through an investigation. Instead, drive the workflow through explicit phases, persist state on every transition, validate structured outputs, and evaluate prompt changes against labeled cases before landing them.

## What This Project Contains

- `soc-agent/`: main implementation, hooks, handlers, schemas, tests, and knowledge base
- `evals/`: prompt and parser evaluation harnesses, bake-offs, and scoring scripts
- `playground/` and `playground-v2/`: security lab scenarios and local simulation assets
- `infra/`: environment and infrastructure setup
- `runs/`: captured investigation runs and experiment outputs
- `tasks/`: design notes, backlog items, and implementation history

## Core Workflow

The main investigation loop is orchestrated as a state machine:

- `CONTEXTUALIZE`
- `SCREEN`
- `PREDICT`
- `GATHER`
- `ANALYZE`
- `REPORT`

The orchestrator persists `state.json` on each phase transition and stops on illegal transitions or loop-cap violations. Production handlers live under `soc-agent/scripts/handlers/`.

## Highlights

- Explicit orchestration instead of a single monolithic prompt
- Structured phase contracts with parser and validator enforcement
- Run artifacts written to disk for replay and auditability
- Custom investigation-language tooling (`invlang`) for corpus analysis and recall
- Prompt-evaluation harnesses with documented postmortems, not just ad hoc tweaking
- Broad automated test coverage, including structural, end-to-end mock, and LLM-gated test paths

## Quick Start

From the repository root:

```bash
uv venv
uv pip install -e "soc-agent[dev]"
export SOC_AGENT_RUNS_DIR=/workspace/runs
```

If you want to use the live investigation path, you will also need:

- `claude` CLI installed and authenticated
- configured adapters under `soc-agent/scripts/tools/`
- signature knowledge under `soc-agent/knowledge/signatures/`

## Sanity Checks

Run the non-LLM test suite used by CI:

```bash
uv run pytest soc-agent/tests/ -v -m "not llm"
```

Run a smaller structural slice:

```bash
uv run pytest soc-agent/tests/test_state_transitions.py soc-agent/tests/test_e2e_mock.py -q -m "not llm"
```

Validate the current environment:

```bash
uv run python soc-agent/scripts/preflight.py --json
```

If you are only checking repository knowledge and do not have live systems connected yet:

```bash
uv run python soc-agent/scripts/preflight.py --kb --json
```

## Running The Orchestrator

The main driver is:

```bash
uv run python soc-agent/scripts/run_orchestrator.py <signature_id> '<alert_json>'
```

Notes:

- `SOC_AGENT_RUNS_DIR` must be set
- the alert must be a JSON object with a top-level `id`
- live runs depend on configured knowledge, handlers, and external tools

Each run starts with at least:

- `alert.json`
- `meta.json`
- `state.json`

Investigation runs may also produce:

- `investigation.md`
- `report.md`
- budget and audit artifacts under the run directory

## Investigation Language (`invlang`)

`invlang` is a local query tool for mining prior investigation runs as a structured corpus.

Examples:

```bash
uv run python soc-agent/scripts/invlang/cli.py --enumerate hypotheses
uv run python soc-agent/scripts/invlang/cli.py --class 8 --top 10
uv run python soc-agent/scripts/invlang/cli.py --class 9 --reversals-only
```

This is one of the more distinctive parts of the project: the system does not only run investigations, it also builds machinery to analyze how those investigations behave over time.

## Evaluation Work

Prompt and output-shape experiments live under `evals/predict/`.

Useful starting points:

- `evals/predict/BAKEOFF.md`
- `evals/predict/cases/README.md`
- `evals/predict/postmortems/final-decision.md`

Those files document variant comparisons, scoring criteria, regressions, and decisions about what not to ship.

## Repository Notes

This repository is intentionally broader than a single package. The portfolio-quality implementation is primarily inside `soc-agent/`, while the surrounding directories capture the evaluation, lab, and operational context that the agent was built against.

If you want one place to start reading code, start here:

- `soc-agent/scripts/orchestrate.py`
- `soc-agent/scripts/handlers/`
- `soc-agent/hooks/scripts/`
- `soc-agent/tests/`
