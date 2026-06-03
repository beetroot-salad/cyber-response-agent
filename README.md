# defender

This repository centers on `defender/`, an exploratory alert-triage agent built around a **self-improving learning loop**.

The core bet: don't hand-tune a triage prompt forever. Run real alerts through a phase-disciplined investigation agent, then mine each run offline — an adversarial actor invents an attack story the run might have missed, a telemetry oracle synthesizes the events that story would have produced, a judge decides whether the investigation would have caught it, and a curator folds the surviving findings back into a checked-in lessons corpus the agent reads on its next run. The agent's job is to generate honest signal; the loop discovers what it should have known.

> **Status: experimental / PoC.** The learning loop is the headlining experiment. Runtime reliability gates (hooks, validators, judge gates) are deliberately out of scope until the loop proves itself end-to-end on real cases.

## What This Project Contains

- `defender/`: the runtime triage agent, its skills/adapters, and the offline learning loop
- `defender/learning/`: actor / oracle / judge / forward-check / author pipeline + eval harness + read-only frontend
- `defender/lessons/`: checked-in pitfall lessons authored by the loop, read by the agent at plan time
- `defender/fixtures/`: alert inputs used to drive runs
- `playground/` and `playground-v2/`: security lab scenarios and local simulation assets
- `soc-agent/`: a separate, earlier production-plugin track that shares some framings and adapters (not the focus of this README)

## Runtime Loop

A single agent works one alert through explicit phases:

- `ORIENT`
- `PLAN`
- `GATHER`
- `ANALYZE`
- `REPORT`

`GATHER` is dispatched to a cheap subagent (Haiku) per query; the main agent works from the summary and reads raw payloads on demand. The run emits three artifacts: `investigation.md` (the dense audit log), `lead_sequence.yaml` (the machine-readable contract the learning loop consumes), and `report.md` (disposition + one paragraph).

`defender/SKILL.md` is the spec for this loop. The on-disk shape and projection contract are documented in `defender/CLAUDE.md`.

## Learning Loop

After the runtime loop exits, `run.py` hands the run dir to the offline loop (skip with `--no-learn`):

1. **Normalize** disposition from `report.md` frontmatter (`benign | inconclusive | malicious`).
2. **Project** `lead_sequence.yaml` to an actor-facing view.
3. **Actor** (gray-box, adversarial) — given the alert, the lead set, an `internal`/`external` archetype, and a sampled MITRE ATT&CK technique menu, writes a candidate attack story citing the techniques it used.
4. **Telemetry oracle** — synthesizes the per-lead events that story would have produced, so the judge isn't grading its own imagination.
5. **Judge** — classifies the outcome (`caught | survived | undecidable | incoherent | skip-passthrough`) and emits findings.
6. **Forward-check gate** — re-runs each queued finding against the actor story to confirm it actually bites.
7. **Persist + queue** findings under `defender/learning/runs/`.
8. **Author** — once enough findings accumulate (`LEARNING_AUTHOR_THRESHOLD`, default 5), the curator folds them into `defender/lessons/*.md` and commits.

Lessons feed back in: at `PLAN` time the agent enumerates `defender/lessons/*.md` frontmatter and reads the bodies relevant to the current alert.

Design rationale lives in `defender/docs/` — start with `defender/docs/learning-loop.md` (the RL / evolutionary-algorithms framing the architecture borrows from). When a doc and the code disagree, the code wins.

## Quick Start

Defender has its own venv at `defender/.venv` (only runtime dep is `pyyaml`):

```bash
cd defender && uv venv .venv && uv pip install --python .venv/bin/python -e '.[dev]'
```

`run.py` re-execs into `defender/.venv/bin/python3`, so it works regardless of which python is on PATH.

Live runs additionally need the `claude` CLI installed and authenticated, plus the SIEM/host adapters reachable (see `defender/skills/{system}/SKILL.md`).

## Running The Agent

Investigate one alert end-to-end (runtime loop + post-steps + learning loop):

```bash
python3 defender/run.py <alert.json>
```

Notes:

- run dirs are created under `$DEFENDER_RUNS_BASE/{run_id}/` (default `/tmp/defender-runs/`), outside the repo
- pass `--no-learn` to skip the learning step while iterating on the runtime loop only
- the learning loop can also run standalone: `python3 defender/learning/loop.py <run_dir>`

Each run dir contains at least `alert.json`, `investigation.md`, `lead_sequence.yaml`, `report.md`, `tool_trace.jsonl`, `transcript.html`, and a `gather_raw/` directory of per-query payloads.

## Learning-Loop Frontend

A read-only posture view of the loop's current output:

```bash
python3 defender/learning/frontend/build.py
```

Writes a self-contained `lessons.html` showing the authored lesson corpora. See `defender/learning/frontend/README.md`.

## Tests

The runtime agent has no unit tests — it's evaluated by running real alerts and reviewing the run dir. `defender/tests/` covers learning-loop invariants (lesson schema, author pre/post-flight, atomic writes, forward-check):

```bash
cd defender && .venv/bin/python -m pytest tests/ -q
```

## Where To Start Reading

- `defender/SKILL.md` — the runtime agent spec
- `defender/CLAUDE.md` — on-disk contracts, run-dir layout, and a "where to make changes" map
- `defender/learning/loop.py` — the offline loop orchestrator
- `defender/docs/learning-loop.md` — design rationale
