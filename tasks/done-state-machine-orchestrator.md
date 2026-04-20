---
title: State-machine orchestrator skeleton + implementation skill
status: done
groups: state-machine-migration, state
---

Baseline for the migration away from the prompt-driven investigation loop in `skills/investigate/SKILL.md` toward a Python-driven state machine that dispatches subagents per phase.

Landed:

- `soc-agent/scripts/orchestrate.py` — skeleton orchestrator: `run(ctx, handlers)` drives phase transitions, validates each move against `schemas/state.py`, persists `state.json`, enforces `MAX_LOOPS`, raises `OrchestrationError` on illegal moves or missing handlers. Phase handlers are stubs at this stage — real `claude --print` subagent dispatch comes in the per-phase migration tasks.
- `soc-agent/tests/test_orchestrate.py` — covers happy paths (SCREEN match, single-cycle, two-cycle, dedup short-circuit, GATHER→HYPOTHESIZE re-entry), failure modes (illegal transition, missing handler, loop cap forces CONCLUDE), and state-persistence invariants.
- Implementation skill documenting the migration approach and per-phase handler contract.

With the skeleton locked in, each phase can be migrated independently: swap the SKILL.md prompt section for an orchestrator handler that shells out to the existing subagent and returns a `PhaseResult(next_phase, payload)`.
