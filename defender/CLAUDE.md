# defender/ (on `defender-v2-env`)

This is the v2 worktree. Branch context, porting model, and push-guard live in `/workspace/CLAUDE.md` §"Defender v2 environment worktree". Full defender design + learning-loop walkthrough lives in `defender/CLAUDE.md` on `main` — cherry-pick or `git show main:defender/CLAUDE.md` if you need it. This file is a directory index only.

```
defender/
  SKILL.md             # runtime agent entry point (ORIENT/PLAN/GATHER/ANALYZE/REPORT)
  CLAUDE.md            # this file
  run.py               # entrypoint: investigate one alert end-to-end
  run-settings.json    # claude --settings template (permissions + extract_lead_metadata hook)
  pyproject.toml       # defender venv deps (uv-managed at defender/.venv)
  uv.lock
  hooks/               # PreToolUse hooks (extract_lead_metadata, ...)
  skills/
    invlang/           # invlang block surface (schema + author-side CLI)
    gather/            # gather subagent + per-system query templates (v2 systems pending)
    advisory/          # advisory skill
  scripts/             # project_lead_sequence, run_stats, visualize_*, lint_*
                       # NOTE: scripts/tools/ (adapters) deleted with v1-strip; v2 adapters TBD
  learning/            # offline learning loop — two directions off the disposition
                       #   loop.py             # run_one dispatch: benign disp → adversarial,
                       #                        #   malicious → benign (FP), inconclusive → both
                       #   footprint.md        # oracle stage A: LLM enumerates the attack's telemetry footprint
                       #   _oracle_router.py   # oracle stage B: deterministic containment routing -> projections/uncovered
                       #   --- adversarial (false-negative) direction ---
                       #   actor.md            # red-team actor (MITRE-sampled attack story)
                       #   judge.md            # caught|survived|… ; defender_findings + actor_observations
                       #   author_actor.md/.py # curate actor_observations → lessons-actor/
                       #   verify_forward_actor.{md,py}  # Haiku forward-check
                       #   --- benign (false-positive) direction ---
                       #   actor_benign.md     # ops-teamer actor (routine-op story; retrieves env lessons)
                       #   judge_benign.md     # survived ⇒ FP ; defender_findings + environment_observations
                       #   author_actor_benign.{md,py}   # curate env observations → lessons-environment/
                       #   verify_forward_env.py         # deterministic retrieval forward-check
                       #   --- shared ---
                       #   author.{md,py}      # defender_findings (both directions) → lessons/, direction-gated
                       #   _author_shared.py   # repo lock + per-direction generation counters
                       #   _pending/           # findings.jsonl, actor_observations.jsonl, environment_observations.jsonl
  lessons/             # curator-authored defender pitfall lessons (empty until v2 loop authors them)
  lessons-actor/       # actor-tradecraft lessons (adversarial direction)
  lessons-environment/ # standing deployment facts the benign actor retrieves (FP direction)
  fixtures/            # alert.json inputs (currently v1-flavored)
  run-visualizations/
  run-transcripts/     # curated past-run transcripts (if present)
  tests/               # learning-loop invariants
  docs/                # design rationale (learning-loop, system-skill-shape, experiment notes)
```

Per-system reference (`skills/{wazuh,host-query,stub-cmdb,stub-iam}/`), gather query packs for those systems, the wazuh env-systems dir, and the v1 adapter CLIs (`scripts/tools/*.py`) were removed with the v1-strip commit; v2-flavored replacements will land in the same paths as they're authored.
