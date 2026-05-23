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
  learning/            # offline learning loop (actor, oracle, judge, verify, author)
  lessons/             # curator-authored pitfall lessons (empty until v2 loop authors them)
  lessons-actor/
  fixtures/            # alert.json inputs (currently v1-flavored)
  run-visualizations/
  run-transcripts/     # curated past-run transcripts (if present)
  tests/               # learning-loop invariants
  docs/                # design rationale (learning-loop, system-skill-shape, experiment notes)
```

Per-system reference (`skills/{wazuh,host-query,stub-cmdb,stub-iam}/`), gather query packs for those systems, the wazuh env-systems dir, and the v1 adapter CLIs (`scripts/tools/*.py`) were removed with the v1-strip commit; v2-flavored replacements will land in the same paths as they're authored.
