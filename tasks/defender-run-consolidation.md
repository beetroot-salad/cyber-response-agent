---
title: Defender — consolidate run.sh + post-steps + learning loop into run.py
status: done
groups: defender, runtime, refactor
---

## Why

Three drags on iteration speed in the defender runtime:

1. **Projection lived in the prompt.** `run.sh` already owned post-steps
   (visualize_run.py), but `project_lead_sequence.py` was delegated to the
   model in the SKILL prompt. Every "agent forgot" or "agent crashed
   mid-REPORT" → run unusable for the learning loop.
2. **Duplicate `project_lead_sequence.py`.** Two copies (canonical in
   `defender/scripts/`, 38-line wrapper in `defender/learning/`) — no
   caller was using the wrapper after `loop.py` started shelling out
   to the canonical script with `--actor-out`.
3. **Brittle `gather_raw/{position}.lead.json` sidecar.** `gather/SKILL.md`
   asked the gather subagent to author it via a heredoc `cat > ... <<JSON`.
   When gather forgot, the projection silently degraded — `goal` collapsed
   to a kebab id and `what_to_characterize` went empty. Bad enough on its
   own, worse for the learning loop's actor projection.
4. **Inline `SETTINGS_JSON` heredoc in `run.sh`.** Permission tweaks
   required heredoc editing.

## What changed

- **New `defender/run.py`** — single entrypoint, replaces `run.sh`. Pipeline:
  materialize run dir → spawn `claude -p` → project lead_sequence → render
  transcript → (default) hand off to `learning.loop.run_one` in-process.
  Skip the learning step with `--no-learn`.
- **New `defender/run-settings.json`** — claude `--settings` template
  (permissions + the new PreToolUse hook). `${DEFENDER_DIR}` placeholder
  resolved at runtime by `run.py`.
- **New `defender/hooks/extract_lead_metadata.py`** — PreToolUse on `Task`.
  When the Task prompt references `defender/skills/gather/SKILL.md`, parses
  the fenced YAML dispatch block (`run_dir` / `position` / `goal` /
  `what_to_characterize`) and writes the sidecar before gather runs. The
  sidecar contract is now a structural side-effect of dispatching gather,
  not a prompt instruction the model can forget. Silent on parse failure
  (degraded projection > blocked dispatch).
- **`defender/SKILL.md`** — Task() snippet now uses the fenced YAML
  dispatch shape; REPORT no longer asks the agent to run the projection
  script (the harness owns that).
- **`defender/skills/gather/SKILL.md`** — heredoc instruction dropped;
  Inputs section now points at the dispatch YAML the hook materializes.
- **`defender/CLAUDE.md`** — directory layout, runtime overview, and run
  dir layout updated to `run.py`. Narrow exception added to the
  "no defender hooks" stance for harness-contract extraction shims.
- **Deleted:** `defender/run.sh`, `defender/learning/project_lead_sequence.py`.

## Tests

`defender/tests/test_extract_lead_metadata.py` — 7 cases covering the happy
path, position-with-suffix, dir auto-create, silent noop on non-Task /
non-gather / malformed YAML / missing required keys. Full defender suite
(38 tests) green.

## Follow-ups (not in this slice)

These came out of the same `slow down development` review and remain open:

- **Defender re-implements an invlang parser.** `L_BLOCK_RE` regex in
  `scripts/project_lead_sequence.py` should reuse
  `soc-agent/scripts/handlers/_dense_parser.py` so parser drift on the
  dense-language surface doesn't have two homes to track.
- **`parse_query_params` silently loses quoted/multi-word values.** With
  the sidecar now harness-owned, a richer `params` shape (lists, quoted
  strings) is reachable — extend the dispatch YAML and have the
  projection prefer sidecar params over the `:L` `query` cell.
- **PLAN-time lesson enumeration scales linearly.** Have `author.py`
  regenerate `defender/lessons/INDEX.md` on commit; PLAN reads just that.
- **Run-id collision under second-resolution timestamps.** Append a
  short random suffix in `run.py::materialize_run_dir`.
