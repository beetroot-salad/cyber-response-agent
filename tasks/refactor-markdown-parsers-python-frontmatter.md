---
title: Refactor hand-rolled markdown/frontmatter parsers to python-frontmatter + markdown-it-py
status: doing
groups: robustness, refactor
---

Roughly seven places in the codebase manually slice markdown files to get YAML frontmatter or fenced YAML blocks or GFM table rows. Each is a tiny custom parser with its own subtle edge cases. Consolidating onto `python-frontmatter` (for frontmatter-vs-body split) and `markdown-it-py` (for AST walks, fenced blocks, tables) would delete ~100 lines of string slicing + three regex patterns, and gain tolerance for things our hand-rolled code silently mishandles (BOMs, indented fences, tilde fences, escaped pipes in table cells, trailing whitespace after `---` delimiters).

## Call sites to migrate

Frontmatter (`---\n...\n---` at file start):
- `soc-agent/hooks/scripts/frontmatter.py::parse_yaml_frontmatter` — used by `validate_report.py`, `validate_conclude.py`, `setup_run.py`, `conclude.py::_load_required_anchors`. Swap implementation to `python-frontmatter`; signature stays the same.
- `soc-agent/scripts/handlers/conclude.py::_load_required_anchors` — currently does its own `---` slicing, should call the shared helper after #1 is migrated.

Fenced YAML block extraction:
- `soc-agent/scripts/handlers/_subagent.py::extract_terminal_yaml` — finds the *last* ```yaml block in subagent stdout.
- `soc-agent/scripts/handlers/screen.py::_extract_prologue_yaml` — finds the ```yaml block that contains `prologue:` in investigation.md.
- `soc-agent/scripts/handlers/contextualize.py::_extract_yaml_block` — generic fenced-YAML extraction.

GFM table walking:
- `soc-agent/scripts/handlers/screen.py::_load_screen_rows` — regex-parses the playbook's `## Screen` table. Swap to `markdown-it-py` with GFM table plugin.
- `soc-agent/scripts/handlers/contextualize.py::_ARCHETYPE_ROW_RE` — extracts archetype names from the `## Archetypes` table rows.

## What this fixes

Structural edge cases only:
- UTF-8 BOM at file start
- Trailing whitespace after `---` frontmatter delimiter
- Fence variants: ```` vs ``` vs ````` vs ~~~ vs indented fences
- Fence info string with extra tokens (` ```yaml linenums=1`)
- Escaped pipes inside GFM table cells (`\|`)
- Missing-frontmatter graceful handling (currently inconsistent across call sites)

## What this does NOT fix

LLM-emitted YAML inside a fenced block with malformed content (e.g., the ticket-context colon bug — `'5710': sshd: Attempt to login...` where Haiku dropped the value quoting). A markdown parser extracts the body cleanly; `yaml.safe_load(body)` still raises. Hardening against that class requires one of: (a) mechanical CLI pass-through (don't let LLM retype structured data), (b) schema-level post-parse validation, (c) narrow YAML repair pass on failure. File those separately; they're orthogonal to this refactor.

## Estimate

1-2 hour focused refactor:
1. Add `python-frontmatter` and `markdown-it-py` (+ GFM plugin) to `soc-agent/pyproject.toml` deps.
2. Rewrite `hooks/scripts/frontmatter.py` implementation; keep `parse_yaml_frontmatter` signature stable so callers don't change.
3. Rewrite the three fenced-block extractors to walk the AST.
4. Rewrite `_load_screen_rows` + the archetype row regex on `markdown-it-py`.
5. Existing unit tests should pass unchanged. Add two edge-case tests (BOM, tilde fence) to lock in the new tolerance.

## Priority

Low / quality-of-life. No observed failures of the structural parsers at time of filing (2026-04-21). Worth doing before adding a fourth hand-rolled markdown parser.