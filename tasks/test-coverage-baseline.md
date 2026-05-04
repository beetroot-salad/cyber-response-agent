---
title: Use pytest-cov to drive coverage decisions (baseline 87%)
status: doing
groups: testing, code-quality
---

`pytest-cov` is installed (dev extra). Coverage is **opt-in** — the default
`pytest` invocation does not measure coverage, and CI does not enforce a
floor.

## Baseline

First full-suite measurement (2026-05-02, post easy-win cleanup):

```
soc-agent/.venv/bin/pytest soc-agent/tests/ -m "not llm" \
    --cov=soc-agent --cov-report=term-missing --cov-report=json:/tmp/coverage.json
```

Result: **87% line coverage** across 24,550 lines, 3,110 uncovered. This
number was **misleading**: hooks/CLIs that tests exercise via `subprocess`
were untracked. With subprocess coverage enabled (see "Subprocess coverage"
below) the baseline jumps significantly. Any decision on a floor should be
made against the post-fix re-baseline, not against this number.

## Subprocess coverage (2026-05-04)

Pre-fix, the largest "uncovered" files were almost all subprocess-driven —
`infer_state.py` showed 19% coverage despite 34 tests exercising it via
`subprocess.run`. With the shim wired up, `infer_state.py` measured 90%,
`resolve_imports.py` 93%. Expect comparable jumps for the other subprocess-
heavy modules (`validate_report*`, `setup_run`, `wazuh_cli`, `host_query`,
`ticket_context`, the `invlang` CLI, etc.) on the next full re-baseline.

How it's wired:
- `pyproject.toml` `[tool.coverage.run]` sets `parallel = true` and lists
  `source = ["hooks", "schemas", "scripts"]`. The earlier
  `source = ["soc-agent"]` was broken — coverage treats `source` as
  importable package names, and `soc-agent` (with a hyphen) is not.
- `tests/conftest.py` writes a `coverage_subprocess.pth` file into the
  venv's site-packages on first import and points
  `COVERAGE_PROCESS_START` at the project's `pyproject.toml`. Every
  child Python under that venv now starts coverage automatically.
- The `.pth` exits cheaply when `COVERAGE_PROCESS_START` is unset, so
  normal `pytest` runs (no `--cov`) pay no subprocess overhead.

Recommended invocation post-fix:

```
.venv/bin/pytest tests/ -m "not llm" \
    --cov --cov-report=term-missing --cov-report=json:/tmp/coverage.json
```

Drop `--cov=soc-agent`; let the config-defined `source` apply.

## Suggested follow-ups (do not enforce yet — investigate first)

1. **Identify the long tail.** Sort `/tmp/coverage.json` by uncovered-line
   count per file. Anything > 20% uncovered in a non-test, non-script module
   is a candidate for either more tests or deletion.
2. **Distinguish "untested" from "untestable".** If a module is hard to test
   (heavy I/O, no seam), the right fix is a refactor (extract pure functions)
   not a fixture. Cross-reference the mock-usage allowlist
   (`soc-agent/tests/.mock_allowlist`) — files that need mocks today are
   often the same files with low coverage.
3. **Decide on a floor.** Once the long tail is investigated, set
   `--cov-fail-under=N` where N is `current - 2%` (don't pick a round number;
   ratchet up). Add the flag to the CI `test` step.
4. **Branch coverage.** Switch from `--cov` (line) to `--cov-branch` once
   line coverage stabilizes — branch is stricter and catches missed
   else-paths. Re-baseline.

## Anti-patterns to avoid

- Don't chase 100% coverage — it produces tests that exercise lines without
  asserting behavior.
- Don't add tests just to cover defensive `except` blocks that can't fire in
  practice — those are candidates for deletion (see the project's
  "no validation for scenarios that can't happen" rule).