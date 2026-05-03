---
title: Drive mypy from soft-launch to hard gate
status: backlog
groups: lint, typing, code-quality
---

`mypy` was wired into CI (`code-smells` job, non-blocking) with a permissive
config:

```toml
[tool.mypy]
python_version = "3.11"
files = ["soc-agent"]
exclude = ["soc-agent/tests/", "soc-agent/.venv/"]
ignore_missing_imports = true
follow_imports = "silent"
check_untyped_defs = true
warn_unused_ignores = true
warn_redundant_casts = true
```

## Plan

1. Run mypy locally and capture the current count of errors per module.
   Stash a baseline so per-PR drift can be measured.
2. Fix the easy classes first: missing return-type annotations on top-level
   functions, `dict[str, Any]` vs untyped `dict`, `Optional[X]` → `X | None`
   (ruff `UP045` will help).
3. Add narrow type aliases in `schemas/` for the recurring envelope shapes
   (manifest entry, lead dict, hypothesis dict, alert dict). These will
   propagate type info through the orchestrator without annotating every
   call-site.
4. Once a directory is clean, add it to a **strict** mypy config block
   (`[[tool.mypy.overrides]] module = "scripts.handlers.*" disallow_untyped_defs = true`).
5. When all of `soc-agent/` is strict-clean, promote the mypy step from the
   `code-smells` job to the hard `lint` job in `.github/workflows/ci.yml`
   (drop the `|| true`).

## Files most likely to need typing love

- `scripts/orchestrate.py` — central dispatcher, lots of dict-passing
- `scripts/handlers/*.py` — heavy use of Any-typed payloads
- `scripts/invlang/queries_*.py` — corpus types are partially Any
