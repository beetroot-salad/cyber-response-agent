---
title: Clean up extended-ruff backlog (215 issues across 9 rule families)
status: backlog
groups: lint, code-quality
---

After the easy auto-fixes (ruff `--fix` cleared 197), the soft-launched
extended ruleset still reports **215 issues**. CI surfaces them in the
`code-smells` job (non-blocking) until this backlog is drained, at which
point the rule(s) can be promoted into the hard `lint` job.

## Current breakdown

| Count | Rule | Description | Notes |
|---:|---|---|---|
| 78 | C901 | mccabe complexity > 10 | Real refactor work — break long functions; biggest offenders are in handlers/ and orchestrate.py |
| 46 | PT018 | composite assertion in tests | `assert a and b` → split into two asserts (mostly mechanical) |
| 18 | PLR0912 | too-many-branches | Often pairs with C901 — fix together |
| 10 | SIM105 | suppressible exception | `try: ...; except X: pass` → `contextlib.suppress(X)` |
| 10 | SIM117 | nested with-statements | Combine into one `with a, b:` |
|  9 | B905 | `zip()` without `strict=` | Add `strict=True` (or `=False` if length divergence is intentional) |
|  8 | PLR0913 | too-many-arguments (>8) | Consider dataclass/typeddict for the param bag |
|  8 | PT012 | pytest.raises with multi-statement body | Move setup outside the `with` block |
|  6 | PLR0915 | too-many-statements | Pairs with C901 |
|  4 | B007 | unused loop control variable | Rename to `_` |
|  4 | B904 | `raise X` inside `except` without `from` | Add `from err` or `from None` |
|  4 | SIM102 | collapsible-if | Combine nested `if a: if b:` |
|  2 | B023 | function uses loop variable | Real bug pattern — needs case-by-case fix |
|  2 | PT006 | parametrize names wrong type | Mechanical |
|  2 | PT011 | pytest.raises too broad | Add `match=` |
|  1 | SIM115 | open() outside context manager | Wrap in `with` |
|  1 | SIM118 | `key in dict.keys()` | Drop `.keys()` |
|  1 | UP028 | `for x in y: yield x` | → `yield from y` |
|  1 | UP042 | str-enum class | Use `enum.StrEnum` |

## Suggested order

1. **One-line mechanical fixes first** (B007, B904, B905, PT006, SIM102, SIM105, SIM117, SIM118, UP028, UP042) — drop ~50 issues in a focused PR.
2. **Test-style sweep** (PT011, PT012, PT018) — touches only `soc-agent/tests/`, ~56 issues.
3. **Complexity refactors** (C901, PLR0912, PLR0915) — one module per PR. Largest hot-spots: `scripts/handlers/report.py`, `scripts/orchestrate.py`, `scripts/handlers/analyze.py`. Use `radon cc soc-agent -nb` output from the `code-smells` job to prioritize.
4. **Param-bag refactors** (PLR0913) — usually a `dataclass` extraction; touches call-sites, do per-function.

## Promoting rules to the hard gate

Once a rule family has zero violations, move it from `extend-select` (reported)
to `select` (blocking) in `soc-agent/pyproject.toml` `[tool.ruff.lint]`, and
add the same rule to the `--select` list in CI's hard-gate `Ruff` step in
`.github/workflows/ci.yml`.
