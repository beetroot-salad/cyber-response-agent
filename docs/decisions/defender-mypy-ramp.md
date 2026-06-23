---
title: Defender mypy type-check — soft-launch signal, ramp to a hard gate
status: todo
groups: defender, typing, code-quality
---

**Shipped (issue #403).** mypy runs in CI's `code-smells` job as a
**non-blocking** soft signal:

```yaml
- name: Mypy (type-check — soft signal, non-blocking)
  run: defender/.venv/bin/mypy --config-file defender/pyproject.toml || true
```

Config is the `[tool.mypy]` block in `defender/pyproject.toml`. This
re-files `tasks/typing-mypy-soft-launch.md`, whose `soc-agent`-scoped
config was dropped in the collapse; the intent (soft-launch → incremental
hardening → promote to a hard gate) is retained, repointed at `defender/`.

## Posture

Soft-launch — surface type errors without blocking on every untyped def:

- `files = ["defender"]`, run from the **repo root** (matching the other
  `code-smells` steps), config pointed explicitly since there's no root
  `pyproject.toml` for mypy to discover.
- `mypy_path = "."` + `explicit_package_bases` + `namespace_packages` —
  `defender/` is a namespace tree (no top-level package; modules invoked by
  path; tests `sys.path.insert("..")` so imports resolve as `defender.*`).
  These give every file a unique dotted module name and dodge the
  duplicate-module crash a bare run hits on repeated leaf names
  (`conftest.py`, `_cli.py`, `__init__`-less dirs).
- `ignore_missing_imports` + `follow_imports = "silent"` — don't chase the
  unstubbed runtime/SIEM stack.
- `check_untyped_defs`, `warn_unused_ignores`, `warn_redundant_casts` — the
  permissive-but-useful middle.
- **Tests excluded** (`tests/`, `test_*.py`, `conftest.py`). They lean on
  duck-typed fakes — a bare `object()` passed where a typed deps struct is
  expected — that mypy can't see through (~200 such errors, mostly one
  repeated pattern). High-noise, low-value for a production-typing ramp;
  folding them in is a later ramp step (§Ramp step 4).

Local run (from the repo root):

```bash
defender/.venv/bin/mypy --config-file defender/pyproject.toml
```

## Baseline (2026-06-23, at soft-launch)

`Found 78 errors in 21 files (checked 98 source files)` — i.e. **77 of 98
shippable modules are already mypy-clean** under this config. The errors
concentrate:

| Cluster | Errors | Dominant code |
|---|---|---|
| `scripts/adapters/*_cli.py` (6 files) | 38 | `union-attr` |
| `learning/{eval_secondary,_loop_orchestrate,replay_actor,…}.py` | ~20 | `union-attr`, `arg-type` |
| `scripts/visualize/*.py` | ~8 | `arg-type`, `union-attr` |
| the rest (`run.py`, `runtime/observe.py`, `skills/invlang/queries.py`, …) | ~12 | mixed |

By code: `union-attr` 47, `arg-type` 15, then a long tail
(`unused-ignore` 3, `assignment` 3, `name-defined` 2, `index` 2, …).

The `union-attr` mass is one shape: the adapter CLIs load a JSON fixture
typed `dict[Any, Any] | list[Any]` from a shared loader, then `.get()` on
it — `list` has no `.get`. The fix is a narrow at the load boundary (give
the loader a precise return type, or `cast`/`isinstance`-narrow each
record), which clears the whole `adapters/*_cli.py` cluster at once. That's
the obvious first batch.

## Ramp

Each step is a small, reviewable PR. The signal is non-blocking throughout,
so a step never breaks CI — it just shrinks the report.

1. **Drain the `adapters/*_cli.py` cluster** (~38 errors). Type the shared
   fixture-loader boundary; the `union-attr` mass falls out.
2. **Clear the easy tail** — missing return annotations, `var-annotated`,
   `name-defined`, stale `# type: ignore` (the `unused-ignore` hits).
3. **Pin each cleared module strict.** Once a module (or subtree) is
   error-free, lock it so it can't regress, even while the global signal
   stays soft:

   ```toml
   [[tool.mypy.overrides]]
   module = "defender.scripts.adapters.*"
   disallow_untyped_defs = true
   ```

   Add overrides bottom-up as subtrees clear (`runtime.*`, `learning.*`, …).
   A regression in a pinned module then shows as a *new* error in the soft
   report — the ratchet, without a checked-in baseline file.
4. **Fold in tests.** Drop the test exclude (or override `tests.*` with
   relaxed flags). Decide whether the duck-typed-fake pattern gets a typed
   fixture or a per-module `disable_error_code`.
5. **Promote to the hard gate.** When `defender/` is strict-clean, move the
   step from `code-smells` to the blocking `lint` job in
   `.github/workflows/ci.yml` and drop the `|| true` — the same graduation
   the extended ruff families went through (issue #400).

**Done (this issue):** mypy runs in CI with a documented ramp path — ✓. The
steps above are follow-up work, tracked from here.
