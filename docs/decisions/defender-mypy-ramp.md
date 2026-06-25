---
title: Defender mypy type-check — now a blocking gate; ramp continues
status: todo
groups: defender, typing, code-quality
---

**Shipped (issue #403).** mypy is a **blocking** gate in CI's `lint` job — the
tree is at **zero errors** under this config, so a new type error fails CI:

```yaml
- name: Mypy (type-check — hard gate)
  run: defender/.venv/bin/mypy --config-file defender/pyproject.toml
```

It launched as a non-blocking `code-smells` signal, then graduated to the
blocking gate above once the errors were driven to zero (same path the extended
ruff families took, #400). Config is the `[tool.mypy]` block in
`defender/pyproject.toml`. This re-files `tasks/typing-mypy-soft-launch.md`,
whose `soc-agent`-scoped config was dropped in the collapse; the intent
(soft-launch → incremental hardening → promote to a hard gate) is retained,
repointed at `defender/`.

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

## Baseline at soft-launch (2026-06-23) → zero (2026-06-24)

The launch baseline was `Found 78 errors in 21 files (checked 98 source files)`
(dev-only, the gate condition; 84 with the `runtime` extra synced — the extra 6
are `runtime/driver.py` pydantic-ai generics, invisible to the dev-only gate).
All were cleared in the promotion PR; the gate now reports
`Success: no issues found in 98 source files` under **both** conditions. For the
record, the launch errors concentrated:

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

1. ~~**Drain the `adapters/*_cli.py` cluster.**~~ **Done.** Added a typed
   `_stub_transport.http_get_obj() -> dict[str, Any]` accessor (asserts the
   response is an object, fails fast otherwise) and pointed the dict-shaped
   endpoints at it; list endpoints keep raw `http_get -> dict | list` + their
   guards. (`-> Any` on the loader was rejected — a black hole right as the gate
   went blocking.)
2. ~~**Clear the tail** — narrows, `importlib` `spec` asserts, the
   `name-defined`/`unused-ignore` cruft, and two real bugs the gate surfaced
   (an author-drain restore warning that fired on every success; a `subprocess.
   _RunFn` DI-seam type that doesn't exist).~~ **Done.**
3. ~~**Promote to the hard gate.**~~ **Done** — the step moved from `code-smells`
   to the blocking `lint` job (`|| true` dropped). The config stays permissive
   (no `disallow_untyped_defs`), so it blocks *new type errors*, not untyped
   defs.

**Remaining (future PRs):**

4. **Pin cleared subtrees strict.** Layer `disallow_untyped_defs` per module so
   regressions to untyped surface, bottom-up:

   ```toml
   [[tool.mypy.overrides]]
   module = "defender.scripts.adapters.*"
   disallow_untyped_defs = true
   ```

5. **Fold in tests.** Drop the test exclude (or override `tests.*` with relaxed
   flags); decide whether the duck-typed-fake pattern gets a typed fixture or a
   per-module `disable_error_code`.

**Spun off as design work** (band-aided to reach zero, tracked separately):

- **#409 — typed contracts for the dict-blob envelopes.** Most of the cleared
  `Any|None` narrows are symptoms of passing bare `dict` records (adapter
  responses, hypothesis/lead/query-row shapes) untyped. The `schemas/` step:
  TypedDict/dataclass contracts, starting with the adapter responses behind
  `http_get_obj`.
- ~~**#410 — unify `RunDeps`/`GatherDeps` modeling.**~~ **Done.** Main-vs-gather
  was split across an `is_main_session` bool *and* a subclass. `is_main_session`
  is now a derived `@property` (single source of truth: the deps type), and the
  capture path in `runtime/tools.py` narrows with `isinstance(deps, GatherDeps)`
  — so the `assert isinstance(...)` band-aid is gone and the redundant bool can
  no longer drift out of sync with the subclass.

**Done (this issue):** mypy runs in CI as a blocking gate over a zero-error
tree, with the ramp path documented above.
