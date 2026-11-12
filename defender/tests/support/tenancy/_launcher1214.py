"""#1214 (r8 Flow 4): the TEST-SIDE launcher for subprocess tests of the host entry points.

Production entry points build their `TenantDirectory` from `DEFENDER_DATABASE_DSN`. A subprocess test that
needs a working tenant runs this module instead of `python run.py` / the drain / the connect command; it builds
the directory from what the TEST controls and calls the entry function with `directory=`. Nothing here is
production code and the production entries are not wrapped: the same function runs, with the one seam used.

    python -m defender.tests.support.tenancy._launcher1214 [options] run|drain|connect|visualize_run|workspace_map|retire_legacy_runs [--] <argv for the entry>

Entries (argv exactly as the production command line takes it, exit status passed through):
- `run`     -> `defender.run.main(argv, directory=...)`
- `drain`   -> `defender.learning.core.cli.main(argv, directory=...)`
- `connect` -> `defender.cli.tenant.main(argv, directory=...)`   (pinned by GAP-Rm-2: `cli.tenant.main(argv, *,
  directory=None)`)
- `visualize_run` -> `defender.presentation.visualize_run.main(["visualize_run.py", *argv], directory=...)` (its `main`
  takes `sys.argv`, program name first; r10 A1: it admits its tenant). The script's own `__main__` logging setup is NOT
  run here: a test of what the script logs runs the real script under PostgreSQL instead
- `workspace_map` -> `defender.cli.workspace_map.main(["workspace_map.py", *argv], directory=...)` (program name first)
- `retire_legacy_runs` -> `defender.cli.retire_legacy_runs.main(argv, directory=...)`
- `lessons_page` -> `defender.cli.learning.lessons_page.main(argv, directory=...)` (r10.1 A1/C1: the page builder admits
  its tenant, then builds)

Directory (give one; `--dsn` wins over `--seed` when both are given):
- `--dsn DSN` (env `DEFENDER_TEST_DSN`): `_active1214.postgres_directory(DSN)`, over rows the test inserted with
  `_active1214.insert_active_tenant(...)` into a `migrated_database`.
- `--seed TENANT[:STATE[:ORIGIN]]` (repeatable; env `DEFENDER_TEST_SEED`, comma separated): an in-memory directory
  holding each tenant in STATE (default `active`) with forge wiring `tenants/<T>` and ORIGIN (default: the folder's
  own `origin` remote under `--data-root`, else `http://forge.test/tenants/<T>.git`). A STATE other than `active`
  is how a subprocess test reaches the refusal side. Seeded rows live only in this process.
- `--data-root DIR` (env `DEFENDER_DATA_ROOT`, which the entry reads itself): where origins are read from.

With neither `--dsn` nor `--seed` the directory is EMPTY: every tenant is unknown, the fail-closed side.

The subprocess never gets `DEFENDER_DATABASE_DSN` from this module (the production entry would build its
own directory from it); `environment()` strips it unless `keep_database_env=True`. It puts this checkout's root first
on `PYTHONPATH`, so `-m` finds this module (and this checkout's `defender`) whatever the caller's path or cwd.

From a test:

    from defender.tests.support.tenancy import _launcher1214 as launcher
    done = subprocess.run(launcher.command("run", argv, seed=[tenant]), env=launcher.environment(),
                          capture_output=True, text=True)
    # or over PostgreSQL:
    done = subprocess.run(launcher.command("drain", argv, dsn=migrated_database), ...)

Publish child. A launched `run` that spawns the publish child (`launch_publish`) starts it as a separate process,
which builds ITS directory from `DEFENDER_DATABASE_DSN` -- a `--seed` directory lives only in this process and cannot
cross. So a test of a run through the publish child uses `--dsn` AND gives the child's environment the address:

    done = subprocess.run(launcher.command("run", argv, dsn=dsn),
                          env=launcher.environment(_active1214.database_env(dsn)), ...)

`environment(database_env(dsn))` adds the address back after stripping the inherited one, so the launched process and
its publish child read the same rows. Minting needs a generation too: insert it with
`insert_active_tenant(dsn, T, generations=[provision_generation(...)])` (see `_active1214`).

Importing this module imports no production code (collection stays clean at base); `main` imports it at run time.
"""
from __future__ import annotations

import argparse
import importlib
import os
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

MODULE = "defender.tests.support.tenancy._launcher1214"
#: kind -> (module, function) of the entry it calls.
ENTRIES: dict[str, tuple[str, str]] = {
    "run": ("defender.run", "main"),
    "drain": ("defender.learning.core.cli", "main"),
    "connect": ("defender.cli.tenant", "main"),
    "visualize_run": ("defender.presentation.visualize_run", "main"),
    "workspace_map": ("defender.cli.workspace_map", "main"),
    "retire_legacy_runs": ("defender.cli.retire_legacy_runs", "main"),
    "lessons_page": ("defender.cli.learning.lessons_page", "main"),
}
#: The entries whose `main` takes `sys.argv` (the program name first), by that name.
PROGRAM_NAMES = {"visualize_run": "visualize_run.py", "workspace_map": "workspace_map.py"}
SEED_ENV, DSN_ENV, ROOT_ENV = "DEFENDER_TEST_SEED", "DEFENDER_TEST_DSN", "DEFENDER_DATA_ROOT"
_PRODUCTION_DSN_ENV = "DEFENDER_DATABASE_DSN"
#: The checkout root holding `defender/` (this file is `defender/tests/support/tenancy/_launcher1214.py`).
REPO_ROOT = Path(__file__).resolve().parents[4]


def command(kind: str, argv: Sequence[str], *, dsn: str | None = None, seed: Sequence[str] = (),
            data_root: Path | None = None, python: str | None = None) -> list[str]:
    """The argv a test hands `subprocess.run` (see the module doc). `seed` items are `TENANT[:STATE[:ORIGIN]]`."""
    out = [python or sys.executable, "-m", MODULE]
    if dsn is not None:
        out += ["--dsn", dsn]
    for item in seed:
        out += ["--seed", item]
    if data_root is not None:
        out += ["--data-root", str(data_root)]
    return [*out, kind, "--", *argv]


def environment(extra: Mapping[str, str] | None = None, *, keep_database_env: bool = False) -> dict[str, str]:
    """The current environment for the child, without `DEFENDER_DATABASE_DSN` (so the only directory is the one
    this launcher builds), plus `extra`, with the checkout root put first on `PYTHONPATH` (any path the caller or
    `extra` gives follows it)."""
    env = {k: v for k, v in os.environ.items() if keep_database_env or k != _PRODUCTION_DSN_ENV}
    env = {**env, **(extra or {})}
    env["PYTHONPATH"] = os.pathsep.join(p for p in (str(REPO_ROOT), env.get("PYTHONPATH", "")) if p)
    return env


def build_directory(*, dsn: str | None, seeds: Sequence[str], data_root: Path | None) -> Any:
    """The `TenantDirectory` the entry gets: PostgreSQL over `dsn`, else in-memory over `seeds`, else empty."""
    from defender.tests.support.tenancy import _active1214

    if dsn:
        return _active1214.postgres_directory(dsn)
    root = data_root or Path(os.environ.get(ROOT_ENV, "/nonexistent"))
    twin = _empty_twin()
    for item in seeds:
        tenant, _, rest = item.partition(":")
        state, _, origin = rest.partition(":")
        _seed(twin, root, tenant, state or "active", origin or None)
    from defender.tenancy import TenantDirectory

    return TenantDirectory(lambda: twin)


def _empty_twin() -> Any:
    from defender.tenancy import InMemoryTenantRepository

    return InMemoryTenantRepository()


def _seed(twin: Any, root: Path, tenant: str, state: str, origin: str | None) -> None:
    import asyncio
    import inspect

    from defender.tests.support.tenancy import _active1214

    added = twin.add_tenant(tenant, created_at=_active1214.CREATED, state=state, repo=f"tenants/{tenant}",
                            origin=_active1214._origin_of(root, tenant, origin))
    if inspect.isawaitable(added):
        asyncio.run(_active1214._await(added))
    _active1214.seed_twin(twin, tenant, _active1214.PLANTED_ALERT_MAPPING)  # #1345: today's mapping, as a seeded row
    _active1214.seed_twin_records(twin, root, tenant)  # #1366 R8: imported, from the tenant's planted settings


def main(argv: Sequence[str] | None = None, *, entries: Mapping[str, Callable[..., int]] | None = None) -> int:
    parser = argparse.ArgumentParser(prog=MODULE, description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--dsn", default=os.environ.get(DSN_ENV) or None)
    parser.add_argument("--seed", action="append", default=None)
    parser.add_argument("--data-root", type=Path, default=None)
    parser.add_argument("kind", choices=sorted(ENTRIES))
    parser.add_argument("entry_argv", nargs=argparse.REMAINDER)
    ns = parser.parse_args(argv)
    seeds = ns.seed if ns.seed is not None else [s for s in os.environ.get(SEED_ENV, "").split(",") if s]
    entry_argv = ns.entry_argv[1:] if ns.entry_argv[:1] == ["--"] else ns.entry_argv
    directory = build_directory(dsn=ns.dsn, seeds=seeds, data_root=ns.data_root)
    if entries is not None and ns.kind in entries:
        entry = entries[ns.kind]
    else:
        module, name = ENTRIES[ns.kind]
        entry = getattr(importlib.import_module(module), name)
    if ns.kind in PROGRAM_NAMES:
        entry_argv = [PROGRAM_NAMES[ns.kind], *entry_argv]
    return int(entry(list(entry_argv), directory=directory))


if __name__ == "__main__":
    sys.exit(main())
