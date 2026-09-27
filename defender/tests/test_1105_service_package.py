"""#1105 D1/D6/D7/D8 — the `defender/run_service/` package, `defender/host_env.py`, and the
values that must not move when the code does.

What an import LOADS is observed in a FRESH interpreter (`_spec1105.fresh_interpreter`): a test
process has already imported half the tree, so an in-process `sys.modules` check sees the
suite's history, not the import under test. What a module IMPORTS is observed by an AST scan of
the real tree, paired with a control the same scan flags. Values derived from a file's location
are compared with the value the base commit resolved — computed here from this checkout's own
layout (`DEFENDER`, `WORKTREE`, the `.git` pointer), never read back off `run_common`, which
`d1_old_paths_gone` requires to be gone.

RED against ed5386bc: `defender.run_service`, `defender.host_env` and `ResumeOpener` do not
exist; `run_common` and `runtime.branch` still import; `learning/frontend/build.py` takes its
CSS through the run page; nothing outside the service imports it yet.
"""
from __future__ import annotations

import ast
import contextlib
import importlib
import json
import os
import sys
from pathlib import Path

import pytest

from defender.tests import _spec1105 as S
from defender.tests import _triplet_947 as T
from defender.tests._by_path import WORKTREE

#: D1's public surface, name by name — the run lookup, the episode tool's checks and launch
#: (`start_family`, `sibling_argv`, `open_source_store`: the base names, kept — the merged
#: screen's own name is the implementer's, F11), `fence_count`, the run page, the family model,
#: the manifest schema and the one error.
PUBLIC = (
    "open_run", "list_run_ids", "bound_runs", "run_exists",
    "fence_count", "start_family", "sibling_argv", "open_source_store",
    "render_and_mirror",
    "Family", "World", "FamilyError", "BranchError", "episode_token_for",
    "parse_family", "load_family", "write_family", "check_identities", "parse_overlay",
    "Overlay", "ElasticEntry", "BASE_ROLE", "world_token_for", "is_reserved_world_label",
    "refuse_bad_episode_id", "PATCHABLE_SYSTEMS",
    "RunServiceError",
)
NOT_EXPORTED = ("BranchSpec", "fence_count_at", "source_session")


# ---------------------------------------------------------------------------------------
# D1 — the package and its surface
# ---------------------------------------------------------------------------------------


def test_1105_every_listed_public_name_imports_from_run_service():
    """each name on D1's public surface imports from `defender.run_service`: run lookup:
    `open_run`, `list_run_ids`, `bound_runs`, `run_exists`; the episode checks and launch,
    `fence_count` and the merged screen; `render_and_mirror`; the family model names and the
    manifest schema names; `RunServiceError` (an exception class).
    """
    svc = S.svc()
    missing = [name for name in PUBLIC if not hasattr(svc, name)]
    assert not missing, missing
    for exc_name in ("RunServiceError", "FamilyError", "BranchError"):
        exc = S.sym(exc_name)
        assert isinstance(exc, type), (exc_name, exc)
        assert issubclass(exc, Exception), (exc_name, exc)


def test_1105_branch_spec_fence_count_at_and_source_session_are_not_public():
    """`BranchSpec`, `fence_count_at` and `source_session` are not importable from
    `defender.run_service`. The positive control: `fence_count` is.
    """
    for name in NOT_EXPORTED:
        with pytest.raises(ImportError):
            exec(f"from defender.run_service import {name}", {})
    namespace: dict = {}
    exec("from defender.run_service import fence_count", namespace)
    assert callable(namespace["fence_count"])


_LAZY_PROBE = """
    import json, sys
    from defender.run_service import {first}
    def loaded_with(attr):
        return sorted(n for n, m in list(sys.modules.items())
                      if (n == "defender.run_service" or n.startswith("defender.run_service."))
                      and m is not None and attr in vars(m))
    print(json.dumps({{a: loaded_with(a) for a in ("Family", "open_source_store",
                                                  "render_and_mirror", "open_run")}}))
"""


def test_1105_importing_one_public_name_loads_only_its_submodule(tmp_path):
    """in a fresh interpreter, `from defender.run_service import open_run` leaves the
    family-model, fork/resume and run-page submodules unloaded in `sys.modules` (no loaded
    service module defines `Family`, `open_source_store` or `render_and_mirror`). Importing
    `Family` loads the family model without loading the run page.
    """
    lookup = S.last_json(S.fresh_interpreter(_LAZY_PROBE.format(first="open_run"),
                                             cwd=tmp_path))
    assert lookup["open_run"], lookup
    for attr in ("Family", "open_source_store", "render_and_mirror"):
        assert lookup[attr] == [], (attr, lookup)
    family = S.last_json(S.fresh_interpreter(_LAZY_PROBE.format(first="Family"),
                                             cwd=tmp_path))
    assert family["Family"], family
    assert family["render_and_mirror"] == [], family


def test_1105_old_import_paths_are_gone_and_run_py_stays(tmp_path):
    """importing `defender.runtime.branch` or `defender.run_common` raises `ModuleNotFoundError`
    in a fresh interpreter. The positive control: `defender.run_service` imports and
    `defender/run.py` exists (the service's CLI stays where `sibling_argv` and tests name it).
    """
    proc = S.fresh_interpreter("""
        import importlib, json
        out = {}
        for name in ("defender.runtime.branch", "defender.run_common", "defender.run_service"):
            try:
                importlib.import_module(name)
                out[name] = "imported"
            except Exception as e:
                out[name] = type(e).__name__
        print(json.dumps(out))
    """, cwd=tmp_path)
    got = S.last_json(proc)
    assert got["defender.runtime.branch"] == "ModuleNotFoundError", got
    assert got["defender.run_common"] == "ModuleNotFoundError", got
    assert got["defender.run_service"] == "imported", got
    assert (S.DEFENDER / "run.py").is_file()


def test_1105_lazy_package_lookup_of_an_unexported_or_misspelt_name(tmp_path):
    """the service package's lazy `__init__` answers only its public list: `from
    defender.run_service import BranchSpec` and a misspelt name raise `ImportError`,
    `hasattr(run_service, name)` is False for them, and `from defender.run_service import *`
    yields exactly the public names in `__all__` — every D1 name, none private.
    """
    proc = S.fresh_interpreter("""
        import json
        import defender.run_service as svc
        out = {"all": sorted(svc.__all__)}
        for name in ("BranchSpec", "open_runn"):
            try:
                exec(f"from defender.run_service import {name}", {})
                out[name] = "imported"
            except ImportError:
                out[name] = "ImportError"
            out["has_" + name] = hasattr(svc, name)
        ns = {}
        exec("from defender.run_service import *", ns)
        out["star"] = sorted(k for k in ns if k != "__builtins__")
        print(json.dumps(out))
    """, cwd=tmp_path)
    got = S.last_json(proc)
    for name in ("BranchSpec", "open_runn"):
        assert got[name] == 'ImportError', (name, got)
        assert got['has_' + name] is False, (name, got)
    assert got["star"] == got["all"], got
    assert set(PUBLIC) <= set(got["all"]), sorted(set(PUBLIC) - set(got["all"]))
    assert not [n for n in got["all"] if n.startswith("_")], got["all"]


def test_1105_render_and_mirror_imported_first_in_a_fresh_interpreter(tmp_path):
    """a fresh interpreter whose first import from the service is `render_and_mirror` exits 0:
    the existing `visualize_messages` and `visualize_data` import cycle does not break it
    (subprocess; author-P5 is the baseline).

    Phase-F null-stub triage: `callable(render_and_mirror)` alone is satisfied by ANY
    placeholder object (a do-nothing stand-in is trivially callable), so it could not tell
    the real function from a stub the import cycle never touched. `__name__` is a dunder a
    stand-in object does not carry, so pinning it keeps this a positive assertion about the
    REAL `render_and_mirror` surviving the import order, not just about something existing.
    """
    proc = S.fresh_interpreter(
        "from defender.run_service import render_and_mirror\n"
        "print(callable(render_and_mirror), getattr(render_and_mirror, '__name__', None))",
        cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    out = proc.stdout.strip().split()
    assert out[0] == "True", proc.stdout
    assert out[-1] == "render_and_mirror", proc.stdout


# ---------------------------------------------------------------------------------------
# O2 / D6 — who imports the service
# ---------------------------------------------------------------------------------------


def _module_package(path: Path) -> list[str]:
    rel = path.relative_to(WORKTREE).with_suffix("")
    parts = list(rel.parts)
    return parts if parts[-1] == "__init__" and parts.pop() is not None else parts[:-1]


def _service_imports(path: Path) -> list[tuple[str, list[str]]]:
    """Every import in `path` (module level, function bodies, `TYPE_CHECKING` blocks) that
    reaches `defender.run_service`, relative imports resolved against the file's package."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: list[tuple[str, list[str]]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                package = _module_package(path)
                base = package[: len(package) - (node.level - 1)]
                module = ".".join([*base, *([module] if module else [])])
            if module == S.SERVICE or module.startswith(S.SERVICE + "."):
                found.append((module, [a.name for a in node.names]))
        elif isinstance(node, ast.Import):
            found += [(a.name, []) for a in node.names
                      if a.name == S.SERVICE or a.name.startswith(S.SERVICE + ".")]
    return found


def _private_reaches(imports: list[tuple[str, list[str]]]) -> list[str]:
    bad: list[str] = []
    for module, names in imports:
        rest = [p for p in module[len(S.SERVICE):].split(".") if p]
        if any(p.startswith("_") for p in rest):
            bad.append(module)
        elif not rest:
            bad += [f"{module}.{n}" for n in names if n.startswith("_")]
    return bad


def _production_modules() -> list[Path]:
    skip = {"tests", ".venv", "__pycache__", "run_service", "node_modules"}
    return sorted(p for p in S.DEFENDER.rglob("*.py")
                  if not skip & set(p.relative_to(S.DEFENDER).parts)
                  and p != S.DEFENDER / "run.py")


def test_1105_no_production_module_outside_the_service_imports_its_private_submodules(tmp_path):
    """an AST scan of every production module outside `defender/run_service/` and
    `defender/run.py` finds imports from `defender.run_service` only of its public names, and no
    `defender.run_service._*` submodule — while learning, the judge and the episode tool DO
    import the service (they are its callers, so the scan is not vacuous). The positive control:
    the same scan flags a planted `from defender.run_service._x import y`.
    """
    violations: dict[str, list[str]] = {}
    importers: list[str] = []
    for path in _production_modules():
        imports = _service_imports(path)
        if imports:
            importers.append(str(path.relative_to(S.DEFENDER)))
        bad = _private_reaches(imports)
        if bad:
            violations[str(path.relative_to(S.DEFENDER))] = bad
    assert not violations, violations
    assert any(p.startswith("learning/") for p in importers), importers

    probe = tmp_path / "planted.py"
    probe.write_text("from defender.run_service._x import y\n", encoding="utf-8")
    assert _private_reaches(_service_imports(probe)) == ["defender.run_service._x"]


EXECUTING_RUN_ROOTS = ("runtime/driver", "runtime/tools", "hooks", "scripts/gather_tools")


def test_1105_no_executing_run_module_loads_the_run_service(tmp_path):
    """two checks show that the executing-run modules (`run_investigation`'s driver, tools, hooks
    and gather tools) never load `defender.run_service`: an AST scan of them finds no import of
    it; a fresh interpreter importing `defender.runtime.driver` has no `defender.run_service`
    entry in `sys.modules`. The positive control: importing `defender.run` does load it.
    """
    scanned = 0
    for root in EXECUTING_RUN_ROOTS:
        for path in sorted((S.DEFENDER / root).rglob("*.py")):
            scanned += 1
            assert not _service_imports(path), (path, _service_imports(path))
    assert scanned > 10, scanned
    probe = """
        import json, sys, importlib
        importlib.import_module(MODULE)
        print(json.dumps(sorted(n for n in sys.modules if n.startswith("defender.run_service"))))
    """
    driver = S.last_json(S.fresh_interpreter(
        probe.replace("MODULE", repr("defender.runtime.driver")), cwd=tmp_path))
    assert driver == [], driver
    run = S.last_json(S.fresh_interpreter(probe.replace("MODULE", repr("defender.run")),
                                          cwd=tmp_path))
    assert "defender.run_service" in run, run


def test_1105_executing_run_loads_host_env_lazily_at_call_time(tmp_path):
    """after an executing-run module calls `run_env`, `sys.modules` holds no
    `defender.run_service` module (subprocess). Whether `learning.core.config` loads stays as at
    base: it does not (measured at ed5386bc with `run_common.run_env`).
    """
    proc = S.fresh_interpreter("""
        import json, sys
        from pathlib import Path
        import defender.runtime.driver
        from defender.host_env import DEFENDER_DIR, run_env
        env = run_env(DEFENDER_DIR, Path(TMP) / "runs" / "r")
        print(json.dumps({
            "service": sorted(n for n in sys.modules if n.startswith("defender.run_service")),
            "config": "defender.learning.core.config" in sys.modules,
            "base": env["DEFENDER_RUNS_BASE"]}))
    """.replace("TMP", repr(str(tmp_path))), cwd=tmp_path)
    got = S.last_json(proc)
    assert got["service"] == [], got
    assert got["config"] is False, got
    assert got["base"] == str(tmp_path / "runs"), got


# ---------------------------------------------------------------------------------------
# D1 survival — every moved name resolves through its new path
# ---------------------------------------------------------------------------------------

#: G1 — the twelve production importers of `run_common` / `runtime.branch` at ed5386bc.
IMPORTERS = (
    "evals/held_out.py", "learning/branch/cli.py", "learning/branch/review.py",
    "learning/branch/seams.py", "learning/judge/family.py", "learning/judge/render.py",
    "scripts/case_history/ticket_writer.py", "run.py", "runtime/orient.py",
    "runtime/lead_zero/__init__.py", "runtime/tools/_bash.py", "runtime/box/_lifecycle.py",
)
#: G2 — the twenty names learning, the episode page and visualize took from `runtime.branch`.
ON_SURFACE = ("Family", "FamilyError", "check_identities", "episode_token_for", "parse_family",
              "BASE_ROLE", "is_reserved_world_label", "load_family", "world_token_for",
              "Overlay", "parse_overlay", "BranchError", "ElasticEntry", "World",
              "PATCHABLE_SYSTEMS")
AS_METHODS = {"runnable_worlds": "runnable_worlds", "resume_world_from": "resume_world"}


def _defender_imports(path: Path) -> list[dict]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:
                package = _module_package(path)
                base = package[: len(package) - (node.level - 1)]
                module = ".".join([*base, *([module] if module else [])])
            if module.startswith("defender"):
                out.append({"module": module, "names": [a.name for a in node.names]})
        elif isinstance(node, ast.Import):
            out += [{"module": a.name, "names": []} for a in node.names
                    if a.name.startswith("defender")]
    return out


_RESOLVE = """
    import importlib, json
    failures = []
    for item in json.loads(ITEMS):
        try:
            mod = importlib.import_module(item["module"])
        except Exception as e:
            failures.append([item["file"], item["module"], type(e).__name__])
            continue
        for name in item["names"]:
            if name == "*" or hasattr(mod, name):
                continue
            try:
                importlib.import_module(item["module"] + "." + name)
            except Exception as e:
                failures.append([item["file"], item["module"] + "." + name, type(e).__name__])
    print(json.dumps(failures))
"""


def test_1105_every_moved_name_resolves_through_its_new_import_path(tmp_path):
    """After the move, every name the base commit's production code took from
    `defender.run_common` or `defender.runtime.branch` resolves through its new path without
    `ImportError` or `AttributeError`. The importers are G1's twelve files, each import
    statement of which — module level or inside a function, as the four lazy executing-run
    sites (`runtime/orient.py`, `runtime/lead_zero/__init__.py`, `runtime/tools/_bash.py`,
    `runtime/box/_lifecycle.py`) have it — is resolved in a fresh interpreter. G2's twenty names
    each resolve on the service's public surface, as a `Family` method for the functions D1 turns
    into methods (`runnable_worlds`, `resume_world`), or — for the three D1 keeps private
    (`BranchSpec`, `fence_count_at`, `source_session`) — in one of the service's own modules.
    """
    items = [{"file": rel, **imp} for rel in IMPORTERS
             for imp in _defender_imports(S.DEFENDER / rel)]
    assert len({i["file"] for i in items}) == len(IMPORTERS), items
    failures = S.last_json(S.fresh_interpreter(
        _RESOLVE.replace("ITEMS", repr(json.dumps(items))), cwd=tmp_path))
    assert failures == [], failures

    missing = [n for n in ON_SURFACE if not hasattr(S.svc(), n)]
    assert not missing, missing
    family = S.sym("Family")
    for old, method in AS_METHODS.items():
        assert callable(getattr(family, method, None)), (old, method)
    for name in ("BranchSpec", "fence_count_at", "source_session"):
        assert S.defining_module(name, packages=(S.SERVICE,)).__name__.startswith(S.SERVICE)


def test_1105_family_methods_match_the_functions_they_replace(tmp_path):
    """for the triplet fixture family: `Family.runnable_worlds()` returns the worlds today's
    `runnable_worlds(family)` returns, with the `role: null` replicate arm dropped; and
    `Family.resume_world(label, episode_dir)` returns a `World` equal to today's
    `resume_world_from(family, label, episode_dir)` — the same token, label, episode dir, overlay
    and clock (the values measured at ed5386bc). An undeclared label is refused as today.
    """
    src = tmp_path / "runs" / T.SOURCE_RUN_ID
    doc = S.manifest_doc(src, worlds=[T.base_world(), T.world_doc("b"), T.world_doc("c"),
                                      T.world_doc("d", role=None)])
    family = S.sym("parse_family")(doc)
    assert [w.world_id for w in family.worlds] == ["a", "b", "c", "d"]
    assert [w.world_id for w in family.runnable_worlds()] == ["a", "b", "c"]
    ep = tmp_path / "episodes" / T.EPISODE_ID
    world = family.resume_world("b", ep)
    assert world.world_id == T.world_token("b") == "20260728t161845z.fresh.case.n59.b"
    assert world.label == 'b'
    assert world.episode_dir == ep
    assert world.run_id == f"{T.EPISODE_ID}-b"
    assert world.as_of == family.as_of
    assert world.family is family
    assert world.overlay == family.world("b").overlay
    with pytest.raises(S.sym("FamilyError")):
        family.resume_world("zzz", ep)


# ---------------------------------------------------------------------------------------
# D7 — host_env
# ---------------------------------------------------------------------------------------


def test_1105_host_env_holds_the_five_names_with_their_old_values(tmp_path, monkeypatch):
    """`defender.host_env` exports `run_env`, `REPO_ROOT`, `DEFENDER_DIR`, `HELD_OUT_FIXTURES`
    and `resolve_runs_base`. Each path equals the value `run_common` produced at the base commit,
    and `resolve_runs_base()` honours `DEFENDER_RUNS_BASE` as before — unset it is
    `/tmp/defender-runs` — including a `DEFENDER_RUNS_BASE` that is a symlink to a real base
    directory, which it returns as given. The subprocess environment `run_env` builds for a run
    directory exports the same `DEFENDER_RUNS_BASE` value (the run directory's parent) as
    `run_common.run_env` did, beside its other host-lane values.
    """
    env_mod = S.host_env()
    assert env_mod.REPO_ROOT == WORKTREE
    assert env_mod.DEFENDER_DIR == S.DEFENDER
    assert env_mod.HELD_OUT_FIXTURES == S.DEFENDER / "fixtures" / "held-out"

    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "learning-state"))
    monkeypatch.delenv("DEFENDER_RUNS_BASE", raising=False)
    assert env_mod.resolve_runs_base() == Path("/tmp/defender-runs")
    real = tmp_path / "real-base"
    real.mkdir()
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(real))
    assert env_mod.resolve_runs_base() == real
    linked = tmp_path / "linked-base"
    linked.symlink_to(real)
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(linked))
    assert env_mod.resolve_runs_base() == linked, "the linked base must be returned as given"

    monkeypatch.setenv("DEFENDER_BOX", "1")
    for base in (real, linked):
        run_dir = base / "20260921t143000z-case-a"
        env = env_mod.run_env(S.DEFENDER, run_dir)
        assert env["DEFENDER_RUNS_BASE"] == str(run_dir.parent) == str(base)
        assert env["DEFENDER_RUN_DIR"] == str(run_dir)
        assert env["DEFENDER_DIR"] == str(S.DEFENDER)
        assert env["PATH"].startswith(f"{S.DEFENDER / 'bin'}{os.pathsep}")
        assert env["PYTHONPATH"].split(os.pathsep)[0] == str(WORKTREE)
        assert "DEFENDER_BOX" not in env
        from defender.runtime import providers

        assert not set(providers.api_key_vars()) & set(env)


def test_1105_runs_base_env_var_set_to_empty_string(tmp_path, monkeypatch):
    """with `DEFENDER_RUNS_BASE` set to the empty string, `host_env.resolve_runs_base()` returns
    `Path('.')`, so the process cwd is the runs base, and raises nothing; unset, it returns
    `/tmp/defender-runs`.
    """
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "learning-state"))
    monkeypatch.setenv("DEFENDER_RUNS_BASE", "")
    assert S.host_env().resolve_runs_base() == Path(".")
    monkeypatch.delenv("DEFENDER_RUNS_BASE")
    assert S.host_env().resolve_runs_base() == Path("/tmp/defender-runs")


def test_1105_runs_base_env_var_collides_with_learning_state_root(tmp_path, monkeypatch):
    """when `DEFENDER_RUNS_BASE` resolves to the learning state root
    (`DEFENDER_LEARNING_STATE_DIR`), `host_env.resolve_runs_base()` raises `FatalConfigError`
    naming both, as `run_common` did.
    """
    from defender._env import FatalConfigError

    shared = tmp_path / "shared"
    shared.mkdir()
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(shared))
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(shared))
    with pytest.raises(FatalConfigError) as refused:
        S.host_env().resolve_runs_base()
    assert "DEFENDER_RUNS_BASE" in str(refused.value)
    assert "DEFENDER_LEARNING_STATE_DIR" in str(refused.value)


def test_1105_a_script_that_relied_on_run_commons_sys_path_insert(tmp_path):
    """a module run by path that imports `host_env` (from the `defender/` directory, as a script
    run by path finds it) before a repo-root package imports that package, because `host_env`
    keeps the repo-root `sys.path` insert `run_common` made (subprocess, no `PYTHONPATH`): the
    `defender` package it then imports is this checkout's.
    """
    script = tmp_path / "by_path.py"
    script.write_text(
        "import json, sys\n"
        f"sys.path.insert(0, {str(S.DEFENDER)!r})\n"
        "import host_env\n"
        "import defender._run_id as rid\n"
        "print(json.dumps({'from': rid.__file__, 'inserted': host_env.REPO_ROOT.as_posix()}))\n",
        encoding="utf-8")
    proc = S.fresh_interpreter("", cwd=tmp_path, env={"PYTHONPATH": ""},
                               argv=[sys.executable, str(script)])
    got = S.last_json(proc)
    assert got["from"] == str(S.DEFENDER / "_run_id.py"), got
    assert got["inserted"] == WORKTREE.as_posix(), got


def test_1105_replay_env_built_by_host_env_after_the_move(tmp_path, monkeypatch):
    """`review.verb_context` builds the same env as today (`run_env`, then the
    `DEFENDER_RUNS_BASE` override), both names now from `host_env`; every replay adapter
    subprocess receives that environment: the configured runs base — not the episode's parent,
    which is the episodes root — and the episode as the run dir.
    """
    runs = S.configure_roots(tmp_path, monkeypatch)
    ep = tmp_path / "episodes-root" / T.EPISODE_ID
    ep.mkdir(parents=True)
    review = S.mod("learning.branch.review")
    ctx = review.verb_context(ep)
    expected = dict(S.host_env().run_env(S.host_env().DEFENDER_DIR, ep))
    expected["DEFENDER_RUNS_BASE"] = str(S.host_env().resolve_runs_base())
    assert ctx.env == expected, (ctx.env, expected)
    assert ctx.env["DEFENDER_RUNS_BASE"] == str(runs) != str(ep.parent), (ctx.env, runs, ep)
    assert ctx.env["DEFENDER_RUN_DIR"] == str(ep), (ctx.env, ep)
    host_env = S.host_env()
    bound = vars(review)
    by_name = (bound.get("run_env") is host_env.run_env
               and bound.get("resolve_runs_base") is host_env.resolve_runs_base)
    by_module = any(value is host_env for value in bound.values())
    assert by_name or by_module, "review.py does not take run_env/resolve_runs_base from host_env"


# ---------------------------------------------------------------------------------------
# D8 — values derived from a file's location keep their resolved values
# ---------------------------------------------------------------------------------------


def test_1105_location_derived_values_resolve_as_before_the_move(tmp_path, monkeypatch):
    """after the move, five location-derived values resolve to the same paths as at the base
    commit: the run page's mirror root (`visualize_run`'s `parents[2]` value, #1109 — the main
    checkout's `run-visualizations/`); `_MIRROR_WRITER`; `visualize_primitives`' `REPO_ROOT` and
    `ASSETS`; the visualize script path the run-end launch invokes; the `run.py` that
    `sibling_argv` names, `defender/run.py`.
    """
    writer = S.defining_module("_MIRROR_WRITER")._MIRROR_WRITER
    assert writer == S.DEFENDER / "scripts" / "visualize" / "_mirror_write.py"
    primitives = S.module_named("visualize_primitives",
                                fallback="defender.scripts.visualize.visualize_primitives")
    assert primitives.REPO_ROOT == WORKTREE
    assert primitives.ASSETS == S.DEFENDER / "scripts" / "visualize" / "assets"

    root_module = S.defining_module("mirror_root").__name__
    proc = S.fresh_interpreter(f"""
        import importlib, os
        os.environ.pop("PYTEST_CURRENT_TEST", None)
        os.environ.pop("DEFENDER_RUN_VISUALIZATIONS_DIR", None)
        print(importlib.import_module({root_module!r}).mirror_root())
    """, cwd=tmp_path)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip().splitlines()[-1] == str(S.main_checkout() / "run-visualizations")

    S.configure_roots(tmp_path, monkeypatch)
    run_dir = tmp_path / "defender-runs" / "20260921t143000z-d8"
    run_dir.mkdir(parents=True)
    import inspect

    visualize = inspect.signature(S.run_py().main).parameters["visualize"].default
    # a run dir with no store fails to render — the launch's argv is what this reads
    with S.watching_waits() as seen, contextlib.suppress(Exception):
        visualize(run_dir)
    script = S.DEFENDER / "scripts" / "visualize" / "visualize_run.py"
    assert any(str(script) in c["argv"] for c in seen), seen

    ep = tmp_path / "episodes-root" / T.EPISODE_ID
    argv = S.sym("sibling_argv")(ep, "b")
    assert argv[1] == str(S.DEFENDER / "run.py"), argv


def test_1105_mirror_writer_child_launched_by_its_file_path_as_the_checkout_owner(tmp_path):
    """`_MIRROR_WRITER`'s file still runs standalone by file path — isolated (`-I`), from `/`,
    exactly the argv the checkout owner's copy runs — once its module sits in the service
    package, and writes the mirror copy (subprocess).
    """
    import subprocess

    writer = S.defining_module("_MIRROR_WRITER")._MIRROR_WRITER
    dest = tmp_path / "mirror" / "20260921t143000z-case-a.html"
    dest.parent.mkdir()
    page = b"<html><body>run page 1105</body></html>"
    proc = subprocess.run([sys.executable, "-I", str(writer), str(dest)], input=page,
                          capture_output=True, cwd="/", check=False, timeout=120)
    assert proc.returncode == 0, proc.stderr
    assert dest.read_bytes() == page


def test_1105_visualize_child_launched_by_script_path_after_the_move(tmp_path, monkeypatch):
    """the visualize CLI at `scripts/visualize/visualize_run.py`, launched by script path from an
    arbitrary cwd as run end launches it, imports the service and renders the run page
    (subprocess): exit 0 and `runtime.html` written, the CLI being a caller of the service.
    """
    run_dir = S.driven_run(tmp_path / "driven")
    (run_dir / "runtime.html").unlink(missing_ok=True)
    script = S.DEFENDER / "scripts" / "visualize" / "visualize_run.py"
    proc = S.fresh_interpreter("", cwd=tmp_path, argv=[sys.executable, str(script), str(run_dir)],
                               env={"DEFENDER_RUN_VISUALIZATIONS_DIR": str(tmp_path / "mirror")})
    assert proc.returncode == 0, proc.stderr
    assert (run_dir / "runtime.html").is_file()
    imported = {n.module for n in ast.walk(ast.parse(script.read_text(encoding="utf-8")))
                if isinstance(n, ast.ImportFrom)}
    assert any(m and m.startswith(S.SERVICE) for m in imported), imported


def test_1105_visualize_cli_given_a_run_dir_argument_that_fails_is_valid_run_id(tmp_path):
    """the standalone visualize CLI keeps taking a directory path with no `open_run` and no id
    check: given a run directory whose basename fails `is_valid_run_id` (`run (1)`), it renders
    the page as at base; given a path that is not a directory, it exits 1 with its `not a
    directory` message, as at base.
    """
    run_dir = S.driven_run(tmp_path / "driven")
    odd = run_dir.with_name("run (1)")
    run_dir.rename(odd)
    (odd / "runtime.html").unlink(missing_ok=True)
    script = S.DEFENDER / "scripts" / "visualize" / "visualize_run.py"
    env = {"DEFENDER_RUN_VISUALIZATIONS_DIR": str(tmp_path / "mirror")}
    proc = S.fresh_interpreter("", cwd=tmp_path, argv=[sys.executable, str(script), str(odd)],
                               env=env)
    assert proc.returncode == 0, proc.stderr
    assert (odd / "runtime.html").is_file()

    not_a_dir = tmp_path / "a-file"
    not_a_dir.write_text("x", encoding="utf-8")
    proc = S.fresh_interpreter("", cwd=tmp_path,
                               argv=[sys.executable, str(script), str(not_a_dir)], env=env)
    assert proc.returncode == 1
    assert "not a directory" in proc.stderr


def test_1105_frontend_build_takes_css_from_visualize_primitives():
    """the CSS that `learning/frontend/build.py` embeds for run pages is the `CSS` object that
    `visualize_primitives` defines — imported from `visualize_primitives` itself, not through
    the run page (which moved into the service).
    """
    build_py = S.DEFENDER / "learning" / "frontend" / "build.py"
    imports = [(node.module or "", {a.name for a in node.names})
               for node in ast.walk(ast.parse(build_py.read_text(encoding="utf-8")))
               if isinstance(node, ast.ImportFrom)]
    sources = [m for m, names in imports if "CSS" in names]
    assert sources, sources
    assert all(m.endswith('visualize_primitives') for m in sources), sources
    assert not any(m.endswith("visualize_run") for m, _names in imports), imports
    primitives = importlib.import_module(sources[0])
    build = S.mod("learning.frontend.build")
    assert any(value is primitives.CSS for value in vars(build).values())


# ---------------------------------------------------------------------------------------
# J10 — generate_case keeps its runs-base reading (an N-f deferred site)
# ---------------------------------------------------------------------------------------

_GENERATE_CASE = """
    import json, os, stat, sys
    from pathlib import Path
    import defender.host_env as host_env
    from defender.evals.oracle_golden import generate_case
    argv_file = Path(ARGV_FILE)
    # the child `investigate` spawns is `[sys.executable, run.py, ...]`: the interpreter path is
    # replaced by a recorder that writes the argv it was handed and creates nothing
    os.unlink(sys.executable)
    Path(sys.executable).write_text("#!/bin/sh\\nprintf '%s\\\\n' \\"$@\\" > " + str(argv_file)
                                    + "\\nexit 0\\n")
    os.chmod(sys.executable, 0o755)
    out = {"expected": str(host_env.resolve_runs_base() / RUN_ID)}
    try:
        generate_case.investigate(Path(ALERT), RUN_ID)
        out["raised"] = None
    except RuntimeError as e:
        out["raised"] = str(e)
    out["argv"] = argv_file.read_text().split() if argv_file.exists() else None
    print(json.dumps(out))
"""


def test_1105_a_second_door_that_creates_a_run_directory(tmp_path, monkeypatch):
    """`generate_case.investigate` predicts its child's run directory as `DEFENDER_RUNS_BASE`
    (default `/tmp/defender-runs`) joined with the run id, and with `DEFENDER_RUNS_BASE` set and
    unset that prediction equals `host_env.resolve_runs_base() / run_id`, the directory the child
    `run.py` materializes. It creates no run directory itself: the child it spawns (the recorded
    `run.py … --run-id <id>`) is the only creator, and a child that created none leaves the
    prediction absent.
    """
    import uuid

    alert = tmp_path / "alert.json"
    alert.write_text("{}", encoding="utf-8")
    run_id = f"gc-1105-{uuid.uuid4().hex[:12]}"
    for tag in ("set", "unset"):
        env = {"DEFENDER_LEARNING_STATE_DIR": str(tmp_path / "learning-state")}
        if tag == "set":
            env["DEFENDER_RUNS_BASE"] = str(tmp_path / "runs")
        else:
            env["DEFENDER_RUNS_BASE"] = ""
        python = S.deletable_interpreter(tmp_path / tag)
        code = (_GENERATE_CASE.replace("ARGV_FILE", repr(str(tmp_path / tag / "argv.txt")))
                .replace("RUN_ID", repr(run_id)).replace("ALERT", repr(str(alert))))
        if tag == "unset":
            code = "import os\nos.environ.pop('DEFENDER_RUNS_BASE', None)\n" + \
                   __import__("textwrap").dedent(code)
        proc = S.fresh_interpreter(code, cwd=tmp_path, python=str(python), env=env)
        got = S.last_json(proc)
        assert got['raised'], (tag, got)
        assert got['expected'] in got['raised'], (tag, got)
        assert got['argv'], got
        assert got['argv'][got['argv'].index('--run-id') + 1] == run_id, got
        assert got["argv"][0] == str(S.DEFENDER / "run.py"), got
        assert not Path(got["expected"]).exists(), (tag, "investigate created the run dir")
        if tag == "unset":
            assert got["expected"] == f"/tmp/defender-runs/{run_id}", got
