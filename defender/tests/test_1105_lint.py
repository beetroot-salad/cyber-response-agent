"""#1105 D5 — `scripts/lint/lint_run_layout_imports.py`: outside the executing run and the run
service, no code imports run-layout names (O1), with its own `CATEGORIES` and an empty
`MIGRATION_ALLOW_LIST`; plus the sibling lints' coverage of `run_service/` and CI's step.

The lint is driven the way `lint_run_records` is (`_spec1077.gate_findings`): its pure
root-taking pass `scan(root)` over a tree PLANTED under `tmp_path` — a real copy of
`_run_paths.py` (the module whose exports it gates by default-deny, read off the swept tree)
plus one planted module per scenario. Findings are asserted by what they NAME (the planted file,
the gated name), never by count: a planted tree lacks most category members, which the lint
reports as stale entries (J12), and those findings sit beside the ones under test.

Every scenario that asserts a module is NOT flagged is paired with the identical import in a
module outside every category that IS flagged — a clean scan of an unscanned file passes
vacuously. Refuted/declared limits respected: the lint does not trace paths out of handles, an
f-string join onto a runs base (N-e), re-exports, or importlib/getattr strings (J12) — those are
pinned as NOT flagged, so nobody mistakes the gap for coverage.

RED against ed5386bc: the lint does not exist; `lint_run_records` and
`lint_tree_read_follows_link` do not cover `run_service/`; `learning/core/config.py` still
re-exports `RunPaths`.
"""
from __future__ import annotations

import ast
import importlib
import re
import textwrap
import types

import pytest
import yaml

from defender.tests import _spec1105 as S
from defender.tests._by_path import WORKTREE, import_lint_lib, load_lint_gate

IMPORT_GATED = "from defender._run_paths import RunLayout\n"


def _scan_one(tmp_path, rel: str, text, **kw) -> list:
    root = S.lint_root(tmp_path, **kw)
    S.plant(root, rel, text)
    return S.lint_findings(root)


def _flagged(tmp_path, tag: str, rel: str, text, name: str = "RunLayout", **kw) -> bool:
    return S.flags(_scan_one(tmp_path / tag, rel, text, **kw), rel, name)


# ---------------------------------------------------------------------------------------
# O1 — clean over the real tree with an empty allow-list
# ---------------------------------------------------------------------------------------


@pytest.mark.gate
def test_1105_run_layout_lint_is_clean_over_defender_with_an_empty_allow_list():
    """`lint_run_layout_imports` run over the `defender/` tree reports zero findings, and its
    `MIGRATION_ALLOW_LIST` is empty — both through its pure pass and its CLI entry point.
    """
    gate = S.lint()
    assert not gate.MIGRATION_ALLOW_LIST, gate.MIGRATION_ALLOW_LIST
    found = list(gate.scan(S.DEFENDER))
    assert found == [], S.displays(found)
    assert gate.main([]) == 0


# ---------------------------------------------------------------------------------------
# D5 — what is flagged, what is admitted
# ---------------------------------------------------------------------------------------


def test_1105_lint_flags_a_gated_import_and_passes_the_listed_helpers(tmp_path):
    """`lint_run_layout_imports` treats a module outside every category as follows: importing
    `RunLayout`, `WireLogNames` or `resolve_run_bundle` from `defender._run_paths` is a finding;
    importing `artifact_file`, `artifact_dir`, `plain_file`, `contained_payload` or `LEAD_ID_RE`
    is not. Rejected: the lint is not required to see a path traced out of a handle or an
    f-string join onto a runs base (N-e) — a module doing only that is not flagged.
    """
    for name in S.GATED:
        assert _flagged(tmp_path, f"gated-{name}", S.OUTSIDER,
                        f"from defender._run_paths import {name}\n", name), name
    for name in S.ADMITTED:
        assert not _flagged(tmp_path, f"admitted-{name}", S.OUTSIDER,
                            f"from defender._run_paths import {name}\n", name), name
    traced = """
        from pathlib import Path
        def reach(run, runs_base: Path, run_id: str):
            return run.run_dir / "report.md", Path(f"{runs_base}/{run_id}/alert.json")
    """
    found = _scan_one(tmp_path / "n-e", S.OUTSIDER, traced)
    assert not S.flags(found, S.OUTSIDER), S.displays(found)


def test_1105_lint_flags_a_gated_attribute_read_through_a_whole_module_import(tmp_path):
    """a module outside every category that does `import defender._run_paths as rp` and then
    reads `rp.RunLayout` is flagged by `lint_run_layout_imports`. Reading `rp.artifact_file` is
    not flagged.
    """
    assert _flagged(tmp_path, "gated", S.OUTSIDER,
                    "import defender._run_paths as rp\nLAYOUT = rp.RunLayout\n")
    assert not _flagged(tmp_path, "admitted", S.OUTSIDER,
                        "import defender._run_paths as rp\nCHECK = rp.artifact_file\n",
                        "artifact_file")


def test_1105_lint_gates_an_unlisted_new_run_paths_export(tmp_path):
    """a name added to `defender._run_paths`'s exports and absent from the helper list is flagged
    by `lint_run_layout_imports` when imported outside the categories — default-deny, with no
    list of gated names for the new export to be missing from.
    """
    extra = "\n\ndef brand_new_layout_helper_1105(run_dir):\n    return run_dir\n"
    assert _flagged(tmp_path, "new", S.OUTSIDER,
                    "from defender._run_paths import brand_new_layout_helper_1105\n",
                    "brand_new_layout_helper_1105", run_paths_extra=extra)


def test_1105_lint_reports_a_file_that_fails_to_parse(tmp_path):
    """a swept file with a syntax error appears as a finding from `lint_run_layout_imports`, and
    the scan still reports findings in other files.
    """
    root = S.lint_root(tmp_path)
    S.plant(root, "learning/ops/zz_1105_broken.py", "def broken(:\n")
    S.plant(root, S.OUTSIDER, IMPORT_GATED)
    found = S.lint_findings(root)
    assert S.flags(found, "learning/ops/zz_1105_broken.py"), S.displays(found)
    assert S.flags(found, S.OUTSIDER, "RunLayout"), S.displays(found)


#: D5's category members the design names file by file. The executing-run and not-a-run
#: categories are named by kind; their members are read off `CATEGORIES` itself below.
OWNERS = ("_run_paths.py", "_episode_paths.py", "_tenant.py", "_run_handle.py")
SERVICE = ("run.py", "run_service/zz_1105_member.py")
NAMES_ONLY = (
    "_report.py", "_artifact_schema.py", "scripts/workspace_map.py", "runtime/compaction.py",
    "runtime/box/_lifecycle.py", "learning/judge/render.py",
    "learning/leads/lead_author/__init__.py", "learning/branch/seams.py",
    "learning/judge/__init__.py", "learning/author/verify_forward/checks.py",
    "learning/core/config.py",
)
N_D = ("evals/held_out.py",)
NOT_A_RUN = ("learning/lead_repository.py", "scripts/visualize/visualize_episode.py")
#: The run page's helper modules at ed5386bc. Phase-F §7 R5 (owner): their record-reading parts
#: move into the service with the run page; whatever of them stays here is styling and constants.
RUN_PAGE_HELPERS = tuple(f"scripts/visualize/{stem}.py" for stem in (
    "visualize_primitives", "visualize_data", "visualize_messages", "visualize_runtime"))


def _css_home() -> str:
    """The module `learning/frontend/build.py` takes `CSS` from, as a path under `defender/`."""
    build = S.DEFENDER / "learning" / "frontend" / "build.py"
    for node in ast.walk(ast.parse(build.read_text(encoding="utf-8"))):
        if isinstance(node, ast.ImportFrom) and any(a.name == "CSS" for a in node.names):
            dotted = node.module or ""
            assert node.level == 0, dotted
            assert dotted.startswith("defender."), dotted
            return dotted[len("defender."):].replace(".", "/") + ".py"
    raise AssertionError("learning/frontend/build.py imports no `CSS`")


#: The one-line escape phase F's second pass found (97 N1): `_run_handle` re-exports `RunPaths`,
#: and the lint does not trace re-exports (J12) — so the lint alone would pass a staying helper
#: that kept its record reads and only changed where it imports the name from.
REEXPORT_ESCAPE = "from defender._run_handle import RunPaths\n"


def _run_paths_own_names() -> dict[str, object]:
    """The public names `defender._run_paths` DEFINES at top level — read off its source, as D5
    reads its gated set, not off `dir()`, which also lists what it imports (`Path`, `re`) —
    mapped to that module's own objects."""
    owner = S.mod("_run_paths")
    names: set[str] = set()
    for node in ast.parse((S.DEFENDER / "_run_paths.py").read_text(encoding="utf-8")).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        targets = (node.targets if isinstance(node, ast.Assign)
                   else [node.target] if isinstance(node, ast.AnnAssign) else [])
        for target in targets:
            elts = target.elts if isinstance(target, ast.Tuple) else [target]
            names.update(t.id for t in elts if isinstance(t, ast.Name))
    return {n: getattr(owner, n) for n in names if not n.startswith("_") and hasattr(owner, n)}


_ABSENT = object()


def _module_or_none(dotted: str):
    try:
        return importlib.import_module(dotted)
    except ImportError:
        return None


def _absolute(origin: str, package: list[str]) -> str:
    """An import binding's `_astlib` origin made absolute. `_astlib` keeps a relative import's
    dots in front — `from .m import y` binds `.m.y`, and `from . import x` binds `..x` (one dot
    more, joined onto an empty module name) — so a lone name after the dots is the second."""
    rest = origin.lstrip(".")
    dots = len(origin) - len(rest)
    if not dots:
        return origin
    level = dots if "." in rest else dots - 1
    return ".".join([*package[:len(package) - (level - 1)], rest])


def _object_at(dotted: str) -> object:
    """What a dotted origin names: its longest importable module prefix, then attributes."""
    parts = dotted.split(".")
    for cut in range(len(parts), 0, -1):
        obj = _module_or_none(".".join(parts[:cut]))
        if obj is None:
            continue
        for attr in parts[cut:]:
            obj = getattr(obj, attr, _ABSENT)
        return obj
    return _ABSENT


def _run_paths_names_imported(text: str, rel: str) -> set[str]:
    """Each of `_run_paths`' own names that the module at `rel` (source `text`) binds through an
    import statement from ANY module — `from M import N` in any scope, relative included, or an
    attribute `h.N` read off a module `h` it imported. The bindings are `_astlib`'s scope-aware
    answer (`module_env`, `origin`); each is then resolved to its object, and it counts only
    when that object IS `_run_paths`' own, so an unrelated object sharing the name does not
    (and one re-exported under another name is reported by `_run_paths`' own name for it).
    A `*` import is not expanded, as `_astlib` does not expand one: ruff's F403 already makes
    one unmergeable."""
    astlib = import_lint_lib("_astlib")
    own = _run_paths_own_names()

    def names_of(name: str, obj: object) -> set[str]:
        if obj is _ABSENT:
            return set()
        if own.get(name, _ABSENT) is obj:
            return {name}
        return {n for n, o in own.items() if o is obj}

    package = ["defender", *rel.split("/")[:-1]]
    tree = ast.parse(text)
    env = astlib.module_env(tree)

    def resolved(node: ast.expr) -> object:
        attrs: list[str] = []
        while isinstance(node, ast.Attribute):
            attrs.insert(0, node.attr)
            node = node.value
        found = astlib.origin(node, env) if isinstance(node, ast.Name) else None
        obj = _ABSENT if found is None else _object_at(_absolute(found, package))
        for attr in attrs:
            step = getattr(obj, attr, _ABSENT)
            if step is _ABSENT and isinstance(obj, types.ModuleType):
                step = _module_or_none(f"{obj.__name__}.{attr}") or _ABSENT
            obj = step
        return obj

    scopes = {id(e): e for e in [env, *env.scope_of.values()]}
    bound = [(o.rsplit(".", 1)[-1], _object_at(_absolute(o, package)))
             for e in scopes.values() for o in e.imports.values()]
    bound += [(node.attr, getattr(receiver, node.attr, _ABSENT)) for node in ast.walk(tree)
              if isinstance(node, ast.Attribute)
              and isinstance(receiver := resolved(node.value), types.ModuleType)]
    return {n for name, obj in bound for n in names_of(name, obj)}


def test_1105_lint_admits_each_category_and_only_its_members(tmp_path):
    """`lint_run_layout_imports` does not flag a gated import in a member of each category: the
    owners, the executing-run modules, the service including `run.py`, each listed names-only
    user, the not-a-run users, and `evals/held_out.py` — every member `CATEGORIES` lists, plus
    every file the design names for a category. It flags the identical import in a module
    outside `CATEGORIES`. The run page's helpers left outside the service — the module
    `learning/frontend/build.py` takes `CSS` from, and whichever of `visualize_primitives`,
    `visualize_data`, `visualize_messages` and `visualize_runtime` stay under
    `scripts/visualize/` — are in no category and import no gated name: each one's own source,
    planted at its own path, draws no finding, and the same source with a gated import added is
    flagged there. "Imports no gated name" is pinned by name, whatever module the name is
    imported from: no import statement in a staying module, from any module, binds one of
    `_run_paths`' own names that the lint gates — `_run_handle`'s re-export of `RunPaths`
    included, which the lint does not trace — and the same source with `from
    defender._run_handle import RunPaths` added is caught.
    """
    members = S.category_members()
    listed = sorted({m for ms in members.values() for m in ms})
    assert len(members) >= 6, members
    named = [*OWNERS, *SERVICE, *NAMES_ONLY, *N_D, *NOT_A_RUN]
    for i, rel in enumerate(dict.fromkeys([*named, *listed])):
        if rel == "_run_paths.py":
            continue
        assert not _flagged(tmp_path, f"member-{i}", rel, IMPORT_GATED), rel
    assert _flagged(tmp_path, "outsider", S.OUTSIDER, IMPORT_GATED)

    # R5 (owner, phase F): what stays outside the service is filed in NO category — a
    # names-only or not-a-run entry would admit a record reader and keep O1 green — and its
    # own source imports no gated name.
    css_home = _css_home()
    assert not css_home.startswith("run_service/"), css_home
    staying = list(dict.fromkeys(
        [css_home, *(rel for rel in RUN_PAGE_HELPERS if (S.DEFENDER / rel).is_file())]))
    for i, rel in enumerate(staying):
        assert rel not in listed, (rel, members)
        text = (S.DEFENDER / rel).read_text(encoding="utf-8")
        found = _scan_one(tmp_path / f"staying-{i}", rel, text)
        assert not S.flags(found, rel), S.displays(found)
        assert _flagged(tmp_path, f"staying-{i}-control", rel, text + "\n" + IMPORT_GATED), rel

    # N1 (phase F's second pass, auto): the owner's "imports no gated name" is pinned BY NAME,
    # whatever module the name comes from — the lint above cannot see a re-export (J12). Which
    # of `_run_paths`' names is gated is the lint's own answer (default-deny plus F6's helper
    # list), asked once for each name a staying module actually imports.
    own = _run_paths_own_names()
    assert S.mod("_run_handle").RunPaths is own["RunPaths"], (
        "`defender._run_handle` no longer re-exports `_run_paths.RunPaths`: the escape this "
        "control plants is gone — re-plant it through a module that still re-exports a gated name")
    verdicts: dict[str, bool] = {}

    def gated(name: str) -> bool:
        if name not in verdicts:
            verdicts[name] = _flagged(tmp_path, f"gated-{name}", S.OUTSIDER,
                                      f"from defender._run_paths import {name}\n", name)
        return verdicts[name]

    for rel in staying:
        text = (S.DEFENDER / rel).read_text(encoding="utf-8")
        imported = sorted(_run_paths_names_imported(text, rel))
        assert not [name for name in imported if gated(name)], (rel, imported, verdicts)
        escaped = _run_paths_names_imported(text + "\n" + REEXPORT_ESCAPE, rel)
        assert "RunPaths" in escaped, (rel, sorted(escaped))
        assert gated("RunPaths"), verdicts


def test_1105_lint_sweeps_defender_including_run_service_and_not_repo_root_scripts(tmp_path):
    """a gated import planted under `defender/run_service/`, outside the service's own category,
    would be reached by the sweep (the sweep file list includes `run_service` files). A file
    under the repo-root `scripts/` is not in the sweep.
    """
    root = S.lint_root(tmp_path)
    inside = S.plant(root, "run_service/zz_1105_new.py", IMPORT_GATED)
    outside = S.plant(tmp_path, "scripts/zz_1105_repo_root.py", IMPORT_GATED)
    swept = {p.resolve() for p in S.lint().sweep_files(root)}
    assert inside.resolve() in swept
    assert outside.resolve() not in swept


def test_1105_ci_runs_the_run_layout_lint():
    """`.github/workflows/ci.yml` has a step that runs `scripts/lint/lint_run_layout_imports.py`
    — located by what the step RUNS, and exactly one such step.
    """
    jobs = yaml.safe_load((WORKTREE / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"))["jobs"]
    runs = [str(step.get("run", "")) for job in jobs.values() for step in job.get("steps", [])]
    hits = [r for r in runs if re.search(r"scripts/lint/lint_run_layout_imports\.py\b", r)]
    assert len(hits) == 1, hits


def test_1105_core_config_no_longer_exports_run_paths_but_still_loads(tmp_path):
    """`defender.learning.core.config` imports cleanly and has no `RunPaths` attribute (in a fresh
    interpreter, where nothing else can have bound it). The positive control: its curator trace
    naming through `WIRE_LOG_NAMES` still produces the same name as before.
    """
    proc = S.fresh_interpreter("""
        import json, os
        from pathlib import Path
        from defender.learning.core import config
        from defender._run_paths import WIRE_LOG_NAMES
        wiring = config.StageWiring.for_batch(Path("p.md"), "m", None, batch_id="b1105",
                                              label="L")
        print(json.dumps({"has": hasattr(config, "RunPaths"), "name": wiring.trace_name,
                          "expected": WIRE_LOG_NAMES.curator_batch("b1105", os.getpid())}))
    """, cwd=tmp_path)
    got = S.last_json(proc)
    assert got["has"] is False, got
    assert got["name"] == got["expected"], got


def test_1105_run_records_and_tree_read_lints_cover_run_service(tmp_path):
    """`lint_run_records`' sweep file list includes the `defender/run_service/*.py` files.
    `lint_tree_read_follows_link`'s module list names the `run_service` modules that took over
    the listed readers (which ones is the implementer's census) and no longer names the deleted
    `run_common.py` or `runtime/branch` readers.
    """
    root = tmp_path / "defender"
    planted = S.plant(root, "run_service/zz_1105_reader.py", "X = 1\n")
    records = load_lint_gate("lint_run_records")
    assert planted in records.sweep_files(root)

    modules = set(load_lint_gate("lint_tree_read_follows_link").LINT_TREE_READER_MODULES)
    assert any(m.startswith("run_service/") for m in modules), sorted(modules)
    for gone in ("run_common.py", "runtime/branch.py", "runtime/branch/_family.py"):
        assert gone not in modules, gone


# ---------------------------------------------------------------------------------------
# settled premises and §7 J10 / J12 / F7
# ---------------------------------------------------------------------------------------


def test_1105_lint_gated_name_via_relative_import(tmp_path):
    """`from .._run_paths import RunPaths` in a module outside every category is flagged."""
    assert _flagged(tmp_path, "rel", "learning/zz_1105_relative.py",
                    "from .._run_paths import RunPaths\n", "RunPaths")


def test_1105_lint_gated_name_via_from_package_import_module(tmp_path):
    """`from defender import _run_paths` then `_run_paths.RUN_LAYOUT` in a module outside every
    category is flagged.
    """
    assert _flagged(tmp_path, "pkg", S.OUTSIDER,
                    "from defender import _run_paths\nLAYOUT = _run_paths.RUN_LAYOUT\n",
                    "RUN_LAYOUT")


N_F = ("learning/author/lessons/run.py", "learning/author/verify_forward/forward.py")


def test_1105_lint_admits_the_n_f_deferred_learning_readers_by_name(tmp_path):
    """`lint_run_layout_imports` does not flag the gated `RunPaths` import in
    `learning/author/lessons/run.py` or `learning/author/verify_forward/forward.py`, because
    `CATEGORIES` lists them under a named "N-f deferred" category, and `MIGRATION_ALLOW_LIST`
    stays empty. The same import in a module outside every category is flagged.
    """
    gate = S.lint()
    assert not gate.MIGRATION_ALLOW_LIST
    members = S.category_members()
    deferred = [k for k, ms in members.items() if set(N_F) <= set(ms)]
    assert deferred, members
    assert any("deferred" in k.lower() and re.sub(r"[^a-z]", "", k.lower()).startswith("nf")
               for k in deferred), deferred
    for rel in N_F:
        assert not _flagged(tmp_path, f"nf-{rel.split('/')[-2]}", rel,
                            "from defender._run_paths import RunPaths\n", "RunPaths"), rel
    assert _flagged(tmp_path, "outsider", S.OUTSIDER,
                    "from defender._run_paths import RunPaths\n", "RunPaths")


def test_1105_lint_flags_a_gated_name_in_every_import_position(tmp_path):
    """in a swept module outside every category, `lint_run_layout_imports` flags an import of a
    gated name from `defender._run_paths` wherever it sits: under `if TYPE_CHECKING:`, inside a
    function body, as `from defender._run_paths import *`, and in one statement naming a gated
    and an admitted helper together, where it reports the gated name only. Categories are per
    module: a module in a category is admitted for every import it makes.
    """
    positions = {
        "type-checking": "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n"
                         "    from defender._run_paths import RunLayout\n",
        "function-body": "def f():\n    from defender._run_paths import RunLayout\n"
                         "    return RunLayout\n",
        "star": "from defender._run_paths import *\n",
    }
    for tag, text in positions.items():
        found = _scan_one(tmp_path / tag, S.OUTSIDER, text)
        assert S.flags(found, S.OUTSIDER), (tag, S.displays(found))
    mixed = _scan_one(tmp_path / "mixed", S.OUTSIDER,
                      "from defender._run_paths import artifact_file, RunLayout\n")
    assert S.flags(mixed, S.OUTSIDER, "RunLayout"), S.displays(mixed)
    assert not S.flags(mixed, S.OUTSIDER, "artifact_file"), S.displays(mixed)
    member = "learning/judge/render.py"
    every = ("from defender._run_paths import RunLayout\n"
             "def g():\n    from defender._run_paths import WireLogNames\n    return WireLogNames\n")
    found = _scan_one(tmp_path / "member", member, every)
    assert not S.flags(found, member), S.displays(found)


def test_1105_lint_does_not_trace_reexports_or_importlib_strings(tmp_path):
    """`lint_run_layout_imports` does not flag a module outside every category that takes
    `RunPaths` through a permitted module's re-export, or reaches it through
    `importlib.import_module` or `getattr` on a string — a declared limit (N-e, J12). Nor does
    it flag a module in which gated names appear only inside a string literal, an f-string
    message, a docstring or a comment (only an import statement, or an attribute read off a
    whole-module import, is a use). The positive controls: the same module importing `RunPaths`
    from `defender._run_paths` directly is flagged, and the strings-only module with one real
    gated import added is flagged.
    """
    untraced = """
        import importlib
        from defender._run_handle import RunPaths
        mod = importlib.import_module("defender._run_paths")
        ALSO = getattr(mod, "RunPaths")
    """
    found = _scan_one(tmp_path / "untraced", S.OUTSIDER, untraced)
    assert not S.flags(found, S.OUTSIDER), S.displays(found)
    assert _flagged(tmp_path, "direct", S.OUTSIDER,
                    "from defender._run_paths import RunPaths\n", "RunPaths")

    # B17: a gated name in prose — message, schema or help text — builds no path. A text
    # match on `defender._run_paths` or on the import line in the comment would flag this.
    mentioned = textwrap.dedent('''
        """Explains `defender._run_paths.RunLayout` and `RunPaths` without importing either."""
        # from defender._run_paths import RunLayout   <- a comment, not an import
        HELP = "run layouts live in defender._run_paths (RunLayout, RUN_LAYOUT, RunPaths)"
        SCHEMA = {"layout": "defender._run_paths.RunLayout"}

        def explain(name):
            raise ValueError(f"{name} is not a RunLayout member; see defender._run_paths")
    ''')
    found = _scan_one(tmp_path / "strings", S.OUTSIDER, mentioned)
    assert not S.flags(found, S.OUTSIDER), S.displays(found)
    assert _flagged(tmp_path, "strings-control", S.OUTSIDER, mentioned + IMPORT_GATED)


_UNREADABLE_LINT = """
    import json
    from pathlib import Path
    from defender.tests._by_path import load_lint_gate
    found = load_lint_gate("lint_run_layout_imports").scan(Path(ROOT))
    print(json.dumps([getattr(f, "display", str(f)) for f in found]))
"""


def test_1105_lint_reports_unreadable_files_and_stale_entries_and_keeps_sweeping(tmp_path):
    """`lint_run_layout_imports` reports a swept file holding bytes that are not UTF-8 or a NUL,
    and one it cannot read at all (mode 000 or a broken symlink), the way it reports an
    unparseable file, and the sweep continues: a gated import in a later file is still flagged.
    A `CATEGORIES` or allow-list entry naming a file that does not exist is itself reported.
    """
    root = S.lint_root(tmp_path)
    bad = {
        "learning/ops/aa_undecodable.py": b"X = '\xff\xfe'\n",
        "learning/ops/ab_nul.py": b"X = 1\x00\n",
    }
    for rel, data in bad.items():
        S.plant(root, rel, data)
    link = root / "learning" / "ops" / "ac_broken_link.py"
    link.symlink_to(tmp_path / "no-such-module.py")
    closed = S.plant(root, "learning/ops/ad_mode_000.py", "X = 1\n")
    later = S.plant(root, "runtime/zz_1105_later.py", IMPORT_GATED)
    closed.chmod(0)
    with S.restoring_modes(closed):
        displays = S.unprivileged(_UNREADABLE_LINT.replace("ROOT", repr(str(root))),
                                  cwd=tmp_path)
    text = "\n".join(displays)
    for rel in [*bad, "learning/ops/ac_broken_link.py", "learning/ops/ad_mode_000.py"]:
        assert rel in text, (rel, text)
    assert any("runtime/zz_1105_later.py" in d and "RunLayout" in d for d in displays), text
    assert str(later.relative_to(root)) in text

    members = S.category_members()
    stale = next(m for ms in members.values() for m in ms if not (root / m).exists())
    assert stale in text, (stale, text)


#: `lint_run_records`' sweep, as that lint declares it (§7 F7): these trees plus the top-level
#: `defender/*.py`, tests excluded — and the run-layout lint adds `run_service`.
SIBLING_SWEEP = ("runtime", "learning", "scripts", "evals", "hooks")


def test_1105_lint_sweep_is_the_sibling_lint_sweep_plus_run_service(tmp_path):
    """the run-layout lint sweeps exactly `lint_run_records`' directories (`runtime`,
    `learning`, `scripts`, `evals`, `hooks` and the top-level `defender/*.py`, tests excluded)
    plus `run_service`. A gated import planted in a top-level module such as
    `defender/host_env.py` is reached, one planted under `defender/skills/` is not, and
    `CATEGORIES` carries no entry for `skills/invlang/corpus.py`.
    """
    root = S.lint_root(tmp_path)
    planted = {d: S.plant(root, f"{d}/zz_1105_sweep.py", "X = 1\n")
               for d in (*SIBLING_SWEEP, "run_service", "skills", "tests")}
    top = S.plant(root, "host_env.py", IMPORT_GATED)
    skill = S.plant(root, "skills/invlang/zz_1105_skill.py", IMPORT_GATED)
    swept = {p.resolve() for p in S.lint().sweep_files(root)}
    sibling = {p.resolve() for p in load_lint_gate("lint_run_records").sweep_files(root)}
    assert swept == sibling | {planted["run_service"].resolve()}, sorted(swept ^ sibling)
    assert planted['skills'].resolve() not in swept
    assert planted['tests'].resolve() not in swept
    assert top.resolve() in swept
    assert skill.resolve() not in swept

    found = S.lint_findings(root)
    assert S.flags(found, "host_env.py", "RunLayout"), S.displays(found)
    assert not S.flags(found, "skills/invlang/zz_1105_skill.py"), S.displays(found)
    members = S.category_members()
    assert not any("skills/invlang/corpus.py" in ms for ms in members.values()), members

