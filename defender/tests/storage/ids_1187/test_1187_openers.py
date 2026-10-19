"""Episode consumers use repository walks rather than opening or rebinding paths."""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path

import pytest

from defender.tests.support.shared.contracts import _by_path
from defender.tests.storage.ids_1187 import _spec1187 as R
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P

DEFENDER = Path(__file__).resolve().parents[3]

#: The repository's walk owner is `_spec1187.WALK_OWNER`, the one definition the made-by-path
#: census shares: the whole `run_repository/` folder and `_episode_handle.py`. A door inside the
#: owner is the walk's own; what the census polices is the owner's PATH-TAKING doors reached
#: from outside (`laundered`), however deep the wrappers nest (adversary F2).
#: The owner's dotted packages: imported BY A STRING (`__import__`, `importlib.import_module`)
#: outside the owner, a door no resolver can follow (adversary F2's `run.py` laundering).
OWNER_PACKAGES = ("defender.run_repository", "defender.episodes._episode_handle")
#: Exempt from the `rebind` rule only: the one-time command holds the operator-named OLD
#: episodes root "following its spelling, as configuration" (design Flow 6, S-move) — a path
#: bind the design asks for, of a folder outside every tenant. It may not open an `Episode`.
REBIND_EXEMPT = ("cli/retire_legacy_runs.py",)
#: The modules holding the design's path re-binds of the episode folder (recheck S2). Once the
#: re-binds are routed through the walked handle these modules open NO folder by a path, so
#: every path opener there is reported, whatever its argument is called (adversary F2:
#: `d = Path(episode_dir); bind(d)` spells no `episode` at the call).
REBIND_MODULES = frozenset({"learning/branch/episode.py", "learning/judge/__init__.py",
                            "learning/judge/family.py", "learning/judge/render.py"})
#: The episode door methods.
DOORS = ("Episode.open", "Episode.create")
#: `_io`'s openers of a folder by its PATH (each follows the path's spelling above its leaf).
PATH_OPENERS = ("defender._io.bind", "defender._io.hold", "defender._io.hold_new")
#: Dynamic importers.
IMPORTERS = ("builtins.__import__", "importlib.import_module")

_astlib = _by_path.import_lint_lib("_astlib")


@dataclass(frozen=True, order=True)
class Hit:
    """One opener the census found: where, which kind, and the call as written."""

    rel: str
    line: int
    kind: str
    what: str

    def __str__(self) -> str:
        return f"{self.rel}:{self.line} {self.kind} {self.what}"


def _parsed(root: Path) -> list[tuple[str, ast.Module, object]]:
    """Parse production files and resolve their module bindings for the opener census."""
    out = []
    for rel in _astlib.source_files(root, (".venv", "__pycache__", "node_modules", "tests")):
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        module, package = _astlib.module_and_package(rel, root="defender")
        out.append((rel, tree, _astlib.module_env(tree, module, package)))
    return out


def _passes_a_parameter(arg: ast.expr, params: set[str], values: dict) -> bool:
    """Is `arg` a parameter of the function, bare or wrapped in `Path(...)`, or a local name bound (transitively) to one?"""
    while isinstance(arg, ast.Call) and len(arg.args) == 1 and (
            (isinstance(arg.func, ast.Name) and arg.func.id == "Path")
            or (isinstance(arg.func, ast.Attribute) and arg.func.attr == "Path")):
        arg = arg.args[0]
    if isinstance(arg, ast.Name):
        if arg.id in params:
            return True
        return any(_passes_a_parameter(v, params, values) for v in values.get(arg.id, ()))
    return False


def _door_wrappers(parsed: list[tuple[str, ast.Module, object]]) -> tuple[frozenset[str],
                                                                       frozenset[str]]:
    """Find owner functions and methods that pass a parameter to an episode opener."""
    names: set[str] = set()
    methods: set[str] = set()
    defs = [(env, owner, node, is_method)
            for rel, tree, env in parsed if R.owned(rel)
            for owner, node, is_method in _functions(
                tree, _astlib.module_and_package(rel, root="defender")[0])]
    grew = True
    while grew:
        grew = False
        for env, owner, node, is_method in defs:
            dotted = f"{owner}.{node.name}"
            if dotted not in names and _opens_at_a_parameter(node, env, names, methods):
                names.add(dotted)
                if is_method:
                    methods.add(node.name)
                grew = True
    return frozenset(names), frozenset(methods)


def _opens_at_a_parameter(node, env, names: set[str], methods: set[str]) -> bool:
    """Check whether an episode opener or wrapper receives a function parameter."""
    params = {a.arg for a in (*node.args.posonlyargs, *node.args.args,
                              *node.args.kwonlyargs)} - {"self", "cls"}
    values = R.bound_values(node)
    for call in ast.walk(node):
        if not isinstance(call, ast.Call) or not call.args:
            continue
        called = _astlib.callee(call, env) or ""
        bare = call.func.attr if isinstance(call.func, ast.Attribute) else None
        wrapper = called.endswith(DOORS) or called in names or (bare in methods and not called)
        if wrapper and _passes_a_parameter(call.args[0], params, values):
            return True
    return False


def _functions(tree: ast.Module, module: str) -> list[tuple[str, ast.FunctionDef, bool]]:
    """Enumerate module functions and class methods with their dotted owners."""
    out = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((module, node, False))
        elif isinstance(node, ast.ClassDef):
            out.extend((f"{module}.{node.name}", m, True) for m in node.body
                       if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)))
    return out


def _kind(node: ast.Call, rel: str, env, values: dict,
          wrappers: tuple[frozenset[str], frozenset[str]]) -> tuple[str, str] | None:
    """`(kind, what)` of the opener `node` is, or `None` (see `census`)."""
    names, methods = wrappers
    called = _astlib.callee(node, env)
    if called is None:
        if node.args and isinstance(node.func, ast.Attribute) and node.func.attr in methods:
            return "laundered", ast.unparse(node.func)
        return None
    if called.endswith(DOORS):
        return "door", ast.unparse(node.func)
    if called in names:
        return "laundered", ast.unparse(node.func)
    if called in IMPORTERS and node.args and isinstance(node.args[0], ast.Constant) and str(
            node.args[0].value).startswith(OWNER_PACKAGES):
        return "dynamic", ast.unparse(node)
    if called in PATH_OPENERS and rel not in REBIND_EXEMPT and (
            rel in REBIND_MODULES or (node.args and R.spells(node.args[0], "episode", values))):
        return "rebind", ast.unparse(node)
    return None


def census(root: Path) -> list[Hit]:
    """Find episode openers and path rebinding outside the repository walk owners."""
    parsed = _parsed(Path(root))
    wrappers = _door_wrappers(parsed)
    hits: list[Hit] = []
    for rel, tree, env in parsed:
        if R.owned(rel):
            continue
        with _astlib.scan_guard(rel):
            for node, values in R.scoped_nodes(tree):
                if isinstance(node, ast.Call) and (kind := _kind(node, rel, env, values,
                                                                  wrappers)):
                    hits.append(Hit(rel, node.lineno, kind[0], kind[1]))
    return sorted(hits)


def test_no_production_code_opens_an_episode_by_path_outside_the_walk():
    hits = census(DEFENDER)
    listing = "\n  ".join(str(h) for h in hits)
    assert hits == [], f"{len(hits)} production site(s) open an episode by path:\n  {listing}"


# Shared owner definitions make wrapper propagation observable in each independent caller.
OWNER_PROGRAMS = {
    "run_repository/_lookup.py": """from pathlib import Path
from defender.episodes._episode_handle import Episode
from defender._io import bind
def walk(episode_dir):
    return Episode.open(episode_dir), bind(Path(episode_dir))
def open_at(path):
    return Episode.open(path)
def helper(path):
    return path
class Opener:
    @staticmethod
    def make(folder):
        return Episode.create(folder)
    def take(self, folder):
        from defender.episodes._episode_handle import Episode as Door
        return Door.open(folder)
class EpisodeRuns:
    def __init__(self, tenant, episode_id):
        self.episode = Episode.open(tenant.dir / episode_id)
""",
    "run_repository/_compat.py": """from pathlib import Path
from defender.episodes._episode_handle import Episode
from defender.run_repository._lookup import open_at
def create_at(path):
    return Episode.create(path, exclusive=True)
def chained(where):
    inner = Path(where)
    return open_at(inner)
def derived(episode_id):
    return Episode.open(Path('/base') / episode_id)
""",
}
CALLER_IMPORTS = """import importlib
from pathlib import Path
from defender.episodes._episode_handle import Episode
from defender.episodes import _episode_handle as EH
from defender import _io
from defender._io import bind, hold
from defender.run_repository._lookup import EpisodeRuns, Opener, helper, open_at
from defender.run_repository._compat import chained, derived
"""
OPENER_CASES = [
    ("pkg/dirty.py", """def direct(episode_dir, view):
    a = Episode.open(Path(episode_dir))
    b = EH.Episode.create(episode_dir, exclusive=True)
    with bind(Path(episode_dir)) as one, bind(episode_dir) as two:
        return a, b, _io.bind(view.episode.dir), one, two
def local(folder):
    from defender.episodes._episode_handle import Episode as Door
    return Door.open(folder)
""", {"door": 3, "rebind": 3}),
    ("pkg/laundry.py", """def launder(episode_dir):
    d = Path(episode_dir)
    with _io.bind(d) as bound, _io.hold(episode_dir / 'runs', follow=False) as h:
        pass
    a = open_at(d)
    b = __import__('defender.run_repository._lookup', fromlist=['x'])
    c = importlib.import_module('defender.episodes._episode_handle')
    e = chained(d)
    f = Opener.make(d)
    g = Opener().take(d)
    return bound, h, a, b, c, helper(d), e, f, g, derived('some-id')
""", {"rebind": 2, "laundered": 4, "dynamic": 2}),
    ("learning/judge/family.py", """def reader(folder):
    d = folder
    with bind(Path(folder)) as bound, bind(d) as again, hold(d) as held:
        return bound, again, held
""", {"rebind": 3}),
    ("pkg/clean.py", """def settings(path, run_dir, episode):
    with bind(Path(path)) as bound:
        return bound, bind(run_dir), episode.view()
""", {}),
    ("cli/retire_legacy_runs.py", """def plan(old_episodes_root, folder):
    with bind(Path(old_episodes_root)) as held:
        return held, Episode.open(folder)
""", {"door": 1}),
]


@pytest.mark.parametrize(("rel", "body", "expected"), OPENER_CASES, ids=[c[0] for c in OPENER_CASES])
def test_opener_census_syntax_partitions(tmp_path, rel, body, expected):
    from collections import Counter

    files = {**OWNER_PROGRAMS, rel: CALLER_IMPORTS + body}
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    hits = census(tmp_path)
    assert Counter(hit.kind for hit in hits if hit.rel == rel) == expected
    assert not [hit for hit in hits if hit.rel in OWNER_PROGRAMS], hits


def test_preflight_never_reads_an_episode_through_a_link(tmp_path, monkeypatch, data_root):
    from defender.learning.branch import cli
    from defender.tests.support.learning.branch import _triplet_947 as T

    P.roots(tmp_path, monkeypatch)
    monkeypatch.delenv(R.EPISODES_BASE_ENV, raising=False)
    est, src = P.launch_source(tmp_path, source_run_id=R.new_id())
    # Today's repository opens the source only through its container record; #1187's natural
    # container holds none (R1). The record goes once the handle is held, so pre-flight meets
    # #1187's container either way.
    source = T.open_source(src)
    (src.parent / "_tenant.json").unlink(missing_ok=True)
    rows = [S.captured(c.system, c.verb, c.params, c.payload) for c in P.source_calls()]

    def episode_at(root: Path, episode_id: str) -> Path:
        doc = S.family_v2(episode_id=episode_id, source_run_id=src.name,
                          source_run_dir=str(src))
        return S.episode_v2(tmp_path, doc=doc, root=root, episode_id=episode_id,
                            base_rows=rows)

    episodes = R.episodes_dir(data_root, P.LAUNCH_TENANT)
    linked_id = R.new_id()
    real = episode_at(tmp_path / "elsewhere", linked_id)
    episodes.mkdir(parents=True, exist_ok=True)
    os.symlink(real, episodes / linked_id, target_is_directory=True)
    oracle = S.oracle(then=S.submit(P.BASE_ANSWER, S.EMPTY_CLAIM))

    err = R.raised(cli.preflight_replay, episodes / linked_id, source=source,
                   roster=est.roster(), tenant=est.run_tenant(), oracle=oracle.model,
                   verifier=S.passing_verifier().model)
    assert not (real / "outcome.yaml").exists(), (
        f"pre-flight calibrated the episode behind a link ({err!r})")
    assert oracle.requests == 0, f"pre-flight asked its oracle through a link ({err!r})"
    assert err is not None, "pre-flight over a linked path returned as if it had run"

    walked_id = R.new_id()
    walked = episode_at(episodes, walked_id)
    control = S.oracle(then=S.submit(P.BASE_ANSWER, S.EMPTY_CLAIM))
    runs = R.tenant(data_root, P.LAUNCH_TENANT).runs_repository()
    with runs.episode(walked_id) as view:
        cli.preflight_replay(view.episode, source=source, roster=est.roster(),
                             tenant=est.run_tenant(), oracle=control.model,
                             verifier=S.passing_verifier().model)
    assert control.requests > 0, "control: pre-flight through the walk never asked its oracle"
    assert (walked / "outcome.yaml").is_file(), "control: pre-flight through the walk wrote nothing"
