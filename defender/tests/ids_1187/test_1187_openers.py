"""#1187 S-iso — the episode openers outside the repository's walk go (review round 1, F4).

Design rev 2 (#1187 comments 6192137519 / 6192137980), Security, S-iso: "Openers outside the
repository that must go (review U5) ... the sibling's pre-acceptance `Episode.open(episode_dir)`
(`run.py:660-663`); `preflight_replay`'s `Path` overload, `Episode.open(Path(episode))`
(`cli.py:618-621`). Both are replaced by the walk. Write-tests pins that no production
`Episode.open`/`Episode.create` takes a path outside the repository's walk." And (recheck S2):
the judge and the comparator re-open the episode by path with `_io.bind(Path(episode_dir))`
(`learning/branch/episode.py:157`, `:294`; `learning/judge/__init__.py:242`;
`learning/judge/family.py:141`; `learning/judge/render.py:339`), which follows the root's
spelling; they are "bound off the episode handle the repository's walk returned, not re-bound
from its `.dir` path".

Two arms:

* The census (static, over production source, through `scripts/lint/_astlib.py`'s resolver, as
  `test_1187_ids`' census): no call to `Episode.open` / `Episode.create` outside the walk's
  owner (the `run_repository/` folder and `_episode_handle.py`, `_spec1187.WALK_OWNER`),
  however the name is reached; no call from outside to an owner function or method that opens
  a door at a path it is handed (wrappers of wrappers, static and instance methods too), and
  no owner package imported by a string (adversary F2: a new `run_repository/_compat.
  open_at(path)` is inside the folder, so the callers are what is policed); no `_io` path opener (`bind`, `hold`,
  `hold_new`) over an episode folder — an argument that spells `episode`, directly or through
  a local alias — outside that owner, and none at all in the five re-bind sites' modules. Its
  own planted positive control proves each shape is seen.
* The behaviour: pre-flight (`cli.preflight_replay`) handed a path to `<T>/episodes/<ep>` that
  is a LINK to a real episode elsewhere reads nothing through it; reached through the walk, the
  same pre-flight runs.

RED at base: the census finds the eight sites above; the linked pre-flight follows the link and
calibrates the target.
"""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass
from pathlib import Path

from defender.tests import _by_path
from defender.tests.ids_1187 import _spec1187 as R
from defender.tests.live_oracle_1224 import _spec1224 as S
from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P

DEFENDER = Path(__file__).resolve().parents[2]

#: The repository's walk owner is `_spec1187.WALK_OWNER`, the one definition the made-by-path
#: census shares: the whole `run_repository/` folder and `_episode_handle.py`. A door inside the
#: owner is the walk's own; what the census polices is the owner's PATH-TAKING doors reached
#: from outside (`laundered`), however deep the wrappers nest (adversary F2).
#: The owner's dotted packages: imported BY A STRING (`__import__`, `importlib.import_module`)
#: outside the owner, a door no resolver can follow (adversary F2's `run.py` laundering).
OWNER_PACKAGES = ("defender.run_repository", "defender._episode_handle")
#: Exempt from the `rebind` rule only: the one-time command holds the operator-named OLD
#: episodes root "following its spelling, as configuration" (design Flow 6, S-move) — a path
#: bind the design asks for, of a folder outside every tenant. It may not open an `Episode`.
REBIND_EXEMPT = ("ops/",)
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


def _owned(rel: str) -> bool:
    return R.owned(rel)


def _parsed(root: Path) -> list[tuple[str, ast.Module, object]]:
    """`(rel, tree, env)` of every production source file under `root`: `_astlib.source_files`
    (tracked plus untracked, unignored `.py`), `tests/` and virtualenvs dropped."""
    out = []
    for rel in _astlib.source_files(root, (".venv", "__pycache__", "node_modules", "tests")):
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        module, package = _astlib.module_and_package(rel, root="defender")
        out.append((rel, tree, _astlib.module_env(tree, module, package)))
    return out


def _passes_a_parameter(arg: ast.expr, params: set[str], values: dict) -> bool:
    """Is `arg` a parameter of the function, bare or wrapped in `Path(...)`, or a local name
    bound (transitively) to one? The path a wrapper hands a door unchanged."""
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
    """`(dotted names, bare method names)` of the owner's functions that open an episode door at
    a PATH THEY ARE HANDED: a function (module-level, or a static/class/instance method) whose
    call to a door — or to another such wrapper, to a fixpoint — passes one of its own
    parameters (bare, or in `Path(...)`) in the path position. A caller outside the owner
    reaching one opens an `Episode` wherever it points (adversary F2: `open_at(path)`,
    `create_at(path)`; round 2: wrappers of wrappers, and methods). A function taking an id
    and deriving the path itself (`EpisodeRuns.__init__`) is not one. An INSTANCE method is
    matched by its bare name at the call (the receiver's class cannot be resolved statically);
    a module-level function or a class's static/class method by its dotted origin."""
    names: set[str] = set()
    methods: set[str] = set()
    defs = [(env, owner, node, is_method)
            for rel, tree, env in parsed if _owned(rel)
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
    """Does `node` call a door, or a known wrapper (by dotted origin, or an instance method by
    bare name), handing it one of `node`'s own parameters as the path?"""
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
    """`(owner dotted name, def, is a method)` for every module-level function (owner = the
    module) and every method of a module-level class (owner = `<module>.<Class>`)."""
    out = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((module, node, False))
        elif isinstance(node, ast.ClassDef):
            out.extend((f"{module}.{node.name}", m, True) for m in node.body
                       if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)))
    return out


def _is_path_call(node: ast.expr, env) -> bool:
    """`Path(...)` / `pathlib.Path(...)`, the name resolved."""
    if not isinstance(node, ast.Call):
        return False
    called = _astlib.callee(node, env)
    return called is not None and called.endswith("pathlib.Path")


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
    if called in PATH_OPENERS and not rel.startswith(REBIND_EXEMPT) and (
            rel in REBIND_MODULES or (node.args and R.spells(node.args[0], "episode", values))):
        return "rebind", ast.unparse(node)
    return None


def census(root: Path) -> list[Hit]:
    """Every episode opener under `root` (the `defender/` folder, or a planted tree) outside
    the walk's owner (`_spec1187.WALK_OWNER`: the `run_repository/` folder and
    `_episode_handle.py`):

    * `door`: a call resolving to `Episode.open` / `Episode.create` (imported by name, through
      a module alias, or inside a function) — a path handed to the episode handle;
    * `laundered`: a call to one of the owner's functions or methods that opens a door at a
      path it is handed, or hands one to another such wrapper, to a fixpoint
      (`_door_wrappers`); an instance method is matched by its bare name;
    * `dynamic`: `__import__` / `importlib.import_module` of a string naming an owner package
      — a door nothing can resolve;
    * `rebind`: a call resolving to a path opener of `_io` (`bind`, `hold`, `hold_new`) — in
      one of `REBIND_MODULES`, ANY such call; elsewhere, one whose argument spells `episode`,
      directly or through a local name bound to something that does (`d = Path(episode_dir);
      bind(d)`) — except under `ops/` (`REBIND_EXEMPT`, Flow 6).

    The listing is `_astlib.source_files` (tracked plus untracked, unignored `.py`), `tests/`
    and virtualenvs dropped."""
    parsed = _parsed(Path(root))
    wrappers = _door_wrappers(parsed)
    hits: list[Hit] = []
    for rel, tree, env in parsed:
        if _owned(rel):
            continue
        with _astlib.scan_guard(rel):
            for node, values in R.scoped_nodes(tree):
                if isinstance(node, ast.Call) and (kind := _kind(node, rel, env, values,
                                                                  wrappers)):
                    hits.append(Hit(rel, node.lineno, kind[0], kind[1]))
    return sorted(hits)


def test_no_production_code_opens_an_episode_by_path_outside_the_walk():
    """S-iso / O8 (review F4): production source has no `Episode.open` / `Episode.create` call
    outside the run repository's walk owner, no laundered door (an owner wrapper called from
    outside, an owner package imported by a string), and no `_io` path opener re-binding an
    episode folder by path — the sibling's pre-acceptance open, `preflight_replay`'s `Path`
    overload, the launcher's `-r<n>` claim, and the judge's and the comparator's re-binds are
    gone, each replaced by the walked handle. RED at base: `run.py:663`,
    `learning/branch/cli.py:216` and `:619`, `learning/branch/episode.py:158` and `:295`,
    `learning/judge/__init__.py:242`, `learning/judge/family.py:141`,
    `learning/judge/render.py:339`. Against adversary F2's tree (a `_compat` module, a string
    import in `run.py`, `d = Path(episode_dir); bind(d)`) it reads those eight again."""
    hits = census(DEFENDER)
    listing = "\n  ".join(str(h) for h in hits)
    assert hits == [], f"{len(hits)} production site(s) open an episode by path:\n  {listing}"


def test_the_opener_census_finds_what_it_is_meant_to_find(tmp_path):
    """Positive control for the census, through the same scanner and listing it runs on
    production: a planted tree holding each shape — a door by name, through a module alias,
    and imported inside a function; a re-bind by `Path(episode_dir)`, by a bare `episode_dir`,
    by `.dir` through a module alias, and by any `Path(...)` in a re-bind module — is reported
    shape by shape. Adversary F2's laundering shapes too: a module-level wrapper in the owner
    (`open_at(path)`, including one in a NEW `run_repository/` module) called from outside; a
    wrapper of a wrapper; a static method and an instance method that open a door at a path
    they are handed; an owner package imported by a string; a local
    alias (`d = Path(episode_dir); bind(d)`, and `hold`) outside; and, in a re-bind module, a
    bind or hold of ANY argument. Not reported: the same shapes inside an owner file, an
    outside call to an owner function that opens no door or derives its path from an id, a `bind(Path(settings))` in an
    ordinary module, and the one-time command's bind of the old episodes root under `ops/` —
    while a door under `ops/` still is."""
    root = tmp_path / "planted"
    files = {
        "pkg/dirty.py": (
            "from pathlib import Path\n"
            "from defender._episode_handle import Episode\n"
            "from defender import _episode_handle as EH\n"
            "from defender._io import bind\n"
            "from defender import _io\n"
            "\n"
            "\n"
            "def a(episode_dir, view):\n"
            "    held = Episode.open(Path(episode_dir))\n"
            "    made = EH.Episode.create(episode_dir, exclusive=True)\n"
            "    with bind(Path(episode_dir)) as one, bind(episode_dir) as two:\n"
            "        pass\n"
            "    return held, made, _io.bind(view.episode.dir), one, two\n"
            "\n"
            "\n"
            "def b(folder):\n"
            "    from defender._episode_handle import Episode as Door\n"
            "    return Door.open(folder)\n"),
        "pkg/laundry.py": (
            "import importlib\n"
            "from pathlib import Path\n"
            "from defender import _io\n"
            "from defender.run_repository._lookup import EpisodeRuns, Opener, helper, open_at\n"
            "from defender.run_repository._compat import chained, derived\n"
            "\n"
            "\n"
            "def c(episode_dir):\n"
            "    d = Path(episode_dir)\n"
            "    with _io.bind(d) as bound, _io.hold(episode_dir / 'runs', follow=False) as h:\n"
            "        pass\n"
            "    one = open_at(d)\n"
            "    two = __import__('defender.run_repository._lookup', fromlist=['x'])\n"
            "    three = importlib.import_module('defender._episode_handle')\n"
            "    four = chained(d)\n"
            "    five = Opener.make(d)\n"
            "    six = Opener().take(d)\n"
            "    seven = derived('some-id')\n"
            "    return bound, h, one, two, three, helper(d), four, five, six, seven\n"),
        "run_repository/_compat.py": (
            "from pathlib import Path\n"
            "from defender._episode_handle import Episode\n"
            "from defender.run_repository._lookup import open_at\n"
            "\n"
            "\n"
            "def create_at(path):\n"
            "    return Episode.create(path, exclusive=True)\n"
            "\n"
            "\n"
            "def chained(where):\n"
            "    inner = Path(where)\n"
            "    return open_at(inner)\n"
            "\n"
            "\n"
            "def derived(episode_id):\n"
            "    return Episode.open(Path('/base') / episode_id)\n"),
        "learning/judge/family.py": (
            "from pathlib import Path\n"
            "from defender._io import bind, hold\n"
            "\n"
            "\n"
            "def raw_manifest(folder):\n"
            "    d = folder\n"
            "    with bind(Path(folder)) as bound, bind(d) as again, hold(d) as held:\n"
            "        return bound, again, held\n"),
        "pkg/clean.py": (
            "from pathlib import Path\n"
            "from defender._io import bind\n"
            "\n"
            "\n"
            "def settings(path, run_dir, episode):\n"
            "    with bind(Path(path)) as bound:\n"
            "        return bound, bind(run_dir), episode.view()\n"),
        "ops/retire_legacy_runs.py": (
            "from pathlib import Path\n"
            "from defender._io import bind\n"
            "from defender._episode_handle import Episode\n"
            "\n"
            "\n"
            "def plan(old_episodes_root, folder):\n"
            "    with bind(Path(old_episodes_root)) as held:\n"
            "        return held, Episode.open(folder)\n"),
        "run_repository/_lookup.py": (
            "from pathlib import Path\n"
            "from defender._io import bind\n"
            "\n"
            "\n"
            "def walk(episode_dir):\n"
            "    from defender._episode_handle import Episode\n"
            "    return Episode.open(episode_dir), bind(Path(episode_dir))\n"
            "\n"
            "\n"
            "def open_at(path):\n"
            "    from defender._episode_handle import Episode\n"
            "    return Episode.open(path)\n"
            "\n"
            "\n"
            "def helper(path):\n"
            "    return path\n"
            "\n"
            "\n"
            "class Opener:\n"
            "    @staticmethod\n"
            "    def make(folder):\n"
            "        from defender._episode_handle import Episode\n"
            "        return Episode.create(folder)\n"
            "\n"
            "    def take(self, folder):\n"
            "        from defender._episode_handle import Episode\n"
            "        return Episode.open(folder)\n"
            "\n"
            "\n"
            "class EpisodeRuns:\n"
            "    def __init__(self, tenant, episode_id):\n"
            "        from defender._episode_handle import Episode\n"
            "        self.episode = Episode.open(tenant.dir / episode_id)\n"),
    }
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")

    found = [(h.rel, h.kind) for h in census(root)]
    assert found.count(("pkg/dirty.py", "door")) == 3, found
    assert found.count(("pkg/dirty.py", "rebind")) == 3, found
    assert found.count(("learning/judge/family.py", "rebind")) == 3, found
    assert found.count(("ops/retire_legacy_runs.py", "door")) == 1, found
    assert ("ops/retire_legacy_runs.py", "rebind") not in found, found
    assert not [f for f in found if f[0].startswith("run_repository/")], found
    assert found.count(("pkg/laundry.py", "rebind")) == 2, found
    # open_at, chained (a wrapper of the wrapper), Opener.make (static), Opener().take
    # (instance); `derived` takes an id and `helper` opens nothing.
    assert found.count(("pkg/laundry.py", "laundered")) == 4, found
    assert found.count(("pkg/laundry.py", "dynamic")) == 2, found
    assert len([f for f in found if f[0] == "pkg/laundry.py"]) == 8, found
    assert not [f for f in found if f[0] in ("pkg/clean.py", "run_repository/_lookup.py")], found


def test_preflight_never_reads_an_episode_through_a_link(tmp_path, monkeypatch, data_root):
    """S-iso / O8 (review F4; design: `preflight_replay`'s `Path` overload goes, replaced by the
    walk). Pre-flight handed `<T>/episodes/<ep>` where that name is a LINK to a real, loadable
    episode folder elsewhere reads nothing through it: its oracle is never asked and no outcome
    record lands in the link's target (whatever it raises — a refusal, or the type error of a
    path where a handle belongs). Positive control on the same channels: the same episode
    reached through the repository's walk (`runs.episode(ep)`'s held handle) is calibrated —
    the oracle is asked and the outcome record is written. RED at base: the `Path` overload
    holds the link, following it, and calibrates the target (the channel was confirmed at base
    by a test-only probe)."""
    from defender.learning.branch import cli
    from defender.tests import _triplet_947 as T

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
