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
  owner (named FILE BY FILE: `run_repository/_lookup.py`, `_held.py`, `_handle.py` and
  `_episode_handle.py`), however the name is reached; no call from outside to an owner
  module-level function that opens a door itself, and no owner package imported by a string
  (contract repair r1, adversary F2: a new `run_repository/_compat.open_at(path)` laundered
  the path opens past the folder-wide exemption); no `_io` path opener (`bind`, `hold`,
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

#: The repository's walk owner: the only production MODULES that may hold an episode folder by
#: an `Episode` door, named file by file (relative to `defender/`). Adversary F2: exempting the
#: whole `run_repository/` folder let a new module there (`_compat.open_at(path)`) launder a
#: path open for any caller. A new module that must open an `Episode` joins this list by a
#: reviewed contract repair.
WALK_OWNER = ("run_repository/_lookup.py", "run_repository/_held.py",
              "run_repository/_handle.py", "_episode_handle.py")
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
    return rel in WALK_OWNER


def _parsed(root: Path) -> list[tuple[str, ast.Module, object]]:
    """`(rel, tree, env)` of every production source file under `root`: `_astlib.source_files`
    (tracked plus untracked, unignored `.py`), `tests/` and virtualenvs dropped."""
    out = []
    for rel in _astlib.source_files(root, (".venv", "__pycache__", "node_modules", "tests")):
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        module, package = _astlib.module_and_package(rel, root="defender")
        out.append((rel, tree, _astlib.module_env(tree, module, package)))
    return out


def _door_wrappers(parsed: list[tuple[str, ast.Module, object]]) -> frozenset[str]:
    """The dotted names of the owner's MODULE-LEVEL functions that call an episode door
    themselves: a caller outside the owner reaching one opens an `Episode` at whatever path it
    hands over (adversary F2: `open_at(path)` / `create_at(path)` beside the walk)."""
    wrappers = set()
    for rel, tree, env in parsed:
        if not _owned(rel):
            continue
        module, _package = _astlib.module_and_package(rel, root="defender")
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                    isinstance(call, ast.Call)
                    and (_astlib.callee(call, env) or "").endswith(DOORS)
                    for call in ast.walk(node)):
                wrappers.add(f"{module}.{node.name}")
    return frozenset(wrappers)


def _is_path_call(node: ast.expr, env) -> bool:
    """`Path(...)` / `pathlib.Path(...)`, the name resolved."""
    if not isinstance(node, ast.Call):
        return False
    called = _astlib.callee(node, env)
    return called is not None and called.endswith("pathlib.Path")


def census(root: Path) -> list[Hit]:
    """Every episode opener under `root` (the `defender/` folder, or a planted tree) outside
    the walk's owner (`WALK_OWNER`, file by file):

    * `door`: a call resolving to `Episode.open` / `Episode.create` (imported by name, through
      a module alias, or inside a function) — a path handed to the episode handle;
    * `laundered`: a call resolving to one of the owner's module-level functions that calls a
      door itself (`_door_wrappers`);
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
                if not isinstance(node, ast.Call):
                    continue
                called = _astlib.callee(node, env)
                if called is None:
                    continue
                if called.endswith(DOORS):
                    hits.append(Hit(rel, node.lineno, "door", ast.unparse(node.func)))
                elif called in wrappers:
                    hits.append(Hit(rel, node.lineno, "laundered", ast.unparse(node.func)))
                elif called in IMPORTERS and node.args and isinstance(
                        node.args[0], ast.Constant) and str(node.args[0].value).startswith(
                        OWNER_PACKAGES):
                    hits.append(Hit(rel, node.lineno, "dynamic", ast.unparse(node)))
                elif called in PATH_OPENERS and not rel.startswith(REBIND_EXEMPT) and (
                        rel in REBIND_MODULES or (node.args and R.spells(
                            node.args[0], "episode", values))):
                    hits.append(Hit(rel, node.lineno, "rebind", ast.unparse(node)))
    return sorted(hits)


def test_no_production_code_opens_an_episode_by_path_outside_the_walk():
    """S-iso / O8 (review F4): production source has no `Episode.open` / `Episode.create` call
    outside the run repository's walk files, no laundered door (an owner wrapper called from
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
    shape by shape. Adversary F2's laundering shapes too: a door in a NEW `run_repository/`
    module (only the named walk files are the owner); a module-level wrapper in an owner file
    (`open_at(path)`) called from outside; an owner package imported by a string; a local
    alias (`d = Path(episode_dir); bind(d)`, and `hold`) outside; and, in a re-bind module, a
    bind or hold of ANY argument. Not reported: the same shapes inside an owner file, an
    outside call to an owner function that opens no door, a `bind(Path(settings))` in an
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
            "from defender.run_repository._lookup import helper, open_at\n"
            "\n"
            "\n"
            "def c(episode_dir):\n"
            "    d = Path(episode_dir)\n"
            "    with _io.bind(d) as bound, _io.hold(episode_dir / 'runs', follow=False) as h:\n"
            "        pass\n"
            "    one = open_at(d)\n"
            "    two = __import__('defender.run_repository._lookup', fromlist=['x'])\n"
            "    three = importlib.import_module('defender._episode_handle')\n"
            "    return bound, h, one, two, three, helper(d)\n"),
        "run_repository/_compat.py": (
            "from defender._episode_handle import Episode\n"
            "\n"
            "\n"
            "def create_at(path):\n"
            "    return Episode.create(path, exclusive=True)\n"),
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
            "    return path\n"),
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
    assert found.count(("run_repository/_compat.py", "door")) == 1, found
    assert found.count(("pkg/laundry.py", "rebind")) == 2, found
    assert found.count(("pkg/laundry.py", "laundered")) == 1, found
    assert found.count(("pkg/laundry.py", "dynamic")) == 2, found
    assert len([f for f in found if f[0] == "pkg/laundry.py"]) == 5, found
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
