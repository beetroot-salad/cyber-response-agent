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
  owner (`run_repository/`, and `_episode_handle.py` itself), however the name is reached; no
  `_io.bind(...)` over an episode folder — an argument that spells `episode`, or, in the five
  re-bind sites' modules, any `Path(...)` — outside that owner. Its own planted positive
  control proves each shape is seen.
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

#: The repository's walk owner: the only production code that may hold an episode folder by
#: an `Episode` door (relative to `defender/`; a folder prefix ends in `/`).
WALK_OWNER = ("run_repository/", "_episode_handle.py")
#: Exempt from the `rebind` rule only: the one-time command holds the operator-named OLD
#: episodes root "following its spelling, as configuration" (design Flow 6, S-move) — a path
#: bind the design asks for, of a folder outside every tenant. It may not open an `Episode`.
REBIND_EXEMPT = ("ops/",)
#: The modules holding the design's path re-binds of the episode folder (recheck S2).
REBIND_MODULES = frozenset({"learning/branch/episode.py", "learning/judge/__init__.py",
                            "learning/judge/family.py", "learning/judge/render.py"})
#: The episode door methods.
DOORS = ("Episode.open", "Episode.create")

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
    return any(rel == own or (own.endswith("/") and rel.startswith(own)) for own in WALK_OWNER)


def _is_path_call(node: ast.expr, env) -> bool:
    """`Path(...)` / `pathlib.Path(...)`, the name resolved."""
    if not isinstance(node, ast.Call):
        return False
    called = _astlib.callee(node, env)
    return called is not None and called.endswith("pathlib.Path")


def census(root: Path) -> list[Hit]:
    """Every episode opener under `root` (the `defender/` folder, or a planted tree) outside
    the walk's owner:

    * `door`: a call resolving to `Episode.open` / `Episode.create` (imported by name, through
      a module alias, or inside a function) — a path handed to the episode handle;
    * `rebind`: a call resolving to `defender._io.bind` whose argument spells `episode`
      (`episode_dir`, `Path(episode_dir)`, `episode.dir`), or — in one of `REBIND_MODULES` —
      whose argument is any `Path(...)` — except under `ops/` (`REBIND_EXEMPT`, Flow 6).

    The listing is `_astlib.source_files` (tracked plus untracked, unignored `.py`), `tests/`
    and virtualenvs dropped."""
    root = Path(root)
    hits: list[Hit] = []
    for rel in _astlib.source_files(root, (".venv", "__pycache__", "node_modules", "tests")):
        if _owned(rel):
            continue
        _text, tree = _astlib.read_and_parse(root / rel, rel)
        module, package = _astlib.module_and_package(rel, root="defender")
        env = _astlib.module_env(tree, module, package)
        with _astlib.scan_guard(rel):
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                called = _astlib.callee(node, env)
                if called is None:
                    continue
                if called.endswith(DOORS):
                    hits.append(Hit(rel, node.lineno, "door", ast.unparse(node.func)))
                elif called == "defender._io.bind" and node.args and not rel.startswith(
                        REBIND_EXEMPT) and (
                        "episode" in ast.unparse(node.args[0])
                        or (rel in REBIND_MODULES and _is_path_call(node.args[0], env))):
                    hits.append(Hit(rel, node.lineno, "rebind", ast.unparse(node)))
    return sorted(hits)


def test_no_production_code_opens_an_episode_by_path_outside_the_walk():
    """S-iso / O8 (review F4): production source has no `Episode.open` / `Episode.create` call
    outside the run repository (the walk's owner) and no `_io.bind(...)` re-binding an episode
    folder by path — the sibling's pre-acceptance open, `preflight_replay`'s `Path` overload,
    the launcher's `-r<n>` claim, and the judge's and the comparator's re-binds are gone, each
    replaced by the walked handle. RED at base: `run.py:663`, `learning/branch/cli.py:216` and
    `:619`, `learning/branch/episode.py:158` and `:295`, `learning/judge/__init__.py:242`,
    `learning/judge/family.py:141`, `learning/judge/render.py:339`."""
    hits = census(DEFENDER)
    listing = "\n  ".join(str(h) for h in hits)
    assert hits == [], f"{len(hits)} production site(s) open an episode by path:\n  {listing}"


def test_the_opener_census_finds_what_it_is_meant_to_find(tmp_path):
    """Positive control for the census, through the same scanner and listing it runs on
    production: a planted tree holding each shape — a door by name, through a module alias,
    and imported inside a function; a re-bind by `Path(episode_dir)`, by a bare `episode_dir`,
    by `.dir` through a module alias, and by any `Path(...)` in a re-bind module — is reported
    shape by shape; the same shapes under `run_repository/`, a `bind(Path(settings))` in an
    ordinary module, and the one-time command's bind of the old episodes root under `ops/`, are
    not — while a door under `ops/` still is."""
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
        "learning/judge/family.py": (
            "from pathlib import Path\n"
            "from defender._io import bind\n"
            "\n"
            "\n"
            "def raw_manifest(folder):\n"
            "    with bind(Path(folder)) as bound:\n"
            "        return bound\n"),
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
            "    return Episode.open(episode_dir), bind(Path(episode_dir))\n"),
    }
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")

    found = [(h.rel, h.kind) for h in census(root)]
    assert found.count(("pkg/dirty.py", "door")) == 3, found
    assert found.count(("pkg/dirty.py", "rebind")) == 3, found
    assert found.count(("learning/judge/family.py", "rebind")) == 1, found
    assert found.count(("ops/retire_legacy_runs.py", "door")) == 1, found
    assert ("ops/retire_legacy_runs.py", "rebind") not in found, found
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
