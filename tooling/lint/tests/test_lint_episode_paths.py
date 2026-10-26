"""Tests for the lint_episode_paths gate: episode trees are reached only through the Episode handle
and the runs repository's walk.

The rule functions are table-driven, so most cases run a rule over the real tree with a doctored
table (a missing row must be found as a violation, a bogus row as stale) or over a planted source
string; the opener census runs over planted trees."""
from __future__ import annotations

import ast
from collections import Counter
import pytest
from _by_path import import_lint_lib, load_lint_gate

_GATE = load_lint_gate("lint_episode_paths")
_C = import_lint_lib("_census1134")
ROOT = _GATE.DEFENDER


def _view():
    return _C.tree_of(ROOT.parent)


def test_the_real_tree_is_clean():
    assert _GATE.scan(ROOT) == []


# --- D6: the migrated modules make no episode I/O but the declared residue ------------------

def _hits(rel: str, src: str):
    return _GATE.census_of(_view(), rel, ast.parse(src))


@pytest.mark.parametrize(("src", "callee"), [
    ("from pathlib import Path\ndef f(p: Path):\n    p.write_text('x')\n", ".write_text"),
    ("import os\ndef f(p):\n    os.makedirs(p)\n", "os.makedirs"),
    ("import shutil\ndef f(a, b):\n    shutil.copy2(a, b)\n", "shutil.copy2"),
    ("def f(p):\n    return open(p)\n", "builtins.open"),
    ("from defender._io import write_guarded\ndef f(p):\n    write_guarded(p, 'x')\n",
     "write_guarded"),
])
def test_episode_io_is_found_however_it_is_spelled(src, callee):
    assert ("learning.branch.cli", "f", callee) in _hits("learning/branch/cli.py", src)


def test_episode_io_is_found_through_a_module_level_alias():
    src = "import os\nmk = os.makedirs\ndef f(p):\n    mk(p)\n"
    assert ("learning.branch.cli", "f", "os.makedirs") in _hits("learning/branch/cli.py", src)


def test_a_residue_row_the_code_no_longer_needs_is_stale():
    bogus = frozenset({("learning.branch.archive", "gone_function", "shutil.copy2")})
    found = _GATE.episode_io(ROOT, residue=_GATE.RESIDUE | bogus)
    assert found == [f"episode-io: residue entry gone (remove it from RESIDUE): "
                     f"{next(iter(bogus))}"]


def test_a_call_outside_the_residue_is_a_violation():
    row = next(iter(_GATE.RESIDUE))
    found = _GATE.episode_io(ROOT, residue=_GATE.RESIDUE - {row})
    assert len(found) == 1, found
    assert "still calls" in found[0], found
    assert str(row) in found[0], found


# --- D6: the handle does I/O only through hold / hold_new ---------------------------------------

def _handle(src: str):
    io_funcs = _GATE._io_functions(ROOT)
    return _GATE.handle_scan(_view(), io_funcs, ast.parse(src))


def test_a_handle_that_goes_around_its_held_root_is_found():
    violations, core = _handle("import os\ndef f(p):\n    os.makedirs(p)\n")
    assert ("f", "os.makedirs") in violations
    assert core == set()


def test_the_handle_core_calls_are_collected_and_not_violations():
    src = ("from defender import _io\n"
           "def open_(p):\n    return _io.hold(p)\n"
           "def create(p):\n    return _io.hold_new(p)\n")
    violations, core = _handle(src)
    assert violations == []
    assert core == {"hold", "hold_new"}


def test_a_held_verb_is_not_path_io():
    violations, _core = _handle("def f(held, rel):\n    held.mkdir(rel)\n    held.unlink(rel)\n")
    assert violations == []


def test_the_io_surface_is_read_from_the_source_of_the_io_modules():
    assert {"hold", "hold_new", "move_at"} <= _GATE._io_functions(ROOT)


# --- O5: parameters that are paths below the episode dir --------------------------------------

def _params(src: str):
    return _GATE.o5_params("m", ast.parse(src))


@pytest.mark.parametrize(("src", "flagged"), [
    ("def f(manifest): ...", True),
    ("def f(draw_dir: str): ...", True),
    ("def f(draw_dir: dict[str, int]): ...", False),
    ("def f(thing_path): ...", True),
    ("from pathlib import Path\ndef f(x: Path): ...", True),
    ("from pathlib import Path\ndef f(x: Path | None = None): ...", True),
    ("def f(x: str): ...", False),
    ("def f(episode_dir): ...", False),
    ("def f(run_dir): ...", False),
    ("from pathlib import Path\ndef f(data_root: Path): ...", False),
    ("def f(path: dict[str, int]): ...", False),
    ("from pathlib import Path\nclass C:\n    def m(self, p: Path): ...", True),
])
def test_a_path_taking_parameter_is_flagged_by_name_or_type(src, flagged):
    assert bool(_params(src)) is flagged


def test_a_method_parameter_is_keyed_by_its_qualified_name():
    src = "from pathlib import Path\nclass C:\n    def m(self, p: Path): ...\n"
    assert _params(src) == {("m", "C.m", "p")}


def test_an_allowlist_row_the_code_no_longer_needs_is_stale():
    bogus = ("run", "gone", "path", "reason")
    found = _GATE.param_paths(ROOT, allowlist=_GATE.PARAM_ALLOWLIST | {bogus})
    assert len(found) == 1 and "allowlist row gone" in found[0], found


def test_a_path_taking_function_outside_the_allowlist_is_a_violation():
    found = _GATE.param_paths(ROOT, allowlist=frozenset(), tolerated=frozenset())
    assert len(found) == len(_GATE.PARAM_ALLOWLIST), found
    assert all("takes a path below the episode dir" in f for f in found), found


# --- O5: EpisodePaths / base_file / staged_path ----------------------------------------------

def _calls(src: str):
    return _GATE.o5_calls("m", ast.parse(src))


@pytest.mark.parametrize("src", [
    "from defender.episodes import EpisodePaths\ndef f(e):\n    return EpisodePaths(e)\n",
    "from defender.episodes import EpisodePaths as EP\ndef f(e):\n    return EP(e)\n",
    "def f(p):\n    return p.base_file()\n",
    "def f(p):\n    return p.staged_path('x')\n",
])
def test_a_call_of_the_episode_path_makers_is_found(src):
    assert len(_calls(src)) == 1


def test_the_path_makers_are_judged_per_enclosing_function():
    src = "def reader(p):\n    return p.base_file()\n"
    hit = next(iter(_calls(src)))
    assert _GATE._allowed(hit, {("m", "reader")})
    assert not _GATE._allowed(hit, {("m", "other")})


def test_a_reader_outside_the_list_of_root_readers_is_a_violation():
    found = _GATE.path_calls(ROOT, readers=frozenset())
    assert found, "no reader names an episode path maker?"
    assert all("outside a root-binding reader" in f for f in found), found


# --- O5: the doors ---------------------------------------------------------------------------

def _doors(src: str):
    return _GATE.o5_doors("m", ast.parse(src))


@pytest.mark.parametrize(("src", "verb"), [
    ("from defender.episodes._episode_handle import Episode\ndef f(p):\n    return Episode.open(p)\n",
     "open"),
    ("from defender.episodes._episode_handle import Episode\ndef f(p):\n    return Episode.create(p)\n",
     "create"),
    ("from defender.episodes._episode_handle import Episode\nE = Episode\ndef f(p):\n    return E.open(p)\n",
     "open"),
    ("from defender.episodes._episode_handle import Episode\nopener = Episode.open\n", "open"),
    ("def f(ep, p):\n    return type(ep).open(p)\n", "open"),
    ("from defender.episodes._episode_handle import Episode\ndef f():\n    return getattr(Episode, 'open')\n",
     "getattr"),
])
def test_a_door_is_found_however_it_is_reached(src, verb):
    assert verb in {hit[2] for hit in _doors(src)}


def test_naming_the_class_alone_is_not_a_door():
    assert _doors("from defender.episodes._episode_handle import Episode\ndef f(e: Episode): ...\n") == set()


def test_a_door_in_a_listed_module_is_a_violation_when_no_door_is_allowed():
    found = _GATE.doors(ROOT, modules=("records/_lookup.py",), allowed=frozenset())
    assert any(f.startswith("doors: opens or creates an Episode outside") for f in found), found


def test_a_required_walk_call_that_is_gone_is_found():
    required = (("learning.branch.cli", "no_such_method", None),)
    found = _GATE.doors(ROOT, required_calls=required)
    assert len(found) == 1 and "former door does not reach" in found[0], found


def test_a_walk_owner_that_stops_calling_a_door_is_found():
    found = _GATE.doors(ROOT, required_verbs=("create", "open", "teleport"))
    assert len(found) == 1 and "Episode.teleport" in found[0], found


def test_the_walk_call_census_finds_what_it_is_meant_to_find():
    good_cli = ast.parse("def launch(runs):\n    return runs.create_episode()\n")
    good_run = ast.parse("def main(runs, ep, label):\n"
                         "    return runs.episode(ep, require_roster=True)\n")
    assert _GATE._walk_calls_missing(_GATE._method_calls("learning.branch.cli", good_cli)
                               | _GATE._method_calls("run", good_run)) == []
    bare_ref = ast.parse("def launch(runs):\n    door = runs.create_episode\n    return door\n")
    no_kw = ast.parse("def main(runs, ep):\n    return runs.episode(ep)\n")
    assert _GATE._walk_calls_missing(_GATE._method_calls("learning.branch.cli", bare_ref)
                               | _GATE._method_calls("run", no_kw)) == [
        ("learning.branch.cli", "create_episode", None), ("run", "episode", "require_roster")]
    elsewhere = _GATE._method_calls("learning.judge", good_cli) | _GATE._method_calls("learning.judge", good_run)
    assert len(_GATE._walk_calls_missing(elsewhere)) == 2


# --- a listed module that is gone, or unparseable, is blind, never skipped --------------------

def test_a_listed_module_that_does_not_exist_is_blind(tmp_path):
    with pytest.raises(_GATE._astlib.ScanBlind, match="does not exist"):
        _GATE._read(tmp_path, "learning/branch/cli.py")


def test_a_listed_module_that_does_not_parse_is_blind(tmp_path):
    (tmp_path / "learning" / "branch").mkdir(parents=True)
    (tmp_path / "learning" / "branch" / "cli.py").write_text("def (:\n", encoding="utf-8")
    with pytest.raises(_GATE._astlib.ScanBlind):
        _GATE._read(tmp_path, "learning/branch/cli.py")


def test_a_root_that_is_not_a_directory_is_blind(tmp_path):
    with pytest.raises(_GATE._astlib.ScanBlind):
        _GATE.scan(tmp_path / "nothing")


# --- #1187: the opener census over planted trees ---------------------------------------------

# Shared owner definitions make wrapper propagation observable in each independent caller.
OWNER_PROGRAMS = {
    "records/_lookup.py": """from pathlib import Path
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
    "records/_held.py": """from pathlib import Path
from defender.episodes._episode_handle import Episode
from defender.records._lookup import open_at
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
from defender.records._lookup import EpisodeRuns, Opener, helper, open_at
from defender.records._held import chained, derived
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
    b = __import__('defender.records._lookup', fromlist=['x'])
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
    files = {**OWNER_PROGRAMS, rel: CALLER_IMPORTS + body}
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    hits = _GATE.opener_census(tmp_path)
    assert Counter(hit.kind for hit in hits if hit.rel == rel) == expected
    assert not [hit for hit in hits if hit.rel in OWNER_PROGRAMS], hits




def test_a_production_file_under_tests_is_not_swept(tmp_path):
    path = tmp_path / "tests" / "t.py"
    path.parent.mkdir()
    path.write_text("from defender.episodes._episode_handle import Episode\n"
                    "def f(p):\n    return Episode.open(p)\n", encoding="utf-8")
    assert _GATE.opener_census(tmp_path) == []


def test_main_reports_findings_with_exit_one_and_clean_with_zero(capsys):
    assert _GATE.main([]) == 0
    assert "0 finding(s)" in capsys.readouterr().out


def test_main_exits_two_when_it_cannot_scan(tmp_path, capsys):
    assert _GATE.main(["--root", str(tmp_path / "nothing")]) == 2
    assert "not a directory" in capsys.readouterr().err
