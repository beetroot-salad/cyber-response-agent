"""Tests for the lint_episode_identity gate: ids carry no composed meaning, and an episode's
folders and file names have one owner."""
from __future__ import annotations

import pytest
from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_episode_identity")


def test_the_real_tree_is_clean():
    assert _GATE.scan(_GATE.DEFENDER) == []


# Each syntax partition has an exact oracle, including import aliases and negative controls.
IDENTITY_SYNTAX = [
    ("bare-fstring", "return f'{episode_id}-{label}'", [("fstring", "{episode_id}-")]),
    ("attribute-fstring", "return f'{family.episode_id}-r2'", [("fstring", "{family.episode_id}-")]),
    ("import-alias", "return m('x')", [("ref", "mint_run_id")]),
    ("module-attribute", "return _run_id.mint_run_id('y')", [("ref", "mint_run_id")]),
    ("local-deriver", "return episode_id_for(label)", [("ref", "episode_id_for")]),
    ("world-deriver", "return family_model.world_token_for(episode_id, label)",
     [("ref", "world_token_for")]),
    ("episode-deriver", "return family_model.episode_token_for(episode_id)",
     [("ref", "episode_token_for")]),
    ("labelled-mint", "return RunId.mint(label)", [("mint-args", "defender.records.RunId.mint")]),
    ("add", "return family.episode_id + '-' + label", [("concat", "family.episode_id + '-'")]),
    ("join", "return '-'.join([episode_id, label])", [("concat", "'-'.join([episode_id, label])")]),
    ("format", "return '{}-{}'.format(episode_id, label)",
     [("concat", "'{}-{}'.format(episode_id, label)")]),
    ("percent", "return '%s-%s' % (episode_id, label)", [("concat", "'%s-%s' % (episode_id, label)")]),
    ("aliases", """    ep = episode_id
    eid: str = family.episode_id
    first = ep
    second = first
    a = f'{ep}-{label}'
    b = f'{eid}-r{n}'
    c = f'{second}-{label}'
    d = ep + '-' + label
    e = getattr(RunId, 'mint')(label)
    if (w := family.episode_id):
        return f'{w}-x'
    return a, b, c, d, e""", [
        ("fstring", "{ep}-"), ("fstring", "{eid}-"), ("fstring", "{second}-"),
        ("concat", "ep + '-'"), ("mint-args", "defender.records.RunId.mint"), ("fstring", "{w}-")]),
    ("composer", "return compose(family.episode_id, label)",
     [("composer", "compose(family.episode_id, label)")]),
    ("class-attribute", """class Holder:
    def __init__(self, family):
        self._eid = family.episode_id
    def arm(self, label):
        return f'{self._eid}-{label}'""", [("fstring", "{self._eid}-")]),
    ("constant", "RUN_ID_MAX_BYTES = 206", [("def", _GATE.BANNED_CONSTANT)]),
    ("re-export", "__all__ = ['episode_id_for']", [("str", "episode_id_for")]),
    ("ordinary-text", """    note = f'{label}-{n} for {episode_id} - done'
    joined = '-'.join([label, str(n)]) + label + '-x' + episode_id
    said = 'episode %s - %s' % (episode_id, n)
    return note, f'{episode_id}', RunId.mint(), joined, said""", []),
    ("separate-scopes", """def binds(episode_id):
    ep = episode_id
    return ep
def other_scope(label, n):
    ep = label
    return f'{ep}-{n}', getattr(RunId, 'mint')()""", []),
    ("ordinary-composer", """def stamp(prefix, n):
    return f'{prefix}-{n}'
def uses_stamp(label, n):
    return stamp(label, n)""", []),
    ("ordinary-attribute", """class Plain:
    def __init__(self, label):
        self._label = label
    def name(self, n):
        return f'{self._label}-{n}'""", []),
    ("unused-definition", "def mint_run_id():\n    return RunId.mint()", []),
]


@pytest.mark.parametrize(("name", "source", "expected"), IDENTITY_SYNTAX, ids=[c[0] for c in IDENTITY_SYNTAX])
def test_id_census_syntax_partitions(tmp_path, name, source, expected):
    import textwrap

    prefix = ("from defender._run_id import mint_run_id as m\n"
              "from defender.records import _family as family_model\n"
              "from defender import _run_id\nfrom defender.records import RunId\n"
              "def episode_id_for(src):\n    return src\n"
              "def compose(eid, label):\n    joined = eid\n    return f'{joined}-{label}'\n")
    if source.startswith(("class ", "def ", "RUN_", "__all__")):
        module = source
    else:
        body = textwrap.indent(textwrap.dedent(source), "    ")
        module = "def check(family, episode_id, label, n):\n" + body
    path = tmp_path / "probe.py"
    path.write_text(prefix + module + "\n", encoding="utf-8")
    found = [(hit.kind, hit.what) for hit in _GATE.census(tmp_path)]
    assert sorted(found) == sorted(expected), (name, found)


def test_the_id_census_leaves_tests_out(tmp_path):
    root = tmp_path / "planted"
    (root / "tests").mkdir(parents=True)
    (root / "tests" / "old.py").write_text(
        "def f(episode_id, label):\n    return f'{episode_id}-{label}'\n", encoding="utf-8")

    assert _GATE.census(root) == []
    assert [h.kind for h in _GATE.census(root, skip_tests=False)] == ["fstring"]


def test_a_folder_made_by_its_path_in_the_walk_owner_is_found_and_a_held_root_is_not(tmp_path):
    planted = tmp_path / "planted"
    (planted / "records").mkdir(parents=True)
    (planted / "records" / "_lookup.py").write_text(
        "import os\n"
        "from pathlib import Path\n"
        "\n"
        "\n"
        "def claim(episodes, episode_id, fd, held):\n"
        "    import os as _os\n"
        "    _os.makedirs(episodes / episode_id, exist_ok=True)\n"
        "    os.mkdir(episodes)\n"
        "    Path(episodes).mkdir(parents=True, exist_ok=True)\n"
        "    folder = Path(episodes)\n"
        "    folder.mkdir()\n"
        "    os.mkdir(episode_id, dir_fd=fd)\n"
        "    held.mkdir(episode_id)\n",
        encoding="utf-8")
    reported = _GATE.folders_made_by_path(planted)
    assert len(reported) == 4, reported
    assert not any("dir_fd" in line or "held.mkdir" in line for line in reported), reported


def test_the_rosters_name_is_found_outside_its_owner_and_not_in_a_docstring(tmp_path):
    planted = tmp_path / "planted"
    files = {
        "records/_episode_paths.py": f'ARM_ROSTER_NAME = "{_GATE.ROSTER_NAME}"\n',
        "records/_lookup.py": f'ROSTER = "{_GATE.ROSTER_NAME}"\n',
        "presentation/page.py": (
            f'def roster(ep):\n    """Reads {_GATE.ROSTER_NAME}."""\n'
            f'    return f"{{ep}}/{_GATE.ROSTER_NAME}"\n'),
        "clean.py": f'"""Mentions {_GATE.ROSTER_NAME} in a docstring only."""\nX = "family.yaml"\n',
    }
    for rel, text in files.items():
        (planted / rel).parent.mkdir(parents=True, exist_ok=True)
        (planted / rel).write_text(text, encoding="utf-8")
    assert _GATE.roster_name_spellings(planted) == [
        "presentation/page.py:3", "records/_lookup.py:1"]


def test_the_rules_report_under_their_own_names(tmp_path):
    (tmp_path / "records").mkdir()
    (tmp_path / "records" / "_lookup.py").write_text(
        "import os\ndef claim(p):\n    os.makedirs(p)\n", encoding="utf-8")
    (tmp_path / "records" / "_episode_paths.py").write_text("X = 1\n", encoding="utf-8")
    (tmp_path / "presentation.py").write_text(
        "R = 'arms.json'\ndef f(episode_id, label):\n    return f'{episode_id}-{label}'\n",
        encoding="utf-8")
    kinds = sorted(line.split(":", 1)[0] for line in _GATE.scan(tmp_path))
    assert kinds == ["id-meaning", "owner-folders", "roster-name"]


def test_an_unparseable_module_is_blind_not_skipped(tmp_path):
    (tmp_path / "bad.py").write_text("def (:\n", encoding="utf-8")
    with pytest.raises(_GATE._astlib.ScanBlind):
        _GATE.scan(tmp_path)


def test_main_exits_zero_when_clean_one_on_a_finding_and_two_when_blind(tmp_path, capsys):
    assert _GATE.main([]) == 0
    capsys.readouterr()
    (tmp_path / "m.py").write_text("def f(episode_id):\n    return f'{episode_id}-x'\n",
                                   encoding="utf-8")
    assert _GATE.main(["--root", str(tmp_path)]) == 1
    assert "id-meaning" in capsys.readouterr().out
    assert _GATE.main(["--root", str(tmp_path / "nothing")]) == 2
    assert "not a directory" in capsys.readouterr().err
