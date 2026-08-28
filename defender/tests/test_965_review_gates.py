"""The two gates and the two typed boundaries that came out of the #965 review.

Each of the four is a rule the review found the tree stating correctly in prose and not
enforcing anywhere. What is tested here is the ENFORCEMENT, so these are all "does the refusal
happen", not "is the rule a good one".
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender._run_id import is_case_stable_id, is_valid_run_id
from defender.tests._by_path import load_lint_gate

READ_GATE = load_lint_gate("lint_tree_read_follows_link")
FIELDS_GATE = load_lint_gate("lint_dataclass_fields")

REPO_ROOT = Path(__file__).resolve().parents[2]
LINT_DIR = REPO_ROOT / "scripts" / "lint"


def _empty_baseline(tmp_path: Path) -> Path:
    """A baseline with no entries, so a run against a fixture reports what it FOUND rather
    than what the repo has already accepted."""
    path = tmp_path / "baseline.json"
    path.write_text(json.dumps({"entries": {}}), encoding="utf-8")
    return path


def _scope(tmp_path: Path, files: dict[str, str]) -> Path:
    scope = tmp_path / "scope"
    for rel, body in files.items():
        target = scope / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")
    return scope


def _run(gate, tmp_path: Path, files: dict[str, str]) -> int:
    return gate.main(
        [], scope=_scope(tmp_path, files), baseline_path=_empty_baseline(tmp_path),
    )


# lint_tree_read_follows_link

def test_a_link_following_admit_check_in_a_tree_reader_is_refused(tmp_path: Path) -> None:
    """`is_file()` answers about a link's TARGET, so admitting on it admits whatever the model
    pointed the link at. This is the shape that copied a planted link's bytes into every
    sibling run dir under the case alert's own name."""
    assert _run(READ_GATE, tmp_path, {"run_common.py": (
        "from pathlib import Path\n"
        "def go(p: Path) -> bool:\n"
        "    return p.is_file()\n"
    )}) == 1


def test_an_aliased_copy_is_the_same_finding_as_the_spelled_one(tmp_path: Path) -> None:
    """Resolved by CALLEE, not by spelling — the hole `_astlib` exists to close. A gate that
    matched `shutil.copy2(...)` textually would be blind to the import that renames it."""
    assert _run(READ_GATE, tmp_path, {"run_common.py": (
        "from shutil import copy2 as cp\n"
        "def go(a, b):\n"
        "    cp(a, b)\n"
    )}) == 1


def test_the_lstat_helpers_are_not_findings(tmp_path: Path) -> None:
    """`artifact_file`/`artifact_dir` are the answer the gate points at; flagging them would
    make the fix unreachable."""
    assert _run(READ_GATE, tmp_path, {"run_common.py": (
        "from defender._run_paths import artifact_dir, artifact_file\n"
        "def go(p):\n"
        "    return artifact_file(p) or artifact_dir(p)\n"
    )}) == 0


def test_a_refuse_if_present_exists_check_is_not_a_finding(tmp_path: Path) -> None:
    """The asymmetry the gate is built on. Following a link in an ADMIT check admits its
    target; following one in a REFUSE check fails closed, and `exists() or is_symlink()` is
    this tree's established spelling for it. Flagging it would bury the real findings."""
    assert _run(READ_GATE, tmp_path, {"run_common.py": (
        "def go(p):\n"
        "    if p.exists() or p.is_symlink():\n"
        "        raise SystemExit('occupied')\n"
    )}) == 0


def test_a_module_outside_the_reader_census_is_not_scanned(tmp_path: Path) -> None:
    """`is_file()` on a config path or a fixture is ordinary everywhere else in the tree. The
    positive census is what keeps this gate's baseline small enough to be read."""
    assert _run(READ_GATE, tmp_path, {"runtime/providers.py": (
        "def go(p):\n"
        "    return p.is_file()\n"
    )}) == 0


def test_the_marker_clears_a_site_whose_guard_is_on_the_line_above(tmp_path: Path) -> None:
    """The sanctioned exception, and the reason the marker must sit on the CALL's own lines:
    a copy whose `artifact_file` screen is right above it is correct, and says so there."""
    assert _run(READ_GATE, tmp_path, {"run_common.py": (
        "import shutil\n"
        "from defender._run_paths import artifact_file\n"
        "def go(a, b):\n"
        "    if artifact_file(a):\n"
        "        shutil.copy2(a, b)  # lint-tree-read-follows-link: ok — screened above\n"
    )}) == 0


def test_the_repo_itself_passes_the_read_gate() -> None:
    """The shipped baseline is accurate and fully annotated — `require_reasons` is on, so an
    entry someone adds later without saying why fails with the force of a new finding."""
    assert READ_GATE.main([]) == 0


def test_every_read_gate_baseline_entry_carries_a_reason() -> None:
    entries = json.loads(
        (LINT_DIR / "lint_tree_read_follows_link_baseline.json").read_text(encoding="utf-8")
    )["entries"]
    assert entries, "an empty baseline here would mean the census stopped matching the tree"
    assert all(reason.strip() for reason in entries.values())


# lint_dataclass_fields

def test_the_raw_field_mapping_is_refused(tmp_path: Path) -> None:
    """It also holds ClassVar/InitVar pseudo-fields, which the generated `__init__` does not
    accept — so splatting it into `replace()` raises from a line that reads as total."""
    assert _run(FIELDS_GATE, tmp_path, {"m.py": (
        "def names(x):\n"
        "    return list(type(x).__dataclass_fields__)\n"
    )}) == 1


def test_the_getattr_spelling_is_the_same_finding(tmp_path: Path) -> None:
    """Same attribute, different door."""
    assert _run(FIELDS_GATE, tmp_path, {"m.py": (
        'def names(x):\n'
        '    return getattr(x, "__dataclass_fields__")\n'
    )}) == 1


def test_naming_the_attribute_in_prose_is_not_a_finding(tmp_path: Path) -> None:
    """The string form is read off a `getattr`/`hasattr` call's arguments, not off every
    literal in the file — otherwise a docstring explaining the ban would be a violation of it,
    this gate's own included."""
    assert _run(FIELDS_GATE, tmp_path, {"m.py": (
        '"""Never read __dataclass_fields__; use dataclasses.fields()."""\n'
        'MSG = "__dataclass_fields__"\n'
    )}) == 0


def test_the_dataclasses_helper_is_not_a_finding(tmp_path: Path) -> None:
    assert _run(FIELDS_GATE, tmp_path, {"m.py": (
        "from dataclasses import fields\n"
        "def names(x):\n"
        "    return [f.name for f in fields(x)]\n"
    )}) == 0


def test_the_repo_itself_passes_the_fields_gate_on_an_empty_baseline() -> None:
    """Ships EMPTY, and the test says so: there is no legitimate production use of the raw
    mapping in this tree, so any entry appearing here later is a decision, not drift."""
    entries = json.loads(
        (LINT_DIR / "lint_dataclass_fields_baseline.json").read_text(encoding="utf-8")
    )["entries"]
    assert entries == {}
    assert FIELDS_GATE.main([]) == 0


# the case-stable id rule

@pytest.mark.parametrize("run_id", ["base", "w1", "2026-05-25t15.30.45z-alert"])
def test_an_already_folded_id_is_case_stable(run_id: str) -> None:
    assert is_case_stable_id(run_id)


@pytest.mark.parametrize("run_id", ["Base", "W1", "wA"])
def test_an_id_carrying_upper_case_is_not(run_id: str) -> None:
    """`is_valid_run_id` admits these — that is the point. They are two ids to every string
    compare in the repo and one file wherever the filesystem folds case, which is how a world
    called `Base` reaches the family's immutable capture through `served/base.jsonl`."""
    assert is_valid_run_id(run_id)
    assert not is_case_stable_id(run_id)


def test_a_world_id_carrying_upper_case_is_refused_at_the_mint() -> None:
    """At the MINT, where the world docstring says every id rule belongs: refused later, the
    cost is a primed episode and however many siblings already ran against a live model."""
    from defender.learning.branch import cli

    with pytest.raises(SystemExit) as caught:
        cli.World(world_id="Base")
    assert "base" in str(caught.value)


def test_an_episode_id_carrying_upper_case_is_refused() -> None:
    """The same rule, because the two are joined into one run id and an episode id names the
    one directory holding the family's capture."""
    from defender.learning.branch import cli

    with pytest.raises(SystemExit):
        cli.refuse_bad_episode_id("Ep1")


# the outbound-body type

def test_the_wire_takes_only_a_body_that_went_past_the_clock() -> None:
    """Both minting functions consult `ctx.as_of`; `_http_json` accepts what they return and
    nothing else. mypy is what enforces the second half — this pins the first, so a mint that
    quietly stopped asking the clock fails here rather than in a branched run's evidence."""
    import inspect

    from defender.scripts.adapters import elastic_adapter as ea

    assert "body: OutboundBody | None" in inspect.getsource(ea._http_json)
    for mint in (ea._search_body, ea._esql_body):
        # The module is `from __future__ import annotations`, so signatures carry the NAME.
        assert inspect.signature(mint).return_annotation == "OutboundBody"
        first = next(iter(inspect.signature(mint).parameters))
        assert first == "ctx", f"{mint.__name__} must take the ctx that carries the clock"


def test_the_esql_mint_carries_the_bound_and_the_payload_does_not() -> None:
    """The split the verb's own comment argues for: the bound rides the wire, the record keeps
    what the model asked. Pinned together because they are one decision."""
    from defender.scripts.adapters import elastic_adapter as ea

    class _Ctx:
        as_of = None

    asked = "FROM logs-* | LIMIT 5"
    assert ea._esql_body(_Ctx(), asked).payload == {"query": asked}
    assert ea.esql_payload(asked, {"values": [], "columns": []})["query"] == asked
