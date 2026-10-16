"""lint_ungated_artifact_write: writers of model-authored artifacts must meet their schema."""

from __future__ import annotations

from pathlib import Path


from defender.tests._by_path import load_lint_gate

_GATE = load_lint_gate("lint_ungated_artifact_write")

#: The #964 shape: compose a block, reach the write primitive directly, no schema anywhere.
_UNGATED_SEED = (
    "from defender._io import write_guarded\n"
    "from defender.run_repository import RunPaths\n"
    "\n"
    "def seed(run_dir, block):\n"
    "    path = RunPaths(run_dir).investigation\n"
    "    write_guarded(path, path.read_text() + block)\n"
)
#: The same write with the schema applied and its verdict obeyed.
_GATED_SEED = (
    "from defender._artifact_schema import INVESTIGATION_NAME, validate_artifact\n"  # lint-stale-ref: ok — FIXTURE source this gate is run against, not a live import
    "from defender._io import write_guarded\n"
    "from defender.run_repository import RunPaths\n"
    "\n"
    "def seed(run_dir, block):\n"
    "    path = RunPaths(run_dir).investigation\n"
    "    current = path.read_text()\n"
    "    proposed = current + block\n"
    "    if validate_artifact(INVESTIGATION_NAME, proposed, current) is not None:\n"  # lint-stale-ref: ok — fixture source, as above
    "        return\n"
    "    write_guarded(path, proposed)\n"
)
#: An alias must not buy a way out — the write is resolved by ORIGIN.
_ALIASED_WRITE = (
    "from defender._io import write_guarded as w\n"
    "\n"
    "def commit(run_dir, body):\n"
    '    w(run_dir / "report.md", body)\n'
)
#: The duck-typed shape: the receiver is a Path VALUE, so there is no import to resolve.
_DUCK_TYPED_WRITE = (
    "def commit(run_dir, body):\n"
    '    (run_dir / "investigation.md").write_text(body)\n'
)
#: The close's DI seam — the schema arrives as a PARAMETER, so origin resolution cannot see
#: through it and the gate has to read the name.
_INJECTED_VALIDATOR = (
    "from defender._io import write_guarded\n"
    "\n"
    "def commit(run_dir, body, validator):\n"
    '    if validator("report.md", body, None) is not None:\n'
    "        return\n"
    '    write_guarded(run_dir / "report.md", body)\n'
)
#: Routed through the permission gate, which applies the schema on the caller's behalf.
_THROUGH_THE_GATE = (
    "from defender._io import write_guarded\n"
    "from defender.runtime import permission\n"
    "\n"
    "def write_file(deps, p, content):\n"
    "    if not permission.decide_write(deps.policy, p, content).allowed:\n"
    "        return\n"
    '    if p.name == "investigation.md":\n'
    "        write_guarded(p, content)\n"
)
_SUPPRESSED = (
    "from defender._io import write_guarded\n"
    "\n"
    "def manifest(run_dir, out):\n"
    "    # lint-artifact-gate: ok — names the artifacts, writes a manifest\n"
    '    write_guarded(out, str(run_dir / "investigation.md"))\n'
)


def _pyfile(tree: Path, rel: str, src: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def _names(findings) -> set[str]:
    return {f.fingerprint for f in findings}


def test_the_two_shipped_defects_are_both_flagged(tmp_path):
    """#964's shape and a report-side sibling, each reduced to the code that made it a bug:
    a write of one of the two artifacts with no schema in the frame."""
    tree = tmp_path / "scope"
    _pyfile(tree, "runtime/lead_zero.py", _UNGATED_SEED)
    _pyfile(tree, "runtime/close_tool.py", _ALIASED_WRITE)

    assert _names(_GATE._scan(tree)) == {
        "runtime/lead_zero.py:seed", "runtime/close_tool.py:commit",
    }
    assert _GATE.main([], scope=tree, baseline_path=tmp_path / "empty.json") == 1


def test_an_alias_and_a_duck_typed_write_are_both_seen(tmp_path):
    """Neither spelling is a way out. `write_guarded as w` is resolved by ORIGIN, and
    `<path>.write_text(...)` has no origin at all — the receiver is a value — so it is matched
    as a method shape, the same way the sibling tree-write gate matches it."""
    tree = tmp_path / "scope"
    _pyfile(tree, "aliased.py", _ALIASED_WRITE)
    _pyfile(tree, "ducked.py", _DUCK_TYPED_WRITE)

    assert _names(_GATE._scan(tree)) == {"aliased.py:commit", "ducked.py:commit"}


def test_the_schema_call_is_the_clean_spelling(tmp_path):
    """LIVENESS CONTROL for the whole gate: all three sanctioned ways to meet the schema scan
    clean, so a green run means "every writer is gated" rather than "the scanner matched
    nothing".

    The injected-validator arm is the one that would break first. The close takes its schema as
    a parameter so the seam can be driven in tests, and a parameter has no import — a gate that
    resolved validators by origin alone would flag the close forever, and the flag would be
    suppressed rather than fixed.
    """
    tree = tmp_path / "scope"
    _pyfile(tree, "gated.py", _GATED_SEED)
    _pyfile(tree, "injected.py", _INJECTED_VALIDATOR)
    _pyfile(tree, "through_gate.py", _THROUGH_THE_GATE)

    assert _GATE._scan(tree) == []
    assert _GATE.main([], scope=tree, baseline_path=tmp_path / "empty.json") == 0


def test_a_write_of_some_other_file_is_not_the_gates_business(tmp_path):
    """The gate is keyed on the TWO artifacts, not on writing in general — that question is
    `lint_unguarded_tree_write`'s, and a gate that answered both would be suppressed by
    everyone who only failed one."""
    tree = tmp_path / "scope"
    _pyfile(
        tree, "other.py",
        "from defender._io import write_guarded\n"
        "\n"
        "def dump(run_dir, rows):\n"
        '    write_guarded(run_dir / "executed_queries.jsonl", rows)\n',
    )
    assert _GATE._scan(tree) == []


def test_a_nested_function_gets_its_own_verdict(tmp_path):
    """An inner def is its own frame. Folding its nodes into the enclosing function's would
    let a validation in one excuse a write in the other, in whichever direction happened to
    nest."""
    tree = tmp_path / "scope"
    _pyfile(
        tree, "nested.py",
        "from defender._artifact_schema import validate_artifact\n"
        "from defender._io import write_guarded\n"
        "\n"
        "def outer(run_dir, body):\n"
        '    validate_artifact("report.md", body, None)\n'
        "\n"
        "    def inner():\n"
        '        write_guarded(run_dir / "report.md", body)\n'
        "\n"
        "    return inner\n",
    )
    assert _names(_GATE._scan(tree)) == {"nested.py:inner"}


def test_the_schema_owner_and_tests_are_exempt(tmp_path):
    """The module that OWNS the schema cannot be required to call it, and test modules build
    ungated writes deliberately. The owner is exempt by full relative PATH — a second
    `_artifact_schema.py` elsewhere under the scope is not the canonical one."""
    tree = tmp_path / "scope"
    _pyfile(tree, "_artifact_schema.py", _UNGATED_SEED)
    _pyfile(tree, "test_writer.py", _UNGATED_SEED)
    _pyfile(tree, "tests/helper.py", _UNGATED_SEED)
    assert _GATE._scan(tree) == []

    _pyfile(tree, "learning/_artifact_schema.py", _UNGATED_SEED)
    assert _names(_GATE._scan(tree)) == {"learning/_artifact_schema.py:seed"}


def test_a_deliberate_site_can_be_marked(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "marked.py", _SUPPRESSED)
    assert _GATE._scan(tree) == []


def test_the_blind_spots_are_real_and_pinned(tmp_path):
    """The gate's own docstring admits two limits; both are asserted, because a limit stated
    only in prose is one people stop believing.

    CO-OCCURRENCE, NOT DATAFLOW: validating one string and writing another passes. And a write
    SPLIT ACROSS FUNCTIONS is invisible from either side — the composer names no artifact, the
    writer runs no schema, and neither frame holds both halves.

    Pinned so that if someone strengthens the gate to catch them, this test fails and says so
    rather than the improvement landing unnoticed.
    """
    tree = tmp_path / "scope"
    _pyfile(
        tree, "wrong_text.py",
        "from defender._artifact_schema import validate_artifact\n"
        "from defender._io import write_guarded\n"
        "\n"
        "def commit(run_dir, checked, actual):\n"
        '    validate_artifact("report.md", checked, None)\n'
        '    write_guarded(run_dir / "report.md", actual)\n',
    )
    _pyfile(
        tree, "split.py",
        "from defender._io import write_guarded\n"
        "\n"
        "def _land(path, text):\n"
        "    write_guarded(path, text)\n"
        "\n"
        "def compose(run_dir, block):\n"
        '    _land(run_dir / "investigation.md", block)\n',
    )
    assert _GATE._scan(tree) == [], "both limits still hold; update the docstring if not"


