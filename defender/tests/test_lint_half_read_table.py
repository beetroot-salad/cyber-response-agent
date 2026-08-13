"""The lint gate for the half-read policy table: lint_half_read_table (#879).

The gate AST-scans defender/ for a boundary that branches on ONE key of another module's
keyed gate table, spelled as a string literal, leaving that table's other keys with no reader
there — then runs the shared _baseline.gate ratchet.

Driven through the testability seam the shipped gates carry, never against the real tree
except in the one `gate`-marked regression:
  - main(argv, *, scope=..., baseline_path=...) -> exit code
  - _scan(scope) -> list[Finding]

The fixtures below are deliberately a matched PAIR at every turn: each "this fires" test has
a near-miss twin that must stay clean, because a detector keyed on a construction boundary is
only worth having if the boundary is where it says it is. The blind spots the module docstring
names (a consumer that enumerates EVERY key; a value-collision on a short generic key) are
pinned here too — a documented hole that nothing pins is a hole that quietly closes or widens.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.tests._by_path import import_lint_lib, load_lint_gate

_ASTLIB = import_lint_lib("_astlib")
_GATE = load_lint_gate("lint_half_read_table")


# The owner: two keys, each with its own answer, reached through a generic lookup. That
# lookup is what ARMS the table — without it there is no owner's answer to route through.
_OWNER = (
    "def _check_benign(body):\n"
    "    return []\n"
    "\n"
    "def _check_false_positive(body):\n"
    "    return []\n"
    "\n"
    "_DISPOSITION_GATES = {\n"
    '    "benign": _check_benign,\n'
    '    "false-positive": _check_false_positive,\n'
    "}\n"
    "\n"
    "def entry_price(disposition, body):\n"
    "    checker = _DISPOSITION_GATES.get(disposition)\n"
    "    return checker(body) if checker is not None else []\n"
)

# The consumer: imports the owner, then re-decides ONE row of its table locally.
_CONSUMER = (
    "from owner import entry_price\n"
    "\n"
    "def close(disposition, body):\n"
    '    if disposition == "false-positive":\n'
    "        return entry_price(disposition, body)\n"
    "    return None\n"
)


def _pyfile(tree: Path, rel: str, src: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def _write_baseline(path: Path, fingerprints: list[str], reason: str = "test") -> None:
    path.write_text(
        json.dumps({"//": "test", "entries": {fp: reason for fp in fingerprints}}) + "\n",
        encoding="utf-8",
    )


def _tree(tmp_path: Path, owner: str = _OWNER, consumer: str = _CONSUMER) -> Path:
    tree = tmp_path / "scope"
    _pyfile(tree, "owner.py", owner)
    _pyfile(tree, "consumer.py", consumer)
    return tree


# --------------------------------------------------------------- (a) it fires


def test_fires_on_a_half_read_table(tmp_path):
    findings = _GATE._scan(_tree(tmp_path))
    assert len(findings) == 1
    (finding,) = findings
    assert finding.fingerprint == (
        "consumer.py:close:owner._DISPOSITION_GATES:unread:benign"
    ), "fingerprint is file:function:owner.TABLE:unread:KEY"
    assert "consumer.py:4:" in finding.display
    assert "'benign' has no reader here" in finding.display


def test_fingerprint_carries_no_line_number(tmp_path):
    """The ratchet's contract: moving the branch down the file must not mint a new entry."""
    before = _GATE._scan(_tree(tmp_path))
    padded = "x = 1\n" * 20 + _CONSUMER
    after = _GATE._scan(_tree(tmp_path / "shifted", consumer=padded))
    assert [f.fingerprint for f in before] == [f.fingerprint for f in after]
    assert before[0].display != after[0].display  # the line number moved


def test_every_unread_key_is_its_own_finding(tmp_path):
    owner = _OWNER.replace(
        '    "false-positive": _check_false_positive,\n',
        '    "false-positive": _check_false_positive,\n'
        '    "inconclusive": _check_benign,\n'
        '    "malicious": _check_benign,\n',
    )
    gaps = {f.fingerprint.rsplit(":", 1)[1] for f in _GATE._scan(_tree(tmp_path, owner=owner))}
    assert gaps == {"benign", "inconclusive", "malicious"}


def test_keys_hoisted_to_module_constants_are_the_same_table(tmp_path):
    """`str_value` resolution, the #602 rule: writing the table tidily must not be the one
    way to evade the gate."""
    owner = _OWNER.replace(
        "_DISPOSITION_GATES = {\n",
        'BENIGN = "benign"\n'
        'FALSE_POSITIVE = "false-positive"\n'
        "_DISPOSITION_GATES = {\n",
    ).replace('    "benign": _check_benign,\n', "    BENIGN: _check_benign,\n").replace(
        '    "false-positive": _check_false_positive,\n',
        "    FALSE_POSITIVE: _check_false_positive,\n",
    )
    assert _GATE._scan(_tree(tmp_path, owner=owner))


def test_match_case_and_membership_branches_count(tmp_path):
    """A branch is a branch however it is spelled — `==`, `in (...)`, `case "s":`."""
    for consumer in (
        "from owner import entry_price\n"
        "def close(d):\n"
        '    return d in ("false-positive", "other")\n',
        "from owner import entry_price\n"
        "def close(d):\n"
        "    match d:\n"
        '        case "false-positive":\n'
        "            return 1\n"
        "    return 0\n",
    ):
        tree = _tree(tmp_path / str(abs(hash(consumer))), consumer=consumer)
        assert _GATE._scan(tree), consumer


def test_module_attribute_lookup_arms_the_table(tmp_path):
    """Arming is a whole-CORPUS property: the generic read may live in a third module and
    reach the table through a resolved import (`m.T.get(...)`), not only in the owner."""
    owner = _OWNER.replace(
        "def entry_price(disposition, body):\n"
        "    checker = _DISPOSITION_GATES.get(disposition)\n"
        "    return checker(body) if checker is not None else []\n",
        "",
    )
    tree = _tree(tmp_path, owner=owner)
    assert _GATE._scan(tree) == [], "no generic read anywhere: the table is not armed"
    _pyfile(
        tree,
        "reader.py",
        "import owner\n\ndef price(d):\n    return owner._DISPOSITION_GATES.get(d)\n",
    )
    assert _GATE._scan(tree), "`owner._DISPOSITION_GATES.get(d)` must arm the table"


# ----------------------------------------------- (b) the legitimate near-misses


def test_owner_branching_on_its_own_key_is_clean(tmp_path):
    """The owner IS the place a key's meaning is decided."""
    owner = _OWNER + (
        "\ndef local(disposition):\n"
        '    return disposition == "false-positive"\n'
    )
    tree = tmp_path / "scope"
    _pyfile(tree, "owner.py", owner)
    assert _GATE._scan(tree) == []


def test_unarmed_table_is_clean(tmp_path):
    """No generic lookup anywhere means no owner's answer to route through, so a literal
    branch elsewhere is not yet borrowing anything (self-arming, per lint_borrowed_vocabulary)."""
    owner = _OWNER.replace("    checker = _DISPOSITION_GATES.get(disposition)\n", "")
    owner = owner.replace("    return checker(body) if checker is not None else []\n", "    return []\n")
    assert _GATE._scan(_tree(tmp_path, owner=owner)) == []


def test_str_to_str_map_is_a_naming_table_not_a_gate_table(tmp_path):
    owner = (
        "_DISPOSITION_GATES = {\n"
        '    "benign": "Benign",\n'
        '    "false-positive": "False positive",\n'
        "}\n"
        "\n"
        "def label(d):\n"
        "    return _DISPOSITION_GATES.get(d)\n"
    )
    assert _GATE._scan(_tree(tmp_path, owner=owner)) == []


def test_single_key_dict_is_not_a_table(tmp_path):
    owner = (
        "def _check_false_positive(body):\n"
        "    return []\n"
        "\n"
        '_DISPOSITION_GATES = {"false-positive": _check_false_positive}\n'
        "\n"
        "def entry_price(d, body):\n"
        "    return _DISPOSITION_GATES.get(d)\n"
    )
    assert _GATE._scan(_tree(tmp_path, owner=owner)) == []


def test_spread_dict_has_no_closed_key_set(tmp_path):
    owner = _OWNER.replace(
        "_DISPOSITION_GATES = {\n", "_DISPOSITION_GATES = {\n    **EXTRA,\n"
    )
    assert _GATE._scan(_tree(tmp_path, owner=owner)) == []


def test_no_import_edge_is_clean(tmp_path):
    """Key identity is VALUE-based, so the import edge is what stops every module in the tree
    that ever writes `"benign"` from being tied to this table."""
    consumer = 'def close(d):\n    if d == "false-positive":\n        return 1\n    return 0\n'
    assert _GATE._scan(_tree(tmp_path, consumer=consumer)) == []


def test_reaching_the_owners_lookup_in_the_same_function_is_clean(tmp_path):
    """A function that looks the table up generically is deciding through the owner's answer;
    a literal beside that is a special case of a decision that was made, not one taken here."""
    consumer = (
        "import owner\n"
        "\n"
        "def close(d, body):\n"
        "    checker = owner._DISPOSITION_GATES.get(d)\n"
        '    if d == "false-positive":\n'
        "        return checker\n"
        "    return checker\n"
    )
    assert _GATE._scan(_tree(tmp_path, consumer=consumer)) == []


def test_every_key_enumerated_is_a_documented_blind_spot(tmp_path):
    """Pinned, not endorsed. The detector fires on the GAP, so a consumer that spells out ALL
    of the table's keys — the fullest copy of someone else's dispatch, and the one that goes
    stale the day a key is added — produces nothing. Module docstring, "WHAT IS NOT
    MECHANIZED" (1). If this ever starts firing, the docstring is the thing to fix."""
    consumer = (
        "from owner import entry_price\n"
        "\n"
        "def close(d):\n"
        '    if d == "false-positive":\n'
        "        return 1\n"
        '    if d == "benign":\n'
        "        return 2\n"
        "    return 0\n"
    )
    assert _GATE._scan(_tree(tmp_path, consumer=consumer)) == []


def test_tests_directory_is_out_of_scope(tmp_path):
    tree = _tree(tmp_path)
    (tree / "tests").mkdir()
    _pyfile(tree, "tests/test_close.py", _CONSUMER)
    assert all("tests/" not in f.fingerprint for f in _GATE._scan(tree))


# ------------------------------------------------------------ (c) the suppression marker


def test_suppression_on_the_branch_line(tmp_path):
    consumer = _CONSUMER.replace(
        '    if disposition == "false-positive":\n',
        '    if disposition == "false-positive":  # lint-half-table: ok — entry price only\n',
    )
    assert _GATE._scan(_tree(tmp_path, consumer=consumer)) == []


def test_suppression_in_the_comment_block_above(tmp_path):
    consumer = _CONSUMER.replace(
        '    if disposition == "false-positive":\n',
        "    # lint-half-table: ok — the price is this disposition's alone;\n"
        "    # benign is gated at the investigation.md write.\n"
        '    if disposition == "false-positive":\n',
    )
    assert _GATE._scan(_tree(tmp_path, consumer=consumer)) == []


def test_a_marker_far_above_does_not_suppress(tmp_path):
    consumer = (
        "from owner import entry_price\n"
        "# lint-half-table: ok — far above, not the site's comment block\n"
        "\n"
        "def close(disposition):\n"
        "    x = 1\n"
        '    if disposition == "false-positive":\n'
        "        return x\n"
        "    return None\n"
    )
    assert _GATE._scan(_tree(tmp_path, consumer=consumer))


# ------------------------------------------------------------------- (d) ScanBlind


def test_unparseable_file_in_scope_raises_scanblind(tmp_path):
    """A gate that cannot look must not report clean (#618/#621/#652). Worse than usual here:
    an unparseable OWNER would silently disarm its table for the whole corpus."""
    tree = _tree(tmp_path)
    _pyfile(tree, "broken.py", "def f(:\n")
    with pytest.raises(_ASTLIB.ScanBlind) as exc:
        _GATE._scan(tree)
    assert "broken.py" in str(exc.value)


def test_clean_tree_still_scans(tmp_path):
    """The control: the same tree minus the unparseable file scans normally and finds the real
    site, so the raises-test cannot pass against a gate that raises unconditionally."""
    assert _GATE._scan(_tree(tmp_path))


def test_scanblind_surfaces_as_exit_2(tmp_path, capsys):
    """Exit 2 specifically, not merely non-zero: exit 1 means "the gate looked and found a
    violation", which a `!= 0` assertion would conflate with "the gate could not look"."""
    tree = _tree(tmp_path)
    _pyfile(tree, "broken.py", "def f(:\n")
    assert _GATE.main([], scope=tree, baseline_path=tmp_path / "bp.json") == 2
    assert "broken.py" in capsys.readouterr().err


def test_missing_scope_is_exit_2(tmp_path):
    assert _GATE.main([], scope=tmp_path / "not-a-dir") == 2


# ----------------------------------------------------------------------- the ratchet


def test_ratchet_contract(tmp_path):
    tree = _tree(tmp_path)
    findings = _GATE._scan(tree)
    assert findings

    empty = tmp_path / "empty.json"
    assert _GATE.main([], scope=tree, baseline_path=empty) == 1
    bp = tmp_path / "bp.json"
    _write_baseline(bp, [f.fingerprint for f in findings])
    assert _GATE.main([], scope=tree, baseline_path=bp) == 0


def test_baseline_lifecycle(tmp_path):
    tree = _tree(tmp_path)
    bp = tmp_path / "bp.json"
    assert _GATE.main(["--update-baseline"], scope=tree, baseline_path=bp) == 0
    assert bp.exists()
    # `--update-baseline` writes "" reasons, and require_reasons refuses them.
    assert _GATE.main([], scope=tree, baseline_path=bp) == 1
    _write_baseline(bp, [f.fingerprint for f in _GATE._scan(tree)], reason="issue #879")
    assert _GATE.main([], scope=tree, baseline_path=bp) == 0


def test_untriaged_baseline_entry_fails_the_gate(tmp_path):
    """`require_reasons` closes the ratchet's own escape hatch: burying a finding costs a
    sentence saying why. An annotation of "" is not an annotation."""
    tree = _tree(tmp_path)
    bp = tmp_path / "bp.json"
    _write_baseline(bp, [f.fingerprint for f in _GATE._scan(tree)], reason="   ")
    assert _GATE.main([], scope=tree, baseline_path=bp) == 1


def test_shipped_baseline_has_a_reason_for_every_entry():
    data = json.loads(
        (Path(_GATE.BASELINE_PATH)).read_text(encoding="utf-8")
    )
    assert data["entries"], "the shipped baseline is not empty — #879 is live"
    for fingerprint, reason in data["entries"].items():
        assert reason.strip(), f"{fingerprint} carries no reason"


def test_fires_on_its_motivating_finding():
    """#879 itself. A gate that does not fire on the defect it exists for is not landed — so
    this asserts the real file, function and unread key, not merely that something was found.

    Not `gate`-marked: it asserts the finding is PRESENT, which the code-smells step (which
    asserts exit 0 against the baseline) cannot.
    """
    findings = _GATE._scan()
    motivating = [
        f for f in findings
        if f.fingerprint == (
            "defender/runtime/close_tool.py:_close_investigation_async:"
            "defender.skills.invlang.validate._DISPOSITION_GATES:unread:benign"
        )
    ]
    assert motivating, [f.fingerprint for f in findings]
    assert "defender/runtime/close_tool.py:438:" in motivating[0].display
    assert "'benign' has no reader here" in motivating[0].display


@pytest.mark.gate  # covered by code-smells' "Half-read-table gate"
def test_real_tree_clean():
    """`gate`-marked: the code-smells step runs this same `main([])` over this same tree and
    blocks on it, so the `test` job's copy was pure duplicate cost on CI's critical path."""
    assert _GATE.main([]) == 0
