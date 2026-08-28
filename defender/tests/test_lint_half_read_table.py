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


# (a) it fires


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


# (b) the legitimate near-misses


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


# Consumers the gate must leave alone. Each is a shape that LOOKS like a half-read of the
# owner's table until you ask the question the detector actually asks.
@pytest.mark.parametrize(("case", "consumer"), [
    # Key identity is VALUE-based, so the IMPORT EDGE is what stops every module in the tree
    # that ever writes `"benign"` from being tied to this table.
    ("no-import-edge",
     'def close(d):\n    if d == "false-positive":\n        return 1\n    return 0\n'),

    # A function that looks the table up generically is deciding through the OWNER's answer;
    # a literal beside that is a special case of a decision that was made, not one taken here.
    ("reaches-the-owners-lookup-in-the-same-function",
     "import owner\n"
     "\n"
     "def close(d, body):\n"
     "    checker = owner._DISPOSITION_GATES.get(d)\n"
     '    if d == "false-positive":\n'
     "        return checker\n"
     "    return checker\n"),

    # Pinned, not endorsed. The detector fires on the GAP, so a consumer that spells out ALL
    # of the table's keys — the fullest copy of someone else's dispatch, and the one that goes
    # stale the day a key is added — produces nothing. Module docstring, "WHAT IS NOT
    # MECHANIZED" (1). If this ever starts firing, the docstring is the thing to fix.
    ("every-key-enumerated-is-a-documented-blind-spot",
     "from owner import entry_price\n"
     "\n"
     "def close(d):\n"
     '    if d == "false-positive":\n'
     "        return 1\n"
     '    if d == "benign":\n'
     "        return 2\n"
     "    return 0\n"),
], ids=lambda v: v if isinstance(v, str) and len(v) < 60 and "\n" not in v else "")
def test_a_consumer_the_gate_leaves_alone(tmp_path, case, consumer):
    """Not every literal beside an owned key is a half-read: without the import edge there is
    no table to half-read, with the owner's lookup in hand the decision was delegated, and a
    consumer that enumerates every key has copied the dispatch whole."""
    assert _GATE._scan(_tree(tmp_path, consumer=consumer)) == []


def test_tests_directory_is_out_of_scope(tmp_path):
    tree = _tree(tmp_path)
    (tree / "tests").mkdir()
    _pyfile(tree, "tests/test_close.py", _CONSUMER)
    assert all("tests/" not in f.fingerprint for f in _GATE._scan(tree))


# (c) the suppression marker


# The marker is scoped to ITS OWN SITE — the branch line, or the comment block directly above
# it. A marker anywhere else in the module is not this site's answer, and a gate that honoured
# it would let one stale comment disarm every half-read below it.
@pytest.mark.parametrize(("case", "consumer", "suppressed"), [
    ("marker-on-the-branch-line",
     _CONSUMER.replace(
         '    if disposition == "false-positive":\n',
         '    if disposition == "false-positive":  # lint-half-table: ok — entry price only\n',
     ), True),
    ("marker-in-the-comment-block-directly-above",
     _CONSUMER.replace(
         '    if disposition == "false-positive":\n',
         "    # lint-half-table: ok — the price is this disposition's alone;\n"
         "    # benign is gated at the investigation.md write.\n"
         '    if disposition == "false-positive":\n',
     ), True),
    # ... and the same marker hoisted to module level, separated from the site by a blank
    # line and a def, suppresses NOTHING.
    ("marker-far-above-is-not-the-sites-comment-block",
     "from owner import entry_price\n"
     "# lint-half-table: ok — far above, not the site's comment block\n"
     "\n"
     "def close(disposition):\n"
     "    x = 1\n"
     '    if disposition == "false-positive":\n'
     "        return x\n"
     "    return None\n", False),
], ids=lambda v: v if isinstance(v, str) and len(v) < 60 and "\n" not in v else "")
def test_the_marker_suppresses_only_at_its_own_site(tmp_path, case, consumer, suppressed):
    """A deliberate half-read is suppressed by a marker ON the branch line or in the comment
    block immediately above it — and by a marker nowhere else."""
    assert (_GATE._scan(_tree(tmp_path, consumer=consumer)) == []) is suppressed


# (d) ScanBlind


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


# the ratchet


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


def _shipped_baseline_entries() -> dict[str, str]:
    return json.loads(Path(_GATE.BASELINE_PATH).read_text(encoding="utf-8"))["entries"]


def test_shipped_baseline_has_a_reason_for_every_entry():
    entries = _shipped_baseline_entries()
    assert entries, "an empty baseline makes this test vacuous — assert something or delete it"
    for fingerprint, reason in entries.items():
        assert reason.strip(), f"{fingerprint} carries no reason"


def test_the_scan_still_produces_exactly_what_the_shipped_baseline_buries():
    """The real-tree POSITIVE control, and the only test that has one since #879 stopped
    being a live finding.

    `test_real_tree_clean` and `test_its_motivating_finding_is_fixed_and_not_baselined` both
    assert an ABSENCE, so a scanner that regressed into finding nothing on the real tree
    passes both — and the synthetic fixtures cannot catch that, because they exercise a tree
    this gate's import-edge and key-identity rules never have to resolve for real. Equality
    (rather than "something was found") also catches the other direction: a baseline entry
    that no longer fires is a burial the ratchet is still carrying."""
    assert {f.fingerprint for f in _GATE._scan()} == set(_shipped_baseline_entries())


def test_its_motivating_finding_is_fixed_and_not_baselined():
    """#879 itself, now closed. `_close_investigation_async` charged the `false-positive`
    entry price by branching on the literal, leaving `benign` — the table's other key —
    with no reader at the close; it now dispatches through `disposition_entry_price`, which
    reads `_DISPOSITION_GATES` whole.

    Asserted on the SCAN, not merely on the baseline: dropping the entry while the branch
    stood would fail `test_real_tree_clean` but would not say why, and re-introducing the
    literal branch under a fresh baseline entry would pass it. Both halves are pinned —
    nothing fires at that site, and the ratchet is not hiding one that does.

    Not `gate`-marked: the code-smells step's exit-0 check covers the tree being clean; this
    covers the ONE site the gate was written for being clean for the right reason.
    """
    at_the_close = [
        f for f in _GATE._scan()
        if f.fingerprint.startswith("defender/runtime/close_tool.py:")
    ]
    assert at_the_close == [], [f.display for f in at_the_close]
    assert not any(
        fp.startswith("defender/runtime/close_tool.py:")
        for fp in _shipped_baseline_entries()
    ), "#879 was fixed — a close_tool entry here means the branch came back and was buried"


@pytest.mark.gate  # covered by code-smells' "Half-read-table gate"
def test_real_tree_clean():
    """`gate`-marked: the code-smells step runs this same `main([])` over this same tree and
    blocks on it, so the `test` job's copy was pure duplicate cost on CI's critical path."""
    assert _GATE.main([]) == 0
