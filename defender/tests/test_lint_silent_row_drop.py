"""The lint gate for the silent invlang row drop: lint_silent_row_drop (#876).

The gate says a row may not leave a loop in the invlang row-carrying surface by
``continue``/``break``/bare ``return`` unless, unconditionally on that same path, a
``ParseWarning`` was raised or the row landed somewhere. What makes it a construction
boundary rather than a ban on a spelling is that the two ROLES are derived structurally —
a PROJECTOR is a class that both holds ``list[ParseWarning]`` state and raises one, a
TOKENIZER is a function whose return annotation mentions ``Block`` — so these tests carry
both directions of each role test, not just the positive one.

Driven through the testability seam the shipped gates carry:
  - ``main(argv, *, scope=None, baseline_path=None) -> exit code``
  - ``_scan(scope) -> list[Finding]``
The gate lives at repo-root ``scripts/lint/``, so its path is derived from this file.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.tests._by_path import import_lint_lib, load_lint_gate

_ASTLIB = import_lint_lib("_astlib")
_GATE = load_lint_gate("lint_silent_row_drop")


# The row container and the drop channel, as their own module — so the gate has to resolve
# `from ._types import Block` through `_astlib.origin` rather than read a spelling.
_TYPES = (
    "from dataclasses import dataclass, field\n"
    "\n"
    "@dataclass\n"
    "class Block:\n"
    "    tag: str\n"
    "    rows: list[dict] = field(default_factory=list)\n"
    "\n"
    "@dataclass\n"
    "class ParseWarning:\n"
    "    block: str\n"
    "    reason: str\n"
)

_PROJECTOR_HEAD = (
    "from ._types import Block, ParseWarning\n"
    "\n"
    "class _Projector:\n"
    "    warnings: list[ParseWarning]\n"
    "\n"
    "    def __init__(self):\n"
    "        self.warnings = []\n"
    "        self.out = {}\n"
    "\n"
    "    def _warn(self, block, reason):\n"
    "        self.warnings.append(ParseWarning(block=block, reason=reason))\n"
    "\n"
)


def _pyfile(tree: Path, rel: str, src: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def _scope(tmp_path: Path, *methods: str, name: str = "scope") -> Path:
    """A scan scope holding the row types plus a projector carrying ``methods``."""
    tree = tmp_path / name
    _pyfile(tree, "_types.py", _TYPES)
    _pyfile(tree, "parser.py", _PROJECTOR_HEAD + "".join(methods))
    return tree


def _write_baseline(path: Path, fingerprints: list[str], reason: str = "triaged") -> None:
    path.write_text(
        json.dumps({"//": "test", "entries": {fp: reason for fp in fingerprints}}) + "\n",
        encoding="utf-8",
    )


def _quals(findings) -> set[str]:
    return {f.fingerprint.split(":")[1] for f in findings}


_DROPS = (
    "    def project_drop(self, block):\n"
    "        for row in block.rows:\n"
    '            hid = row.get("id")\n'
    "            if not hid:\n"
    "                continue\n"
    '            self.out.setdefault("rows", []).append(hid)\n'
    "\n"
)

_WARNS = (
    "    def project_warned(self, block):\n"
    "        for row in block.rows:\n"
    '            hid = row.get("id")\n'
    "            if not hid:\n"
    '                self._warn(block, "row has no id")\n'
    "                continue\n"
    '            self.out.setdefault("rows", []).append(hid)\n'
    "\n"
)

_LANDS = (
    "    def project_landed(self, block):\n"
    "        for row in block.rows:\n"
    '            self.out.setdefault("rows", []).append(row)\n'
    '            if row.get("last"):\n'
    "                break\n"
    "\n"
)


# the rule


def test_the_gate_fires_on_an_unwarned_drop(tmp_path):
    findings = _GATE._scan(_scope(tmp_path, _DROPS))
    assert _quals(findings) == {"_Projector.project_drop"}
    assert "no ParseWarning" in findings[0].display


def test_a_warned_or_landed_escape_is_not_a_drop(tmp_path):
    """The legitimate near-miss shape, in both of its forms — the row was reported through
    the sanctioned channel, or it reached a destination first."""
    assert _GATE._scan(_scope(tmp_path, _WARNS + _LANDS)) == []


def test_both_verdicts_inside_one_function_family(tmp_path):
    """The discrimination that makes the detector real, and the shape of the motivating
    `_project_surviving_block` finding: warned and unwarned escapes side by side, one
    flagged and one cleared."""
    assert _quals(_GATE._scan(_scope(tmp_path, _DROPS + _WARNS))) == {
        "_Projector.project_drop"
    }


def test_a_transitive_warn_helper_clears_the_escape(tmp_path):
    """The warn-emitter set is a FIXPOINT, not a table: a helper that merely CALLS the
    warner emits too, so adding one clears its call sites with no edit to the gate."""
    helper = (
        "    def _note(self, block, rid):\n"
        '        self._warn(block, f"dropping {rid}")\n'
        "\n"
        "    def project_via_helper(self, block):\n"
        "        for row in block.rows:\n"
        '            hid = row.get("id")\n'
        "            if not hid:\n"
        "                self._note(block, hid)\n"
        "                continue\n"
        '            self.out.setdefault("rows", []).append(hid)\n'
        "\n"
    )
    assert _GATE._scan(_scope(tmp_path, helper)) == []


def test_a_landing_in_a_one_armed_if_does_not_clear(tmp_path):
    """The unconditional-path rule. A landing inside a sibling `if` the path did not take
    is not on this path; requiring it unconditionally is the conservative direction."""
    conditional = (
        "    def project_maybe(self, block):\n"
        "        for row in block.rows:\n"
        '            if row.get("keep"):\n'
        '                self.out.setdefault("rows", []).append(row)\n'
        '            if not row.get("id"):\n'
        "                continue\n"
        "\n"
    )
    assert _quals(_GATE._scan(_scope(tmp_path, conditional))) == {
        "_Projector.project_maybe"
    }


def test_suppression_marker(tmp_path):
    marked = (
        "    def project_drop(self, block):\n"
        "        for row in block.rows:\n"
        '            hid = row.get("id")\n'
        "            if not hid:\n"
        "                continue  # lint-row-drop: ok — a blank row carries nothing\n"
        '            self.out.setdefault("rows", []).append(hid)\n'
        "\n"
    )
    assert _GATE._scan(_scope(tmp_path, marked)) == []
    # The control: the same site without the marker is the finding the marker suppresses.
    assert _GATE._scan(_scope(tmp_path, _DROPS, name="unmarked"))


# the roles


_COMPANION_CARRIER = (
    "from dataclasses import dataclass, field\n"
    "from ._types import ParseWarning\n"
    "\n"
    "@dataclass\n"
    "class Companion:\n"
    "    parse_warnings: list[ParseWarning] = field(default_factory=list)\n"
    "\n"
)
_COMPANION_RAISES = (
    "    def complain(self, block):\n"
    '        self.parse_warnings.append(ParseWarning(block=block, reason="x"))\n'
    "\n"
)
_COMPANION_FILTER = (
    "    def matching(self, rows):\n"
    "        out = []\n"
    "        for row in rows:\n"
    "            if not row:\n"
    "                continue\n"
    "            out.append(row)\n"
    "        return out\n"
)


# Each row plants one module beside `_types.py` and pins the gate's whole verdict as a set
# of qualnames — empty means the shape is not this gate's business. The role anchor is the
# only thing that varies; the identical read-side filter body appears in three of the four,
# which is the point: the FILTER is never what decides.
@pytest.mark.parametrize(("case", "filename", "source", "expected"), [
    # `corpus.Companion`'s real shape: it DECLARES a `list[ParseWarning]` field but never
    # raises one, so it owns no drop channel and its read-side filters are not drops. Both
    # halves of the PROJECTOR test are required — this is the half a name list would miss.
    ("carrier-that-never-raises-is-not-a-projector", "corpus.py",
     _COMPANION_CARRIER + _COMPANION_FILTER, set()),

    # The control for the above: add a method that CONSTRUCTS the warning and the same class
    # arms — so the exemption is the missing raise, not the class.
    ("carrier-that-also-raises-is-a-projector", "corpus.py",
     _COMPANION_CARRIER + _COMPANION_RAISES + _COMPANION_FILTER, {"Companion.matching"}),

    # The TOKENIZER is resolved through `_astlib.origin`, so `from ._types import Block as B`
    # is the same case as `Block` (#602) — a gate keyed on the SPELLING would go blind on the
    # one-word rename.
    ("aliased-block-return-annotation-is-still-a-tokenizer", "tok.py",
     "from ._types import Block as B\n"
     "\n"
     "def _tokenize(body: str) -> list[B]:\n"
     "    blocks = []\n"
     "    cur = None\n"
     "    for raw in body.splitlines():\n"
     "        stripped = raw.strip()\n"
     "        if cur is None:\n"
     "            continue\n"
     "        cur.rows.append(stripped)\n"
     "    return blocks\n", {"_tokenize"}),

    # The scoping that took the rule from 61 findings to 8: a read-side filter that drops
    # nothing is not this gate's business, and only the role anchor tells them apart.
    ("function-in-neither-role-is-left-alone", "queries.py",
     "def summarize(rows) -> list[str]:\n"
     "    out = []\n"
     "    for row in rows:\n"
     "        if not row:\n"
     "            continue\n"
     "        out.append(row)\n"
     "    return out\n", set()),
], ids=lambda v: v if isinstance(v, str) and "\n" not in v and len(v) < 60 else "")
def test_only_a_role_anchor_arms_the_gate(tmp_path, case, filename, source, expected):
    """The gate fires on a function in one of two ROLES — a projector that owns a drop
    channel, or a tokenizer that returns blocks — and on nothing else. The same read-side
    filter is a drop in one role and ordinary code in another, so the role is what the scan
    has to resolve; a name list or a spelling match would get every one of these wrong."""
    tree = tmp_path / "scope"
    _pyfile(tree, "_types.py", _TYPES)
    _pyfile(tree, filename, source)
    assert _quals(_GATE._scan(tree)) == expected


# ratchet + corpus


def test_scan_and_ratchet_contract(tmp_path):
    tree = _scope(tmp_path, _DROPS)
    findings = _GATE._scan(tree)
    assert findings
    assert all("parser.py" in f.fingerprint for f in findings)
    assert all(not part.isdigit() for f in findings for part in f.fingerprint.split(":")), \
        "a fingerprint must be path + salient token, never a line number"
    assert all(f.display.split(":")[1].isdigit() for f in findings), \
        "the display line must carry a line number"

    assert _GATE.main([], scope=tree, baseline_path=tmp_path / "absent.json") == 1
    bp = tmp_path / "bp.json"
    _write_baseline(bp, [f.fingerprint for f in findings])
    assert _GATE.main([], scope=tree, baseline_path=bp) == 0
    assert _GATE.main([], scope=tmp_path / "does-not-exist") == 2


def test_an_untriaged_baseline_entry_still_fails(tmp_path):
    """`require_reasons` closes the ratchet's own escape hatch: burying a drop by running
    `--update-baseline` costs a sentence saying why it is not one."""
    tree = _scope(tmp_path, _DROPS)
    bp = tmp_path / "bp.json"
    assert _GATE.main(["--update-baseline"], scope=tree, baseline_path=bp) == 0
    assert _GATE.main([], scope=tree, baseline_path=bp) == 1, "'' must not pass"
    _write_baseline(bp, [f.fingerprint for f in _GATE._scan(tree)], reason="#876")
    assert _GATE.main([], scope=tree, baseline_path=bp) == 0


def test_unparseable_file_in_scope_raises_scanblind(tmp_path):
    """A file the gate could not read never entered the corpus, so a silent drop could sit
    in it while the gate printed 0 findings. It must raise, not shrink the corpus."""
    tree = _scope(tmp_path, _DROPS)
    _pyfile(tree, "broken.py", "def f(:\n    this is not python\n")
    with pytest.raises(_ASTLIB.ScanBlind) as exc:
        _GATE._scan(tree)
    assert "broken.py" in str(exc.value)
    assert _GATE.main([], scope=tree, baseline_path=tmp_path / "bp.json") == 2


def test_clean_tree_still_scans(tmp_path):
    """The control for the above: without the unparseable file the same tree scans normally
    and still finds the real site, so the raises-test cannot pass against a gate that raises
    unconditionally."""
    assert _quals(_GATE._scan(_scope(tmp_path, _DROPS))) == {"_Projector.project_drop"}


def test_every_finding_this_gate_was_built_on_stays_fixed():
    """The four real drops `lint_silent_row_drop` shipped with, asserted GONE — neither
    reported nor baselined.

    They were baselined at the gate's landing because that change was forbidden from editing
    `parser.py`; #876 fixed all four, so the shipped baseline now holds nothing but false
    positives. Absent-from-BOTH is the assertion that matters: a later edit that reverted a
    landing would make the site a finding again, and regenerating the baseline would then
    accept it in silence — this test is what refuses that.

    That the gate can still SEE a drop is proved by the synthetic-scope tests above
    (`test_clean_tree_still_scans` and its siblings), which build a projector with a real
    drop in it and assert the gate reports exactly that one. Nothing in the shipped tree is
    load-bearing for the gate's sight any more, which is the point of having fixed them.
    """
    reported = {f.fingerprint for f in _GATE._scan(_GATE.INVLANG)}
    baselined = json.loads(_GATE.BASELINE_PATH.read_text(encoding="utf-8"))["entries"]
    for fingerprint in (
        # F-2's two spellings — the guard was split, so both are gone.
        "defender/skills/invlang/parser.py:_tokenize_fence:continue:in_story or cur is None",
        "defender/skills/invlang/parser.py:_tokenize_fence:continue:in_story",
        "defender/skills/invlang/parser.py:_Projector._project_surviving_block:"
        "continue:not hid or is_conclude_empty_marker(hid)",
    ):
        assert fingerprint not in reported, f"{fingerprint} came back"
        assert fingerprint not in baselined, f"{fingerprint} was re-baselined"


def test_every_baseline_entry_carries_a_reason():
    """The baseline is the gate's triage record: an entry with no reason is a finding
    nobody looked at. `require_reasons` enforces it at run time; this pins it as intent.

    Not asserted non-empty any more. Every true positive the gate found is fixed, so an
    empty baseline is now a legal — and better — state, and a test demanding entries would
    stand in the way of the last two false positives being retired."""
    data = json.loads(_GATE.BASELINE_PATH.read_text(encoding="utf-8"))
    assert all(reason.strip() for reason in data["entries"].values())


@pytest.mark.gate  # covered by code-smells' "Silent invlang row drop gate"
def test_real_tree_clean():
    """`gate`-marked: the code-smells step runs this same `main([])` over this same tree and
    blocks on it, so the `test` job's copy would be duplicate cost on CI's critical path."""
    assert _GATE.main([]) == 0
