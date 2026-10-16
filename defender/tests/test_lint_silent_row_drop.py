"""The lint gate for the silent invlang row drop: lint_silent_row_drop (#876)."""
from __future__ import annotations

import json

from pathlib import Path

import pytest

from defender.tests._by_path import load_lint_gate

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


def _write_baseline(path: Path, fingerprints: list[str]) -> None:
    path.write_text(
        json.dumps({"//": "test", "entries": {fp: "triaged" for fp in fingerprints}}) + "\n",
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


