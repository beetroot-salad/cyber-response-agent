"""The gate that keeps the fence-scan fold from regressing: lint_unaccounted_selection
(#932).

`scan_fences` is the one place that knows which bytes of an investigation are invlang
content, and it returns what the fences ORPHAN alongside what they hold. Three readers had
derived that split independently and all three dropped the complement in silence, which is
how a run's whole PLAN section came to sit outside a fence, parse to an empty companion, and
clear every hypothesis-side rule vacuously.

A lint whose baseline ships empty is indistinguishable from a lint that scans nothing, so
every arm is exercised against a synthetic tree here, and each violation is paired with the
clean spelling of the same read.

Driven through the gate's testability seam — `main(argv, *, scope, baseline_path)` and
`_scan(root)` — so nothing is hardcoded to a checkout path.
"""

from __future__ import annotations

import json
from pathlib import Path

from defender.tests._by_path import load_lint_gate

_GATE = load_lint_gate("lint_unaccounted_selection")

_IMPORT_ALIASED = (
    "from defender.skills.invlang.parser import INVLANG_FENCE_RE as F\n"
    "\n"
    "def f_import(text):\n"
    "    return F.findall(text)\n"
)
_ATTRIBUTE = (
    "from defender.skills.invlang import parser\n"
    "\n"
    "def f_attribute(text):\n"
    "    return parser.INVLANG_FENCE_RE.finditer(text)\n"
)
_REDERIVED = (
    "import re as regex\n"
    "\n"
    'PAT = r"```invlang\\n(.*?)\\n```"\n'
    "\n"
    "def f_rederive(text):\n"
    "    return regex.findall(PAT, text, regex.DOTALL)\n"
)
_CLEAN = (
    "from defender.skills.invlang.parser import scan_fences\n"
    "\n"
    "def f_clean(text):\n"
    "    return scan_fences(text).bodies\n"
)
_SUPPRESSED = (
    "from defender.skills.invlang.parser import INVLANG_FENCE_RE"
    "  # lint-selection: ok — counting only\n"
)


def _pyfile(tree: Path, rel: str, src: str) -> Path:
    p = tree / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(src, encoding="utf-8")
    return p


def _kinds(findings) -> set[str]:
    return {f.fingerprint.split(":")[-1] for f in findings}


def _write_baseline(path: Path, fingerprints: list[str]) -> None:
    path.write_text(
        json.dumps({"//": "test", "entries": {fp: "" for fp in fingerprints}}) + "\n",
        encoding="utf-8",
    )


def test_each_bypass_arm_is_flagged(tmp_path):
    """Both ways to reach the shared regex, and the way around it. Re-deriving the pattern
    is the arm that matters most: importing the constant at least reuses one grammar, while
    a second `re.compile` is a second grammar free to drift from the first."""
    tree = tmp_path / "scope"
    _pyfile(tree, "a_import.py", _IMPORT_ALIASED)
    _pyfile(tree, "b_attribute.py", _ATTRIBUTE)
    _pyfile(tree, "c_rederive.py", _REDERIVED)

    findings = _GATE._scan(tree)
    assert _kinds(findings) == {"import", "attribute", "regex"}
    assert _GATE.main([], scope=tree, baseline_path=tmp_path / "empty.json") == 1


def test_the_alias_does_not_hide_the_import(tmp_path):
    """`as F` binds the same object under another label, so the alias is not a way out —
    the arm reads the IMPORTED name, not the local one."""
    tree = tmp_path / "scope"
    _pyfile(tree, "aliased.py", _IMPORT_ALIASED)
    assert _kinds(_GATE._scan(tree)) == {"import"}


def test_the_canonical_module_and_tests_are_exempt(tmp_path):
    """The owner of the split must use the regex, and test modules quote both spellings.
    The exemption is by full relative PATH — a second `parser.py` elsewhere under the scope
    is exactly the copy this gate exists to stop, so a basename match would wave it in."""
    tree = tmp_path / "scope"
    _pyfile(tree, "skills/invlang/parser.py", _IMPORT_ALIASED)
    _pyfile(tree, "test_reader.py", _IMPORT_ALIASED)
    _pyfile(tree, "tests/helper.py", _IMPORT_ALIASED)
    assert _GATE._scan(tree) == []

    # ...but a parser.py somewhere else is not the canonical one.
    _pyfile(tree, "runtime/parser.py", _IMPORT_ALIASED)
    assert _kinds(_GATE._scan(tree)) == {"import"}


def test_the_helper_call_is_the_clean_spelling(tmp_path):
    """LIVENESS CONTROL for the whole gate: the read it pushes toward scans clean, so a
    green run means "nobody bypassed it" rather than "the scanner matched nothing"."""
    tree = tmp_path / "scope"
    _pyfile(tree, "clean.py", _CLEAN)
    assert _GATE._scan(tree) == []
    assert _GATE.main([], scope=tree, baseline_path=tmp_path / "empty.json") == 0


def test_a_deliberate_site_can_be_marked(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "marked.py", _SUPPRESSED)
    assert _GATE._scan(tree) == []


def test_the_ratchet_and_the_blind_scope(tmp_path):
    """Baselined fingerprints pass; a missing scope exits 2 rather than reading as clean —
    a gate that could not run is categorically not a green one."""
    tree = tmp_path / "scope"
    _pyfile(tree, "a_import.py", _IMPORT_ALIASED)
    findings = _GATE._scan(tree)

    baselined = tmp_path / "bp.json"
    _write_baseline(baselined, [f.fingerprint for f in findings])
    assert _GATE.main([], scope=tree, baseline_path=baselined) == 0
    assert _GATE.main([], scope=tmp_path / "does-not-exist") == 2


_GRAMMAR_FILTER = (
    "def f_filter(tokens):\n"
    "    return [t for t in tokens if SOME_ID_RE.fullmatch(t)]\n"
)
_NEGATED_REPORT = (
    "def f_report(tokens):\n"
    "    return [err(t) for t in tokens if not SOME_ID_RE.fullmatch(t)]\n"
)
_MARKED_FILTER = (
    "def f_marked(tokens):\n"
    "    return [  # lint-selection: ok — the empty case returns None\n"
    "        t for t in tokens if SOME_ID_RE.fullmatch(t)\n"
    "    ]\n"
)


def test_arm2_flags_a_grammar_filter_that_drops_the_rest(tmp_path):
    """`[t for t in xs if ID_RE.fullmatch(t)]` keeps the matches and discards everything
    else, which is how a token in neither namespace reached no rule at all."""
    tree = tmp_path / "scope"
    _pyfile(tree, "filt.py", _GRAMMAR_FILTER)
    assert _kinds(_GATE._scan(tree)) == {"filter"}


def test_arm2_leaves_the_reporting_shape_alone(tmp_path):
    """THE DISTINCTION THE ARM RESTS ON. `if not RE.fullmatch(t)` turns every non-match into
    the finding — the shape validate.py's four id-structure rules use. Without the negation
    test this gate would flag all of them and read as noise, so this is the control that
    keeps the arm honest rather than merely quiet."""
    tree = tmp_path / "scope"
    _pyfile(tree, "report.py", _NEGATED_REPORT)
    assert _GATE._scan(tree) == []


def test_arm2_applies_inside_the_parser_too(tmp_path):
    """Arm 1 exempts the module that OWNS the fence split — it must use the regex. Arm 2 has
    no such owner: a silent grammar filter is the same defect wherever it sits, and three of
    the four sites this gate documents live in the parser."""
    tree = tmp_path / "scope"
    _pyfile(tree, "skills/invlang/parser.py", _GRAMMAR_FILTER + _IMPORT_ALIASED)
    # arm 1 exempt (the import), arm 2 not
    assert _kinds(_GATE._scan(tree)) == {"filter"}


def test_arm2_marker_must_sit_inside_the_flagged_span(tmp_path):
    """The marker documents where the complement goes, and it only counts where a reader
    will see it — on the flagged expression, not floating above it."""
    tree = tmp_path / "scope"
    _pyfile(tree, "marked.py", _MARKED_FILTER)
    assert _GATE._scan(tree) == []


def test_the_real_tree_is_clean_and_the_baseline_is_empty():
    """The fold actually landed: no production reader under `defender/` bypasses
    `scan_fences`, so the shipped baseline holds nothing to inherit."""
    assert _GATE.main([]) == 0
    baseline = json.loads(_GATE.BASELINE_PATH.read_text(encoding="utf-8"))
    assert baseline.get("entries", {}) == {}
