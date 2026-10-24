"""The gate that keeps the fence-scan fold from regressing: lint_unaccounted_selection"""

from __future__ import annotations

from pathlib import Path


from _by_path import load_lint_gate

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


def test_each_bypass_arm_is_flagged(tmp_path):
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
    tree = tmp_path / "scope"
    _pyfile(tree, "skills/invlang/parser/__init__.py", _IMPORT_ALIASED)
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
    tree = tmp_path / "scope"
    _pyfile(tree, "report.py", _NEGATED_REPORT)
    assert _GATE._scan(tree) == []


def test_arm2_applies_inside_the_parser_too(tmp_path):
    tree = tmp_path / "scope"
    _pyfile(tree, "skills/invlang/parser/__init__.py", _GRAMMAR_FILTER + _IMPORT_ALIASED)
    # arm 1 exempt (the import), arm 2 not
    assert _kinds(_GATE._scan(tree)) == {"filter"}


def test_arm2_marker_must_sit_inside_the_flagged_span(tmp_path):
    """The marker documents where the complement goes, and it only counts where a reader
    will see it — on the flagged expression, not floating above it."""
    tree = tmp_path / "scope"
    _pyfile(tree, "marked.py", _MARKED_FILTER)
    assert _GATE._scan(tree) == []
