"""#959 - one scanner: the token record stream, the unquoter, the blanks and the `\\r`."""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.execution import bash_exec  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.permission import bash as pbash  # noqa: E402
from defender.runtime.permission import command_shape  # noqa: E402
from defender.tests.support.sandbox import _baseline_959 as base
from defender.tests.support.shared.contracts._by_path import cached_parse  # noqa: E402

CR = base.CR
NBSP = base.NBSP
DEFENDER = Path(__file__).resolve().parents[2]
REPORT = base.REPORT

#: Production python under `defender/`, minus the test tree - the census surface for "one
#: module decides where a bash word ends".
PRODUCTION_FILES = tuple(
    p for p in DEFENDER.rglob("*.py")
    if "tests" not in p.relative_to(DEFENDER).parts
    and ".venv" not in p.parts
    and "fixtures" not in p.relative_to(DEFENDER).parts
)


def _bash(cmd: str, policy=None):
    return permission.decide_bash(
        cmd, policy=policy or base.MAIN, run_dir=base.RUN, defender_dir=base.DFN,
    )


def _argv(cmd: str, policy=None):
    """The pipelines the gate authorised, as nested argv - `None` when it refused."""
    d = _bash(cmd, policy)
    if d.pipelines is None:
        return None
    return [[list(st.argv) for st in pl.stages] for pl in d.pipelines]


def _parsed(cmd: str):
    return [[list(st.argv) for st in pl.stages] for pl in bash_exec.parse(cmd)]


def _records(line: str):
    """`_scan`'s record stream for `line`, with the shape demanded of it asserted first."""
    scanned = bash_exec._scan(line)
    assert scanned is not None, f"{line!r} did not scan"
    records = list(scanned)
    for r in records:
        missing = [f for f in ("value", "start", "end", "kind") if not hasattr(r, f)]
        assert not missing, (
            f"_scan({line!r}) yielded {r!r}, which is missing {missing}. The record stream is "
            "M1: one frozen record per token carrying value, start, end and kind - not the "
            "three index-aligned collections this returned before, where alignment between the "
            "token stream and the raw text was exactly what #955 was about."
        )
    return records


def test_a_quote_that_never_closes_still_ends_the_scan_with_no_tokens():
    """A line whose quote never closes yields no token record stream, and `parse` turns that into `UntokenizableCommand` exactly as it does today -..."""
    assert bash_exec._scan("cat 'x") is None
    with pytest.raises(bash_exec.UntokenizableCommand):
        bash_exec.parse("cat 'x")
    for cmd in (f"cat {REPORT} | grep 'unterminated", f"bash -c 'cat {REPORT}"):
        d = _bash(cmd)
        assert not d.allow
        assert d.pipelines is None
        assert d.reason == permission.UNTOKENIZABLE_REASON, (
            f"{cmd!r} must keep the reason class it is refused for today - reason identity is "
            "part of the verdict (F2) and this shape is not in the enumerated set"
        )


def test_a_blank_command_is_answered_ahead_of_the_parse_not_by_its_result():
    """The blank command is answered before the parse runs and not from the parse's result"""
    d = _bash("")
    assert d.allow
    assert d.pipelines is None

    assert command_shape.flat_stages([]) == []
    assert pbash._decide_readers([], base.MAIN, run_dir=base.RUN) is None
    assert command_shape.has_adapter([]) is False
    # ...and end to end: a command that really does parse to zero pipelines DENIES, so the
    # blank allow above cannot have been derived from a parse result.
    assert not _bash("bash -c ''").allow


@pytest.mark.parametrize("cmd", list(base.BASH_BLANKS))
def test_a_command_of_only_bash_blanks_is_still_the_allowed_no_op(cmd):
    """A command that is empty, or only spaces, tabs or newlines, still allows with no pipelines - deleting the trim does not turn the blank command into..."""
    d = _bash(cmd)
    assert d.allow, f"{cmd!r} stopped being the allowed no-op"
    assert d.pipelines is None


@pytest.mark.parametrize("blank", [base.NBSP, base.VT, base.FF, base.LSEP],
                         ids=["nbsp", "vt", "ff", "u2028"])
def test_a_command_of_only_unicode_blanks_is_a_word_bash_would_try_to_run(blank):
    """A command that is nothing but U+00A0, a vertical tab, a form feed or U+2028 is a command bash would look up as a program name, so it is refused..."""
    d = _bash(blank)
    assert not d.allow, (
        f"a command that is nothing but U+{ord(blank):04X} was answered as blank; bash would "
        "look that word up as a program name"
    )


def test_a_no_break_space_at_either_end_is_part_of_the_word_it_touches():
    """An allowed pipeline prefixed or suffixed with U+00A0, a vertical tab or a form feed no longer authorises the trimmed command"""
    for blank in (NBSP, base.VT, base.FF):
        assert not _bash(blank + "cat " + REPORT).allow
        assert not _bash("cat " + REPORT + blank).allow
    # The wrapper words, glued (worked examples 1 and 2). Refused before and after - what the
    # examples pin is WHY: the first token is not `timeout`/`bash` at all.
    assert not _bash("timeout" + NBSP + "5 cat " + REPORT).allow
    assert not _bash("bash" + NBSP + "-c 'ls'").allow
    # The allow-side half, which a check reading only allow/deny cannot see: where the grant
    # shape ends in a bare VALUE the command stays allowed - with the blank in the argv.
    assert _argv("echo hi" + NBSP) == [[["echo", "hi" + NBSP]]]


def test_a_divergent_blank_inside_a_quoted_argument_is_part_of_that_argument():
    """There is no extracted inner text any more (#971), so the question this used to ask - does the divergent-blank rule reach inside a `-c` payload -..."""
    inner = NBSP + "cat " + REPORT
    assert _parsed("bash -c '" + inner + "'") == [[["bash", "-c", inner]]], (
        "the quoted argument is one token and keeps its blank; nothing re-scans its contents"
    )
    for cmd in ("bash -c '" + inner + "'", "bash -c '" + NBSP + "'"):
        d = _bash(cmd)
        assert not d.allow
        assert d.reason == base.MAIN.deny_reason, cmd


# M6 + M2 - the carriage return, and the two layers that must agree about it.
def test_the_boundary_decision_and_the_value_resolution_agree_about_the_removed_separator():
    """The boundary decision and the value resolution agree about the removed separator in all three shapes, which is only true once the unquoter has no..."""
    assert bash_exec._word_value("A" + CR + "B") == "A" + CR + "B"
    assert bash_exec._word_value("P" + CR) == "P" + CR
    assert bash_exec._word_value(CR) == CR

    assert _parsed("echo A" + CR + "B") == [[["echo", "A" + CR + "B"]]]
    assert _parsed("echo P" + CR) == [[["echo", "P" + CR]]]
    assert _parsed("echo " + CR) == [[["echo", CR]]]
    assert _parsed(CR) == [[[CR]]], "a line that is one carriage return is a one-character word"

    # The quoted control, unchanged in both directions.
    assert bash_exec._word_value("'A" + CR + "B'") == "A" + CR + "B"
    assert _parsed("echo 'A" + CR + "B'") == [[["echo", "A" + CR + "B"]]]


# O2 - one module decides, and it still decides.
def _shlex_attributes(path: Path) -> set[str]:
    _text, tree = cached_parse(path, str(path))
    return {
        node.attr for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name) and node.value.id == "shlex"
    }


def test_the_unquoter_has_no_notion_of_whitespace():
    """`_word_value` resolves the quoting of one span and nothing else"""
    assert not _shlex_attributes(DEFENDER / "execution" / "bash_exec.py") & {"split", "shlex"}, (
        "`_word_value` is still built on a splitter, so it still has a blank set of its own - "
        "`shlex.split`'s own hardcoded whitespace contains the carriage return whatever "
        "`_BLANKS` says, which is why M6 does not close O1 without M2"
    )
    # ...and behaviourally: handed a span carrying the character the scanner no longer splits
    # on, it resolves it rather than re-splitting or dropping it.
    assert bash_exec._word_value("A" + CR + "B") == "A" + CR + "B"


def test_the_unquoter_resolves_every_quoting_form_the_lexer_resolved():
    """The hand-rolled unquoter returns exactly what the POSIX lexer returned for every form the grammar admits"""
    table = [
        ('"a\\nb"', "a\\nb"),
        ('"a\\"b"', 'a"b'),
        ('"a\\\\b"', "a\\b"),
        ("a\\ b", "a b"),
        ("'a'\"b\"c", "abc"),
        ("'a\\nb'", "a\\nb"),
        ('"$x"', "$x"),
        ("\\;", ";"),
        ("'ba''sh'", "bash"),
    ]
    for span, value in table:
        assert bash_exec._word_value(span) == value, f"{span!r} resolved wrongly"


def test_a_trailing_backslash_still_continues_nothing():
    with pytest.raises(bash_exec.UntokenizableCommand):
        bash_exec.parse("cat " + REPORT + " \\")
    d = _bash("cat " + REPORT + " \\\n | wc -l")
    assert not d.allow
    assert d.reason == permission.UNTOKENIZABLE_REASON
    assert "continues nothing" in d.reason


def test_the_line_boundary_and_incomplete_connector_causes_still_name_what_they_name():
    """Causes (3) and (4) - a `|`/`&&`/`||` at a line boundary, and a connector without a complete command on both sides within one line - still name..."""
    for cmd, phrase in (
        (f"cat {REPORT} |\nwc -l", "line boundary"),
        (f"cat {REPORT}\n| wc -l", "line boundary"),
        (f"cat {REPORT} | ; wc -l", "BOTH sides"),
        (f"cat {REPORT} && ;", "BOTH sides"),
        (f"cat {REPORT} | 2> /dev/null", "BOTH sides"),
    ):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r}"
        assert d.reason == permission.UNTOKENIZABLE_REASON, f"{cmd!r}"
        assert phrase in d.reason, f"{cmd!r}: the reason no longer names this cause"
    d = _bash("cat " + REPORT + CR + "|\nwc -l")
    assert not d.allow
    assert d.reason == permission.UNTOKENIZABLE_REASON

    connector_cases = [
        "cat " + REPORT + " " + sep + blank
        for sep in ("|", "&&", "||")
        for blank in base.DIVERGENT_BLANKS
    ] + ["cat " + REPORT + " |" + CR + "\nwc -l"]
    for cmd in connector_cases:
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} became an allow - a connector lost its right-hand side"
        assert d.reason != permission.UNTOKENIZABLE_REASON, (
            f"{cmd!r} still answers the line-boundary cause. After M4+M6+M2 the blank is a word "
            "after the connector, so cause (3) is not what refuses this any more, and a reason "
            "that says 'rewrite as a SINGLE line' sends the model to fix the wrong thing"
        )
