r"""#959 - one scanner: the token record stream, the unquoter, the blanks and the `\r`.

Four places in the request path decide where a bash word ends: `bash_exec._scan`,
`bash_exec._word_value` (a `shlex.split` per word), the standalone wrapper step that used to live in `hooks/_cmd_segments.py` (a second
parser that flattens the command before deciding what the `bash -c` argument was), and
`permission/bash.decide_bash`'s `command.strip()`. After this change exactly one does. Any
disagreement between them is a disagreement between what was CHECKED and what RUNS - the gate
grant-checks the pipelines `parse` produced and those same pipelines cross into the box.

This file carries the scanner half (M1, M2, M4, M6); `test_959_wrapper_fold.py` carries the
wrapper (M3), `test_955_bash_fd_prefix.py` the oracle against real bash, and
`test_959_frozen_baseline.py` the recorded neutrality replay.

EVERY DIVERGENT BLANK HERE COMES FROM `_baseline_959`'s CODEPOINT CONSTANTS, never from a
character typed into a docstring or a fixture: this spec's own premise record lost every
literal U+00A0 and CR it was written with (claim a3), and a test written from those
descriptions passes while exercising an ordinary space.
"""
from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import bash_exec  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.runtime.permission import bash as pbash  # noqa: E402
from defender.runtime.permission import command_shape  # noqa: E402
from defender.tests import _baseline_959 as base  # noqa: E402

CR = base.CR
NBSP = base.NBSP
DEFENDER = Path(__file__).resolve().parents[1]
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


# --------------------------------------------------------------------------- #
# M1 - the record stream, and what `parse` is handed.
# --------------------------------------------------------------------------- #
def test_scan_returns_one_frozen_record_per_token_with_value_span_and_kind():
    r"""`_scan` returns one frozen record per token carrying the resolved value, the start and
    end offsets of that token in the raw line, and its kind - word, operator, or fd-prefixed
    operator - and `line[start:end]` of every record is that token's raw spelling, quoting and
    glue intact. Offsets are code-point offsets, so a multibyte character earlier on the line
    leaves every later slice exact.

    Rejected: positional tuples, where named access is lost and nothing separates the two
    offsets; and keeping parallel collections plus spans, which is four index-aligned
    collections instead of three."""
    line = "cat 'a b' 2>/dev/null"
    records = _records(line)
    assert [r.value for r in records] == ["cat", "a b", "2", ">", "/dev/null"]
    assert [line[r.start:r.end] for r in records] == ["cat", "'a b'", "2", ">", "/dev/null"], (
        "a record's span must slice the RAW spelling out of the line - quotes and glue intact"
    )
    # Named access, and the record cannot be edited after the scan.
    with pytest.raises(AttributeError):
        records[0].value = "rm"

    # The kind separates the three cases the grammar turns on. `2>` is bash's IO_NUMBER
    # redirect; a spaced `>` is a redirect of stdout after the ordinary word `2`, and both
    # arrive with the same TEXT - which is the whole of #955 F-50.
    fd_redirect = _records("cat 2>/dev/null")[1]
    plain_redirect = _records("cat > /dev/null")[1]
    word = records[0]
    assert len({word.kind, plain_redirect.kind, fd_redirect.kind}) == 3, (
        "word, operator and fd-prefixed operator must be three distinguishable kinds"
    )

    # Code-point offsets: a multibyte character earlier on the line leaves later slices exact.
    accented = "echo " + chr(0x00E9) + " " + REPORT
    tail = _records(accented)[-1]
    assert accented[tail.start:tail.end] == REPORT


def test_a_quote_that_never_closes_still_ends_the_scan_with_no_tokens():
    """A line whose quote never closes yields no token record stream, and `parse` turns that
    into `UntokenizableCommand` exactly as it does today - including when the unclosed quote
    lives entirely inside a `-c` argument, where the reason class is the one it is refused for
    today and not a free implementation choice."""
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


def test_parse_takes_the_raw_command_and_no_caller_unwraps_first():
    """`parse` is handed the model's command text exactly as written and returns the pipelines
    that text names; there is no second function a caller must remember to apply first, and
    since #971 no word is treated as a wrapper on the way through either.

    Both folds are gone for one reason: a fold DELETES TEXT AHEAD OF THE DECISION, so the
    command the gate judges can differ from the command the model wrote. What is left special
    is punctuation - the connectors, the two stderr redirects, the newline, the quoting - and
    none of it can make the parse report a program the text does not name."""
    assert _parsed(f"bash -c 'cat {REPORT} | wc -c'") == [
        [["bash", "-c", f"cat {REPORT} | wc -c"]]
    ], "the wrapper and its payload are ordinary words; the pipe inside the quotes is not a pipe"
    assert _parsed(f"timeout 5 cat {REPORT}") == [[["timeout", "5", "cat", REPORT]]]
    # ...and the gate reaches those same pipelines from the same raw text: one entry point, so
    # what was grant-checked is what would cross into the box. Both refuse here, on the
    # capability reason, because neither first word is a program this lane has.
    for cmd in (f"bash -c 'cat {REPORT} | wc -c'", f"timeout 5 cat {REPORT}"):
        assert _bash(cmd).reason == base.MAIN.deny_reason, cmd


def test_a_blank_command_is_answered_ahead_of_the_parse_not_by_its_result():
    """The blank command is answered before the parse runs and not from the parse's result: a
    command with no tokens still allows with no pipelines.

    The other horn is refuted, not forked (probe g6): an empty pipeline list reaches
    `_decide_readers`, which returns `None`, so `has_adapter([])` is false and `decide_bash`'s
    tail is a refusal. The probe is re-executed here rather than cited, so the day it stops
    being true this test says so."""
    d = _bash("")
    assert d.allow
    assert d.pipelines is None

    assert command_shape.flat_stages([]) == []
    assert pbash._decide_readers([], base.MAIN, run_dir=base.RUN) is None
    assert command_shape.has_adapter([]) is False
    # ...and end to end: a command that really does parse to zero pipelines DENIES, so the
    # blank allow above cannot have been derived from a parse result.
    assert not _bash("bash -c ''").allow


# --------------------------------------------------------------------------- #
# M4 - the gate's trim, and the blank alphabet.
# --------------------------------------------------------------------------- #
def test_the_gate_hands_the_parser_the_command_text_unchanged():
    """`decide_bash` passes the model's command text to the parser byte for byte: no character
    is removed from either end on the way in, so the argv the gate authorises is the argv the
    text names and not the argv a Unicode-blank predicate left behind."""
    for blank in (NBSP, base.VT, base.FF, base.LSEP, CR):
        for cmd in ("echo hi" + blank, blank + "echo hi"):
            argv = _argv(cmd)
            assert argv is None or any(blank in tok for st in argv[0] for tok in st), (
                f"{cmd!r} was authorised as {argv} - the argv the gate approved is not the one "
                "the text names, and it is the approved argv that crosses into the box"
            )
    # The positive control this negative needs: the same bytes DO reach the parser, and the
    # blanks bash itself splits on are still dropped - by the scanner, where the one opinion
    # about word boundaries lives.
    assert _argv("  echo hi  ") == [[["echo", "hi"]]]
    assert _argv("\techo hi\t") == [[["echo", "hi"]]]


@pytest.mark.parametrize("cmd", list(base.BASH_BLANKS))
def test_a_command_of_only_bash_blanks_is_still_the_allowed_no_op(cmd):
    """A command that is empty, or only spaces, tabs or newlines, still allows with no
    pipelines - deleting the trim does not turn the blank command into a refusal. The falsy
    member is the one that matters most: `if not cmd` is the swallow shape, and the empty
    command is a legitimate allowed no-op today."""
    d = _bash(cmd)
    assert d.allow, f"{cmd!r} stopped being the allowed no-op"
    assert d.pipelines is None


@pytest.mark.parametrize("blank", [base.NBSP, base.VT, base.FF, base.LSEP],
                         ids=["nbsp", "vt", "ff", "u2028"])
def test_a_command_of_only_unicode_blanks_is_a_word_bash_would_try_to_run(blank):
    """A command that is nothing but U+00A0, a vertical tab, a form feed or U+2028 is a command
    bash would look up as a program name, so it is refused rather than answered as the blank
    no-op `str.strip()` used to make it. Each case is built from the ESCAPE - the codepoint -
    never from a literal character in this docstring."""
    d = _bash(blank)
    assert not d.allow, (
        f"a command that is nothing but U+{ord(blank):04X} was answered as blank; bash would "
        "look that word up as a program name"
    )


def test_a_no_break_space_at_either_end_is_part_of_the_word_it_touches():
    r"""An allowed pipeline prefixed or suffixed with U+00A0, a vertical tab or a form feed no
    longer authorises the trimmed command: the blank belongs to the word it touches, exactly as
    bash reads it, so the gate refuses rather than approving an argv the text does not name.
    The same rule glued to a wrapper word makes the wrapper unrecognisable - `timeout<U+00A0>5
    cat x` denies as an ordinary ungranted program, and `bash<U+00A0>-c 'ls'` denies because
    `bash<U+00A0>-c` is not `bash` (restated worked examples 1 and 2; both were written with a
    literal U+00A0 that the record then normalised away)."""
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


def test_a_divergent_blank_between_two_words_changes_no_verdict():
    """A divergent blank sitting BETWEEN two words, with no real blank between it and either,
    is the positive control for the whole class: it merges into the word(s) it touches,
    matching bash, and it is verdict-neutral - neither the deleted trim, nor the scanner, nor
    the unquoter ever split on it there, so nothing about this command's decision moves."""
    frozen = {c["id"]: c for c in base.frozen()["cases"]}
    for cid in ("neutral-interior-blank-echo", "neutral-interior-blank-operand",
                "neutral-quoted-blank"):
        case = frozen[cid]
        assert base.decision_record(case["command"], case["policy"]) == case["baseline"], (
            f"{cid}: an interior divergent blank moved a verdict. It is not in the enumerated "
            "set, and it is the control that says the fix is scoped to the ENDS."
        )
    assert _argv("echo a" + NBSP + "b") == [[["echo", "a" + NBSP + "b"]]]


def test_a_divergent_blank_inside_a_quoted_argument_is_part_of_that_argument():
    r"""There is no extracted inner text any more (#971), so the question this used to ask -
    does the divergent-blank rule reach inside a `-c` payload - has no subject. What replaces it
    is the rule that made the answer yes: a quoted argument is ONE token and its contents are
    its own, blanks included. `bash -c '<U+00A0>cat x'` is three words, the third of which
    begins with a no-break space, and nothing in the parse looks inside it.

    Still refused, and now for the reason that was always the true one: `bash` is not a program
    this lane has."""
    inner = NBSP + "cat " + REPORT
    assert _parsed("bash -c '" + inner + "'") == [[["bash", "-c", inner]]], (
        "the quoted argument is one token and keeps its blank; nothing re-scans its contents"
    )
    for cmd in ("bash -c '" + inner + "'", "bash -c '" + NBSP + "'"):
        d = _bash(cmd)
        assert not d.allow
        assert d.reason == base.MAIN.deny_reason, cmd


def test_every_member_of_the_divergent_blank_alphabet_behaves_the_same_way():
    r"""One table-driven sweep over the whole closed alphabet, not three hand-authored members:
    the 26 characters `str.strip()` removes that neither the scanner nor the line split treats
    as a blank are each exercised at both ends of an allowed pipeline, and each behaves the way
    the three named members do. The set is derived in the test from `str.strip()` and the
    scanner's own separator constant - never transcribed - so the 26th member (`\r`, which
    joins the alphabet the moment M6 removes it from `_WORD_SEPARATORS`) cannot be left out by
    hand."""
    stripped = {chr(cp) for cp in range(0x110000) if chr(cp).strip() == ""}
    alphabet = stripped - set(bash_exec._WORD_SEPARATORS) - {"\n"}
    assert len(alphabet) == 26, (
        f"the divergent-blank alphabet computes to {len(alphabet)} characters, not 26. It is "
        "`str.strip()`'s 29 minus space, tab and newline; the count the closed set recorded "
        "was 25 because it was measured against the very constant this change edits."
    )
    assert CR in alphabet, (
        "the carriage return is still a word separator here, so it is missing from the "
        "alphabet - M6(a) has not landed"
    )
    assert alphabet == set(base.DIVERGENT_BLANKS), (
        "the derived alphabet and the frozen corpus alphabet disagree; the frozen one is what "
        "the baseline replay was recorded over and cannot move"
    )

    for blank in sorted(alphabet):
        for cmd in (blank + "cat " + REPORT, "cat " + REPORT + blank):
            assert not _bash(cmd).allow, (
                f"U+{ord(blank):04X} at an end of an allowed pipeline still authorises the "
                "trimmed command"
            )


# --------------------------------------------------------------------------- #
# M6 + M2 - the carriage return, and the two layers that must agree about it.
# --------------------------------------------------------------------------- #
def test_the_boundary_decision_and_the_value_resolution_agree_about_the_removed_separator():
    r"""The boundary decision and the value resolution agree about the removed separator in all
    three shapes, which is only true once the unquoter has no blank set of its own: a mid-word
    `\r` leaves one token whose RESOLVED value still carries the `\r`; an edge `\r` is not
    silently dropped from the resolved value; and a word that is nothing but `\r` resolves to
    that one-character word rather than to zero parts that make the line untokenizable. A
    quoted `\r` is the control - unchanged in both directions, because quoting suppresses
    separator recognition unconditionally.

    M6 is necessary and NOT sufficient on its own: `_word_value` is `shlex.split`, whose own
    hardcoded whitespace contains `\r` whatever `_WORD_SEPARATORS` says, so with M6(a) alone a
    mid-word `\r` still splits the resolved value, an edge `\r` is silently DROPPED, and a lone
    `\r` resolves to zero parts and makes the whole line untokenizable."""
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


# --------------------------------------------------------------------------- #
# O2 - one module decides, and it still decides.
# --------------------------------------------------------------------------- #
def _shlex_attributes(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.attr for node in ast.walk(tree)
        if isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name) and node.value.id == "shlex"
    }


def test_nothing_outside_bash_exec_decides_where_a_bash_word_ends():
    """One module decides where a bash word ends: no other module in the tree splits command
    text - no `shlex.split`, no `shlex.shlex`, no blank-set `strip` on a command - and the only
    `shlex` left elsewhere is `shlex.join`, which formats an argv and never parses one.

    The census is computed here over the production tree rather than cited: claim c3 named four
    splitters at this base commit (`_cmd_segments.py:45`, `bash_exec._word_value`,
    `bash_exec._scan`, and `decide_bash`'s `command.strip()`), and a census that is not
    re-executed is how the fifth trim at `test_bash_exec.py:28` stayed off the migration list."""
    splitters = {
        str(p.relative_to(DEFENDER)): sorted(_shlex_attributes(p) & {"split", "shlex"})
        for p in PRODUCTION_FILES
    }
    offenders = {name: attrs for name, attrs in splitters.items() if attrs}
    assert not offenders, (
        f"these production modules still split command text themselves: {offenders}. After "
        "this change the word boundary is decided in exactly one place; `shlex.join` formats "
        "an argv and is fine, `shlex.split`/`shlex.shlex` parse one and are not."
    )
    gate = (DEFENDER / "runtime" / "permission" / "bash.py").read_text(encoding="utf-8")
    for spelling in ("command.strip()", "cmd.strip()"):
        assert spelling not in gate, (
            f"`{spelling}` is still in the gate: Python's blank predicate removes 26 characters "
            "bash does not treat as blanks at all, so the argv the gate authorises is not the "
            "argv the text names"
        )
    segments = (DEFENDER / "hooks" / "_cmd_segments.py")
    if segments.exists():
        text = segments.read_text(encoding="utf-8")
        assert 'lstrip(" \\t")' not in text, (
            "the raw-text prefix surgery is still in the shim module - M3 replaces it with a "
            "token-index match, and it is what makes a quoted `timeout` prefix unmatchable"
        )


def test_the_one_module_that_splits_bash_text_still_splits_it():
    r"""The paired control: the one module that does split still splits - `a | b && c` is three
    stages across two connectors, an operator-looking character produced by a quoting idiom was
    never an operator token, and an escaped operator character is an ordinary word everywhere -
    so the negative above cannot pass by everything having stopped working."""
    assert _parsed("a | b && c") == [[["a"], ["b"]], [["c"]]]
    assert _parsed("echo ';' foo") == [[["echo", ";", "foo"]]]
    assert _parsed("echo \\; foo") == [[["echo", ";", "foo"]]]
    assert _parsed("find . -exec ls {} ';'") == [[["find", ".", "-exec", "ls", "{}", ";"]]]
    # A quote that closes and reopens around an operator character never made an operator:
    # operator recognition happens over the raw characters, before quote resolution.
    assert _parsed("echo 'a'\"|\"'b'") == [[["echo", "a|b"]]]


def test_the_unquoter_has_no_notion_of_whitespace():
    r"""`_word_value` resolves the quoting of one span and nothing else: it holds no blank set,
    it is not built on a splitter, and there is no pin stopping it from re-splitting because it
    has no such capability to pin.

    Rejected: the design body's claim that the current code pins `lex.whitespace` to stop it -
    there is no such pin in the module (x1), and the mechanism the doc credits does not exist.
    Rejected too: any performance claim for the hand-rolled unquoter, which the design defers."""
    assert not _shlex_attributes(DEFENDER / "runtime" / "bash_exec.py") & {"split", "shlex"}, (
        "`_word_value` is still built on a splitter, so it still has a blank set of its own - "
        "`shlex.split`'s own hardcoded whitespace contains the carriage return whatever "
        "`_WORD_SEPARATORS` says, which is why M6 does not close O1 without M2"
    )
    # ...and behaviourally: handed a span carrying the character the scanner no longer splits
    # on, it resolves it rather than re-splitting or dropping it.
    assert bash_exec._word_value("A" + CR + "B") == "A" + CR + "B"


def test_the_unquoter_resolves_every_quoting_form_the_lexer_resolved():
    r"""The hand-rolled unquoter returns exactly what the POSIX lexer returned for every form
    the grammar admits: `"a\nb"` keeps its backslash, `"a\"b"` gives `a"b`, `"a\\b"` gives
    `a\b`, `a\ b` gives one word with a space, `'a'"b"c` glues to `abc`, `'a\nb'` is literal,
    `"$x"` is not expanded, `\;` is the semicolon `find -exec` needs, and a quote-concatenated
    spelling of a wrapper word (`'ba''sh'`) resolves to `bash` and is recognised like any
    other. The table is the one claim x13 read off the current implementation, not a prior."""
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
    """A command ending in a dangling backslash is still refused as untokenizable - the escape
    the lexer raised on must still be a refusal once the unquoter is hand-rolled, or cause (2)
    of the lexing reason becomes a sentence about nothing."""
    with pytest.raises(bash_exec.UntokenizableCommand):
        bash_exec.parse("cat " + REPORT + " \\")
    d = _bash("cat " + REPORT + " \\\n | wc -l")
    assert not d.allow
    assert d.reason == permission.UNTOKENIZABLE_REASON
    assert "continues nothing" in d.reason


def test_the_line_boundary_and_incomplete_connector_causes_still_name_what_they_name():
    r"""Causes (3) and (4) - a `|`/`&&`/`||` at a line boundary, and a connector without a
    complete command on both sides within one line - still name exactly what the parser
    refuses for every spelling that still REACHES them. The per-line dangling-connector and
    pending-connector checks stay inside the per-line loop while the wrapper decision sits
    outside it; the two constraints pull in opposite directions and both must hold.

    A divergent blank is where this demand has a side that holds and a side that does not, and
    the run's own record stated only the first (RC1). A blank glued to the word BEFORE a
    connector leaves the connector as the line's last token, so the check still fires and the
    lexing reason still answers. A blank AFTER the connector does not: it becomes a word of its
    own, the connector is no longer last, this check never fires at all, and the command is
    refused down the other path. That is enumerated verdict-change member 8, and member 8 is the
    WHOLE 26-character alphabet against each separator, not a carriage-return rule (RC6) - the
    carriage return is only the spelling a CRLF paste produces. It is NOT repaired by teaching
    this check to look past a trailing blank, because bash genuinely ends the pipeline there and
    a second private opinion about what a blank is is the thing this change exists to delete.
    What the model is told instead is
    `test_a_command_refused_only_for_an_invisible_character_is_told_so`'s to pin."""
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
    # The side that HOLDS: a carriage return glued to the word BEFORE the connector is neither
    # a separator nor an operator character, so it neither starts nor extends the operator run,
    # and `|` is still the line's last token - cause (3) still answers.
    d = _bash("cat " + REPORT + CR + "|\nwc -l")
    assert not d.allow
    assert d.reason == permission.UNTOKENIZABLE_REASON

    # The side that DOES NOT, and is enumerated because of it (member 8): after the connector,
    # the blank is the line's last token and this check is structurally out of reach. The
    # command must still be refused - it is not a widening - and it must NOT be refused with
    # the reason that tells the model to rewrite on one line, because that is no longer why.
    # Over the alphabet, not over the carriage return: stating this member as a `\r` rule is
    # exactly the error RC6 found, and the alphabet is read off the frozen tuple.
    # The three DANGLING connectors only: they are the ones whose reach cause (3) loses. `;`
    # never reached this check at all, so its own move (allow->deny) belongs to the corpus and
    # to the invisible-character demand, not here.
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


# --------------------------------------------------------------------------- #
# F1 + FK4 - where the blank test sits, and which alphabet it reads.
# --------------------------------------------------------------------------- #
def test_the_blank_test_holds_no_opinion_of_its_own_about_what_a_blank_is():
    r"""The blank test ahead of the parse holds no opinion of its own about what a blank is: it
    READS the scanner's separator constant rather than owning a second one, so exactly one
    place in the tree still decides. Checked against every member it touches - `""`, `"   "`,
    `"\t"`, `"\n"` stay the allowed no-op; `"\u00a0"`, `"\v"`, `"\f"` alone are words bash
    would try to run as program names and are refused; a lone `"\r"` is likewise a word, which
    is exactly what M6 says bash reads it as.

    The alphabet is not transcribed here either: it is read off `_WORD_SEPARATORS` at run time,
    so this test follows the constant when M6 moves it. That is the whole content of the
    resolution - the blank test reads the one opinion rather than holding a second."""
    separators = set(bash_exec._WORD_SEPARATORS)
    for sep in sorted(separators):
        cmd = sep * 3
        assert _bash(cmd).allow, (
            f"U+{ord(sep):04X} is a word separator for the scanner but a command made only of "
            "it is refused - the blank test and the scanner hold different opinions"
        )
    assert _bash("").allow, "the falsy member is the allowed no-op"

    stripped = {chr(cp) for cp in range(0x110000) if chr(cp).strip() == ""}
    for blank in sorted(stripped - separators - {"\n"}):
        assert not _bash(blank).allow, (
            f"U+{ord(blank):04X} is not a word separator for the scanner, so a command made "
            "only of it is a word bash would try to run - and it was answered as blank"
        )

    gate_source = (DEFENDER / "runtime" / "permission" / "bash.py").read_text(encoding="utf-8")
    assert "_WORD_SEPARATORS" in gate_source, (
        "the gate's blank test names no separator constant, so it is holding a second opinion "
        "about what a blank is - inside the change whose thesis is that there should be one"
    )


def test_the_relocated_blank_check_and_the_embedded_nul_check_keep_the_same_relative_order():
    """The order is firm and pinned: the blank test, then the embedded-NUL check, then the
    parse. The NUL arm may not move above or below the relocated blank test, it still runs once
    over the whole raw command before any parsing including wrapper detection - so it fires
    identically at every wrapper depth - and a command carrying both a NUL and a divergent
    blank is answered by the NUL arm."""
    nul = base.NUL
    # Before the parse: a command that ALSO fails to lex answers the NUL reason, not the
    # lexing one - so the NUL arm is not reached through the parse.
    for cmd in (
        "cat " + REPORT + nul,
        "cat 'x" + nul,                                   # ...and unbalanced besides
        "bash -c 'cat " + REPORT + nul + "'",             # ...at wrapper depth
        "timeout 5 cat " + REPORT + nul,
    ):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} was allowed with a NUL in it"
        assert d.reason == pbash.EMBEDDED_NUL_REASON, (
            f"{cmd!r} was answered {d.reason[:60]!r} - the NUL check runs once over the whole "
            "raw command, before any parsing including wrapper detection"
        )
    # A NUL beside blanks is still the NUL arm's: the blank test must not swallow it.
    assert _bash("   " + nul + "   ").reason == pbash.EMBEDDED_NUL_REASON
    # ...and the blank test still answers first for a command that is only blanks.
    assert _bash("   ").allow
    # A divergent blank beside a NUL: the NUL arm fires first, over the whole raw string.
    assert _bash(NBSP + nul).reason == pbash.EMBEDDED_NUL_REASON
