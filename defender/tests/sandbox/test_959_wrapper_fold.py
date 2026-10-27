"""#971 — no word is a wrapper: `bash -c` and `timeout` reach the gate as ordinary ungranted words.
A fold would delete text ahead of the decision, so a mis-read could only widen what is allowed."""
from __future__ import annotations

import re

import pytest

pytest.importorskip("pydantic_ai")

from defender.investigation import permission  # noqa: E402
from defender.tests.support.sandbox import _baseline_959 as base

NBSP = base.NBSP
REPORT = base.REPORT
_bash = base.decide_bash
_parsed = base.parsed_argv


# #971 - no word is a wrapper, and what that leaves the parser doing.
def test_no_word_is_parsed_as_a_wrapper():
    """Neither `bash` nor `sh` is recognised, so nothing is extracted before the gate decides."""
    for cmd in (
        f"bash -c 'cat {REPORT}'",                    # the plain wrapper
        f"bash -c 'cat {REPORT} | wc -l'",            # a pipeline payload
        "sh -c 'echo hi'",
        '"bash" -c "echo hi"',                        # the quoted spelling of the word
        "'ba''sh' -c 'echo hi'",                      # ...and the concatenated one
        "bash",                                       # a bare wrapper
        "sh",
        f"bash {REPORT}",                             # a script path
        "sh -lc 'ls'",
        "bash -c'echo hi'",                           # a glued `-c`
        "bash -x -c 'echo hi'",                       # a flag in between
        f"bash -c 'cat {REPORT}' extra",              # a stray word after the argument
        "bash -c 'echo a' bash -c 'echo b'",          # a second wrapper
        "bash -c 'ls'\ncat /etc/hosts",               # a second physical line
        "bash -c ''",                                 # an empty payload
        "bash -c 'bash -c \"echo hi\"'",              # a wrapper inside a wrapper
        "bash -c 'echo a '2>/dev/null",              # an OUTER operator after the quote
        f"bash -c 'cat {REPORT} '2>/dev/null",
    ):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} is allowed"
        assert d.reason == base.MAIN.deny_reason, f"{cmd!r}: refused, but not with the capability reason"
    # ...and the parse reports what the text says, quotes and all - no payload is unpacked, and
    # the `|` inside a quoted argument is not a pipe.
    assert _parsed(f"bash -c 'cat {REPORT} | wc -l'") == [
        [["bash", "-c", f"cat {REPORT} | wc -l"]]
    ]
    assert _parsed("bash -c 'bash -c \"echo hi\"'") == [[["bash", "-c", 'bash -c "echo hi"']]]
    causes = "\n".join(
        line for line in permission.UNTOKENIZABLE_REASON.splitlines()
        if line.startswith("(")
    )
    assert causes.count("(") >= 4, "the numbered causes stopped being parseable as a list"
    for word in ("bash -c", "wrapper", "-lc", "fold"):
        assert word not in causes, f"a numbered lexing cause still describes a wrapper step ({word!r})"


def test_a_newline_inside_a_quoted_argument_is_the_unclosed_quote_it_looks_like():
    """A quoted newline is an unclosed quote on its line, and the reason says so: a pretty-printed payload needs telling."""
    for cmd in (
        f"bash -c 'cat {REPORT}\nwc -l'",
        f"cat {REPORT} | grep 'a\nb'",
        "defender-sql 'SELECT 1\nFROM t'",
    ):
        d = _bash(cmd)
        assert not d.allow, cmd
        assert d.reason == permission.UNTOKENIZABLE_REASON, cmd
    assert "newline INSIDE a quoted argument" in permission.UNTOKENIZABLE_REASON, (
        "the reason no longer explains a newline inside a quoted argument"
    )


def test_a_timeout_prefix_is_not_a_wrapper_and_is_never_folded_away():
    """`timeout` is an ordinary ungranted word: no prefix is stripped before the decision."""
    assert _parsed(f"timeout 5 cat {REPORT}") == [[["timeout", "5", "cat", REPORT]]], (
        "the parse dropped or rewrote the `timeout` prefix"
    )
    for cmd in (
        f"timeout 5 cat {REPORT}",             # the plain prefix
        f"timeout 0.5 cat {REPORT}",           # a fractional duration
        f"timeout '5' cat {REPORT}",           # quoted
        f'"timeout" 5 cat {REPORT}',
        f"timeout --foreground cat {REPORT}",  # no duration anywhere
        f"timeout\n5 cat {REPORT}",            # the prefix straddling a line boundary
        f"timeout 5 timeout 3 cat {REPORT}",   # a second prefix
        f"bash -c 'timeout 5 cat {REPORT}'",   # inside a `bash -c`
        f"timeout cat {REPORT}",
        "timeout",
        "timeout --",
    ):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} is allowed"
        assert d.reason == base.MAIN.deny_reason, f"{cmd!r}: refused, but not with the capability reason"
    assert "timeout" not in permission.UNTOKENIZABLE_REASON, (
        "the lexing reason names a `timeout` prefix, which the parser does not treat specially"
    )


def test_an_ungranted_first_word_answers_before_any_classification_of_the_rest():
    """Deliberate: a prefixed adapter command gets the capability reason, not the adapter redirect."""
    for policy in (base.MAIN, base.GATHER):
        bare = _bash("defender-elastic query foo", policy)
        assert bare.reason == permission.ADAPTER_RETIRED_REASON, (
            "a bare adapter command no longer gets the adapter message"
        )
        prefixed = _bash("timeout 60 defender-elastic query foo", policy)
        assert prefixed.reason == policy.deny_reason, (
            "an ungranted first word stopped answering first"
        )


def test_a_blank_glued_to_an_ungranted_word_is_not_blamed_for_the_refusal():
    """A blank that changes nothing about the refusal is not named; a decisive one still is."""
    for cmd in (NBSP + f"timeout '5' cat {REPORT}", f"timeout '5' cat {REPORT}" + NBSP):
        d = _bash(cmd)
        assert not d.allow
        assert not re.search(r"U\+0*[0-9a-f]{4}\b", d.reason, re.IGNORECASE), (
            f"{cmd!r}: a codepoint is named for a command that is refused with or without it"
        )
    # The control: a blank that IS decisive is still named, so the quiet above is about this
    # command and not about the machinery having stopped working.
    d = _bash(NBSP + f"cat {REPORT}")
    assert not d.allow
    assert re.search(rf"U\+0*{ord(NBSP):04x}\b", d.reason, re.IGNORECASE)


# What the removal leaves behind.
def test_the_paren_fall_through_still_fails_closed_a_layer_up():
    """`(`/`)` break words without being operators, so `cat <(id)` reaches argv as words and the argv guard refuses it."""
    assert _parsed("cat <(id)") == [[["cat", "<(", "id", ")"]]]
    assert _parsed("bash -c 'cat <(id)'") == [[["bash", "-c", "cat <(id)"]]]
    for cmd in ("cat <(id)", "bash -c 'cat <(id)'"):
        d = _bash(cmd)
        why = f"{cmd!r}: expected the capability refusal, not a lexing one"
        assert not d.allow, why
        assert d.reason == base.MAIN.deny_reason, why
