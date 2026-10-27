"""#959 - the wrapper folded into the parser (M3)"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.execution import bash_exec  # noqa: E402
from defender.investigation import permission  # noqa: E402
from defender.tests.support.sandbox import _baseline_959 as base

CR = base.CR
NBSP = base.NBSP
REPORT = base.REPORT
DEFENDER = Path(__file__).resolve().parents[2]
TESTS = DEFENDER / "tests"


def _bash(cmd: str, policy=None):
    return permission.decide_bash(
        cmd, policy=policy or base.MAIN, run_dir=base.RUN, defender_dir=base.DFN,
    )


def _argv(cmd: str):
    d = _bash(cmd)
    if d.pipelines is None:
        return None
    return [[list(st.argv) for st in pl.stages] for pl in d.pipelines]


def _parsed(cmd: str):
    return [[list(st.argv) for st in pl.stages] for pl in bash_exec.parse(cmd)]


def _generic_lexing_reason() -> str:
    """The reason an ordinary unbalanced quote earns - the 'generic parse failure' F5's
    obligation says a design-introduced narrowing may not hide behind."""
    return _bash("cat 'x").reason


# #971 - no word is a wrapper, and what that leaves the parser doing.
def test_no_word_is_parsed_as_a_wrapper():
    """#971: neither `bash` nor `sh` is recognised, so no text is extracted from a command before the gate decides about it."""
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
        "bash -c 'echo a '2>/dev/null",              # the retired member 3: an OUTER operator
        f"bash -c 'cat {REPORT} '2>/dev/null",
    ):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} is allowed"
        assert d.reason == base.MAIN.deny_reason, (
            f"{cmd!r}: refused, but not on the reason that names the programs this lane has"
        )
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
        assert word not in causes, (
            f"a numbered lexing cause still describes a wrapper step ({word!r}) - the parser "
            "does not take one, so no cause may be about one"
        )


def test_a_newline_inside_a_quoted_argument_is_the_unclosed_quote_it_looks_like():
    """A quoted argument carrying a newline is refused for the reason every cross-line quote is refused - a quoted string cannot span lines - and the..."""
    for cmd in (
        f"bash -c 'cat {REPORT}\nwc -l'",
        f"cat {REPORT} | grep 'a\nb'",
        "defender-sql 'SELECT 1\nFROM t'",
    ):
        d = _bash(cmd)
        assert not d.allow, cmd
        assert d.reason == permission.UNTOKENIZABLE_REASON, cmd
    assert "newline INSIDE a quoted argument" in permission.UNTOKENIZABLE_REASON, (
        "the reason no longer explains a newline inside a quoted argument, which is the one "
        "thing a model that pretty-printed its payload needs told"
    )


def test_a_timeout_prefix_is_not_a_wrapper_and_is_never_folded_away():
    """#971: `timeout` is an ORDINARY UNGRANTED WORD."""
    assert _parsed(f"timeout 5 cat {REPORT}") == [[["timeout", "5", "cat", REPORT]]], (
        "the prefix is still in the argv - the parse reports what the text says, and the "
        "capability question is asked about `timeout` itself"
    )
    for cmd in (
        f"timeout 5 cat {REPORT}",             # the plain prefix
        f"timeout 0.5 cat {REPORT}",           # a fractional duration
        f"timeout '5' cat {REPORT}",           # quoted: the retired member 4
        f'"timeout" 5 cat {REPORT}',
        f"timeout --foreground cat {REPORT}",  # no duration anywhere: the old FK1 hazard
        f"timeout\n5 cat {REPORT}",            # the prefix straddling a line boundary
        f"timeout 5 timeout 3 cat {REPORT}",   # a second prefix the apply-once fold left behind
        f"bash -c 'timeout 5 cat {REPORT}'",   # inside a wrapper, where the fold never reached
        f"timeout cat {REPORT}",
        "timeout",
        "timeout --",
    ):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} is allowed"
        assert d.reason == base.MAIN.deny_reason, (
            f"{cmd!r}: refused, but not on the reason that tells the model which programs this "
            "lane actually has - which is the whole point of letting the word through"
        )
    assert "timeout" not in permission.UNTOKENIZABLE_REASON, (
        "the lexing reason names a `timeout` prefix, and the parser has no opinion about one - "
        "the only sentence the model is ever shown about this would be a sentence about nothing"
    )


def test_an_ungranted_first_word_answers_before_any_classification_of_the_rest():
    """The consequence #971 accepts rather than repairs, pinned so nobody repairs it."""
    for policy in (base.MAIN, base.GATHER):
        bare = _bash("defender-elastic query foo", policy)
        assert bare.reason == permission.ADAPTER_RETIRED_REASON, (
            "the adapter message no longer answers a bare adapter command - the classification "
            "this test scopes has broken, not just its reach"
        )
        prefixed = _bash("timeout 60 defender-elastic query foo", policy)
        assert prefixed.reason == policy.deny_reason, (
            "an ungranted first word stopped answering first. If this is now the adapter "
            "message, something taught the classifier to look past a prefix - which is the "
            "special casing #971 removed, rebuilt one layer down"
        )


def test_a_blank_glued_to_an_ungranted_word_is_not_blamed_for_the_refusal():
    """The composition #971 retires"""
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


# C3 / C4 - what the removal leaves behind.
def _identifier_hits(name: str, *, skip: set[str]) -> dict[str, list[int]]:
    """Every line under `defender/` naming `name`, by file - tests included, this file's own
    suite excluded (it names the symbol in prose about its removal)."""
    hits: dict[str, list[int]] = {}
    pattern = re.compile(rf"\b{re.escape(name)}\b")
    for path in DEFENDER.rglob("*.py"):
        if path.name in skip or ".venv" in path.parts:
            continue
        lines = [
            i for i, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1)
            if pattern.search(line)
        ]
        if lines:
            hits[str(path.relative_to(DEFENDER))] = lines
    return hits


def test_the_paren_fall_through_still_fails_closed_a_layer_up():
    """`(` and `)` still break a word without being operators the grammar accepts, so `cat <(id)` still reaches argv as ordinary words and is still..."""
    assert _parsed("cat <(id)") == [[["cat", "<(", "id", ")"]]]
    assert _parsed("bash -c 'cat <(id)'") == [[["bash", "-c", "cat <(id)"]]]
    for cmd in ("cat <(id)", "bash -c 'cat <(id)'"):
        d = _bash(cmd)
        why = (f"{cmd!r}: the parens reach argv as ordinary words and the argv-reading guard "
               "is what refuses them - a capability refusal, not a lexing one")
        assert not d.allow, why
        assert d.reason == base.MAIN.deny_reason, why
