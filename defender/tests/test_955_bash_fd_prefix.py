"""#955 F-50 — the fd prefix is a property of the raw text, not of the previous token.

Both redirect arms used to decide "is this an fd 2 redirect?" by asking whether the previous
TOKEN was `2`. Nothing in the token stream can answer that. `bash_exec.tokenize` is `shlex`
with punctuation splitting on, which cuts operator characters off whatever they were glued to,
and bash's grammar is entirely about that glue: `2>` is one indivisible IO_NUMBER redirect and
`2 >` is the word `2` followed by a redirect of STDOUT. Both arrive as `['2', '>']`, and
`'a 2>&1'` and `'a 2 >& 1'` tokenize to identical lists.

So `head -c 2 >/dev/null` was accepted as an fd 2 redirect and the `2` silently popped: the
executor ran `head -c`, a different command from the one the model wrote, while `head -c 20
>/dev/null` was refused. Two properties broke at once — the gate's verdict turned on an
ARGUMENT'S VALUE, which no grant is expressed in, and the argv that ran was not the argv that
was checked.

WHY THE #897 DIFFERENTIAL COULD NOT CATCH THIS, AND WHAT THIS FILE ADDS

`test_bash_differential_897.py` asserts one direction: anything real bash REJECTS, `parse`
must refuse. Bash accepts `head -c 2 >/dev/null` — it is perfectly legal bash — and so did we.
Both sides said yes. The disagreement was about what the command MEANS, and an oracle that
compares accept/reject verdicts is structurally blind to it, whatever its corpus. (Its
alphabet could not render the shape either: one stand-in word, and redirects only ever spelled
pre-glued.) The class #897 named is narrower than the class that keeps producing these.

The differential below closes that direction: for every shape we ACCEPT, bash is asked what it
actually does — the argv the command runs and where its stderr goes — and our parse must agree.
It fails against the pre-#955 parser on the first accepted mis-spelling.
"""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from defender.runtime import bash_exec

#: The word every candidate runs. A shim rather than a real tool, because the oracle needs the
#: argv bash actually passed — recovered from a FILE, not from stdout, so a candidate that
#: redirects cannot erase the evidence of what it redirected.
_SHIM = "w"
_SHIM_SRC = """#!/bin/sh
for a in "$@"; do printf '%s\\n' "$a" >> "$W_ARGV"; done
printf 'ARGV_END\\n' >> "$W_ARGV"
printf 'OUT\\n'
printf 'ERR\\n' >&2
"""


def _parsed(cmd: str):
    """`(argv, stderr)` of the single stage `cmd` parses to, or `None` if we refuse it."""
    try:
        pipelines = bash_exec.parse(cmd)
    except bash_exec.BashExecError:
        return None
    stages = [s for p in pipelines for s in p.stages]
    assert len(stages) == 1, f"{cmd!r} is not the single-stage shape this file is about"
    return stages[0].argv, stages[0].stderr


# --------------------------------------------------------------------------- #
# The properties, which need no bash.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("operand", ["2", "20", "1", "0", "9", "x"])
def test_the_verdict_does_not_depend_on_the_value_of_an_operand(operand):
    """The headline property, stated over values rather than over the one value that broke.

    A gate whose answer moves with an argument's VALUE is answering a question no grant asks.
    `head -c 2 >/dev/null` was accepted and `head -c 20 >/dev/null` refused, which is not a
    distinction any policy in this tree can express — and the accepted one ran `head -c`."""
    assert _parsed(f"head -c {operand} >/dev/null") is None, (
        f"a spaced `>` redirect was accepted after the operand {operand!r} — the fd prefix is "
        "being read off the previous token, so the verdict moves with an argument's value"
    )
    assert _parsed(f"head -c {operand} >& 1") is None


@pytest.mark.parametrize(("cmd", "argv"), [
    # The spaced spellings, which this executor REFUSES — `>`/`>&` after a bare `2` is a
    # redirect of STDOUT, which is not on this surface. `None` is the whole assertion.
    ("head -c 2 >/dev/null", None),
    ("cat /etc/hosts 2 >/dev/null", None),
    ("tail -n 2 >&1", None),
    ("cut -f 2 >& 1", None),
    # …and the ACCEPTED neighbours, which are where an operand can actually go missing. The
    # expected argv is written out rather than derived from `cmd.split()`: a derivation has to
    # re-implement the grammar under test to know which words are operator and which are
    # operand, and gets it wrong on exactly the shapes that matter (for `cut -f 2 >& 1` it
    # keeps the redirect TARGET `1` as an operand). Every case above refuses, so a body that
    # only asserted on the accepted ones asserted NOTHING at all.
    ("head -c 2 2>/dev/null", ["head", "-c", "2"]),
    ("cat /etc/hosts 2>/dev/null", ["cat", "/etc/hosts"]),
    ("tail -n 2 2>&1", ["tail", "-n", "2"]),
    ("cut -f 2 2>&1", ["cut", "-f", "2"]),
    ("cut -f 22 2>&1", ["cut", "-f", "22"]),
    ("echo 2 2>/dev/null", ["echo", "2"]),
])
def test_an_accepted_command_never_loses_an_operand(cmd, argv):
    """The second half of the defect: when the fd test fired wrongly, it POPPED the operand.

    Whatever the verdict, the argv that survives parse must be the argv the model wrote. A
    refusal satisfies this; a silent rewrite does not, and the executor and the gate share
    this parse, so neither could see the substitution. The only word a redirect may remove is
    the fd prefix that IS the redirect — `head -c 2 2>/dev/null` keeps its `-c 2`."""
    result = _parsed(cmd)
    if argv is None:
        assert result is None, f"{cmd!r} was accepted — a spaced `>` is a redirect of stdout"
        return
    assert result is not None, f"{cmd!r} was refused — the fd redirect itself broke"
    assert result[0] == argv, f"{cmd!r} parsed to {result[0]} — an operand was dropped"


@pytest.mark.parametrize(("cmd", "stderr"), [
    ("head -c 2 2>/dev/null", "devnull"),
    ("cat /etc/hosts 2>/dev/null", "devnull"),
    ("head -c 2 2>&1", "stdout"),
    ("echo 2>/dev/null", "devnull"),
])
def test_the_glued_spelling_still_works(cmd, stderr):
    """The fix must not cost the construct it is about. `2>` written the way bash means it —
    glued, at the start of its own word — is still an fd 2 redirect, and the `2` that IS the
    prefix is the only word removed."""
    result = _parsed(cmd)
    assert result is not None, f"{cmd!r} was refused — the fd redirect itself broke"
    argv, got = result
    assert got == stderr
    assert argv == cmd.split()[:-1], f"{cmd!r} parsed to {argv}"


@pytest.mark.parametrize("cmd", [
    "echo '2' >/dev/null", 'echo "2" >/dev/null', "foo2>/dev/null",
    # A character bash does not split on keeps the `2` INSIDE the previous word, so it is not
    # an IO_NUMBER — `a\r2>` is the word `a\r2` redirecting stdout. Read `\r` as a blank and
    # the same text becomes `a` plus an fd-2 redirect: the operand vanishes and the routing
    # inverts. This is the fd question and the word-boundary question meeting on one input.
    "echo a\r2>/dev/null", "echo a\xa02>/dev/null",
])
def test_a_quoted_or_suffixed_two_is_not_an_fd(cmd):
    """Bash's IO_NUMBER is an UNQUOTED digit run that starts its own word. A quoted `2` is an
    ordinary argument and `foo2>` is the word `foo2`; in both, bash redirects stdout, which
    this executor does not implement — so the answer is a refusal, never a stderr redirect."""
    assert _parsed(cmd) is None


@pytest.mark.parametrize(("cmd", "argv"), [
    (r"find . -name '*.py' -exec grep -l x {} \;",
     ["find", ".", "-name", "*.py", "-exec", "grep", "-l", "x", "{}", ";"]),
    ("find . -exec ls {} ';'", ["find", ".", "-exec", "ls", "{}", ";"]),
    (r"echo \; foo", ["echo", ";", "foo"]),
    ('echo "|" x', ["echo", "|", "x"]),
    ('echo "&&"', ["echo", "&&"]),
])
def test_a_quoted_or_escaped_operator_is_a_word(cmd, argv):
    r"""The same defect as F-50, in the other direction: not "is this operator an fd?" but "is
    this an operator at all?" — and the token stream cannot answer that either.

    Every arm of the builder dispatches on a token's TEXT, and `shlex` hands back the resolved
    VALUE, so an escaped `\;` and a bare `;` are the same token. `find -exec … \;` therefore
    lost the terminator `find` cannot run without, silently, and the executor ran a command
    `find` rejects. Fixed in the same place as F-50, because it is the same missing bit: what
    the raw text said, as against what the value came out as."""
    parsed = _parsed(cmd)
    assert parsed is not None, f"{cmd!r} was refused — a quoted operator is an ordinary word"
    assert parsed[0] == argv, f"{cmd!r} parsed to {parsed[0]}"


@pytest.mark.parametrize(("cmd", "argv"), [
    # An unquoted `#` that STARTS a word opens a comment, and the rest of the line is not
    # command text. Everything after it — operands, and the `;`/`|` that would otherwise
    # separate stages — is gone, as it is for bash.
    ("w a # b", ["w", "a"]),
    ("w a #b", ["w", "a"]),
    ("w a #", ["w", "a"]),
    ("w #", ["w"]),
    ("w a # ; w b", ["w", "a"]),
    # ...and a `#` that does NOT start a word is an ordinary character, in all three of the
    # spellings that make it one.
    ("w a# b", ["w", "a#", "b"]),
    ("w a '#' b", ["w", "a", "#", "b"]),
    (r"w a\#b", ["w", "a#b"]),
])
def test_an_unquoted_hash_that_starts_a_word_opens_a_comment(cmd, argv):
    r"""F-50's own class, on the third fact the raw text has to answer.

    `shlex` resolves a word to its VALUE before any arm looks, so a `#` that opened a comment
    and a `#` that stood for itself arrive as the same token — and the scanner, reading the
    token stream, kept both. `w a # ; w b` therefore parsed to TWO stages where bash runs ONE
    command and a comment: the executor running an argv the model's own text says is commented
    out, and the gate authorising that one. The converse matters as much: `a#b` is a filename,
    `'#'` is a grep pattern, and truncating either would deny a command bash runs."""
    parsed = _parsed(cmd)
    assert parsed is not None, f"{cmd!r} was refused — a comment is not a lexing failure"
    assert parsed[0] == argv, f"{cmd!r} parsed to {parsed[0]}"


@pytest.mark.parametrize("cmd", ["w a|#b", "w a&&#b", "w >#x", "w 2>#x"])
def test_an_operator_left_dangling_by_a_comment_still_fails(cmd):
    """The control the test above needs: dropping the comment must not smuggle an operator
    past the checks that exist for it. Each of these is a bash SYNTAX ERROR — the comment ate
    the token the operator needed — and each must stay a refusal here rather than becoming a
    line that quietly runs its left half."""
    assert _parsed(cmd) is None


@pytest.mark.parametrize("cmd", ["w a)2>/dev/null", "w a(2>/dev/null"])
def test_a_paren_is_not_a_word_boundary_an_fd_may_follow(cmd):
    """`_SHLEX_PUNCTUATION` is wider than bash's operator set, and the gap is `(`/`)`. Reading
    the wide set as "a word starts here" made `w a)2>/dev/null` an fd-2 redirect — the `2`
    popped off argv and stderr rerouted — on a line `bash -n` refuses outright. That is the
    accept-what-bash-rejects direction `test_bash_differential_897.py` exists to close, and
    the operand loss is F-50's own defect."""
    assert _parsed(cmd) is None


@pytest.mark.parametrize("cmd", ["w a;2>/dev/null", "w a 2>/dev/null"])
def test_a_real_operator_boundary_still_admits_the_fd(cmd):
    """The control: the refusal above must be about the PAREN, not about narrowing the
    predecessor set until no fd redirect is ever recognised again."""
    assert _parsed(cmd) is not None


#: Characters `str.isspace()` OR `shlex.whitespace` calls whitespace and BASH does not. The
#: two candidate sets a scanner might be copied from are both wider than bash's, which is
#: space and tab: `str.isspace()` is a Unicode predicate, and `shlex.whitespace` is
#: ' \t\r\n' — one character wider than bash's default IFS of space/tab/newline. Every
#: character here is an ordinary word character to `bash` itself, which is the only oracle
#: that counts.
_NOT_SHELL_BLANKS = [
    # `\r` FIRST, because it is the one `shlex.whitespace` contains and bash does not, so it
    # is the only member of this list a scanner copied from `shlex` gets wrong. `cat a\rb`
    # is one word to bash; splitting it hands the gate an argv the model never wrote.
    "\r",
    "\x0b", "\x0c", "\x1c", "\x1f", "\x85", "\xa0", "\u2003", "\u3000",
]


#: The same question as `_NOT_SHELL_BLANKS`, asked so that RECALL cannot answer it.
#:
#: That list is written by hand, and it was wrong: it omitted `\r`, the one character where the
#: two libraries disagree with each other. It was wrong because of HOW it was derived — by
#: asking "what does `str.isspace()` add to `shlex`?", a question that can see what `isspace`
#: gets wrong and is structurally blind to what `shlex` gets wrong. Enumerating an axis from
#: one side is not enumerating it.
#:
#: So this derives the alphabet from the libraries themselves — every character either
#: plausible source calls whitespace — and asks bash about each. A scanner copied from a THIRD
#: source (a `\s` regex, a Unicode category test) lands inside this set whatever it picks, and
#: nobody has to have remembered it.
#: U+3000 IDEOGRAPHIC SPACE is the highest code point `str.isspace()` answers True for, so the
#: scan stops there rather than walking all 1,114,112 of them — the same 29 characters, at
#: pytest COLLECTION time, which every filtered run of this tree pays whether or not a test in
#: this file is selected. `test_the_candidate_ceiling_still_holds` re-derives the ceiling from
#: the full range, so the bound is machine-checked rather than asserted in prose.
_ISSPACE_CEILING = 0x3000

_CANDIDATE_BLANKS = sorted(
    {c for c in map(chr, range(_ISSPACE_CEILING + 1)) if c.isspace()}
    | set(shlex.shlex("").whitespace)
)


def test_the_candidate_ceiling_still_holds():
    """The bound `_CANDIDATE_BLANKS` is derived under, paid once, in a test body rather than at
    import. If a future Unicode revision adds a whitespace character above U+3000, the
    alphabet above would silently stop covering it — and an alphabet that quietly narrows is
    the failure `_CANDIDATE_BLANKS` was written to prevent."""
    highest = max(c for c in map(chr, range(0x110000)) if c.isspace())
    assert ord(highest) == _ISSPACE_CEILING, (
        f"U+{ord(highest):04X} is whitespace and above the ceiling the alphabet is built "
        "under, so `_CANDIDATE_BLANKS` no longer enumerates the axis"
    )


@pytest.mark.parametrize("blank", _CANDIDATE_BLANKS, ids=lambda c: f"U+{ord(c):04X}")
def test_our_word_boundary_is_bash_s_word_boundary(shim_dir, blank):
    """For every character either library calls whitespace, we split iff bash splits.

    Not "we agree with `shlex`" and not "we agree with a list" — bash is the only oracle that
    counts, because the argv is a claim about what bash would run. Asserting EQUALITY with
    bash's argv pins both directions from one observation, so it cannot be satisfied by a
    scanner that never splits, nor by one that splits on everything."""
    if blank == "\n":
        pytest.skip("`parse` splits the command on newlines before a line reaches the scanner")
    cmd = f"{_SHIM} a{blank}b"
    theirs = _bash_meaning(shim_dir, cmd)
    if theirs is None or theirs[0] is None:
        pytest.skip("bash will not run this shape, so it makes no claim about the boundary")
    ours = _parsed(cmd)
    assert ours is not None, f"U+{ord(blank):04X} made an ordinary command untokenizable"
    assert ours[0] == theirs[0], (
        f"U+{ord(blank):04X}: we would run {ours[0]}, bash runs {theirs[0]} — the gate "
        "authorises our argv and the executor runs it, so this IS the divergence"
    )


@pytest.mark.parametrize("blank", _NOT_SHELL_BLANKS)
def test_a_character_the_shell_does_not_split_on_stays_inside_its_word(blank):
    """The third question the raw text has to answer, beside "glued?" and "an operator?":
    WHERE DOES THE WORD END?

    `str.isspace()` is a Unicode predicate and the shell's blank set is four ASCII characters.
    Reaching for the former cut `cat 'a\xa0b'` into `['cat', 'a', 'b']` — two operands where
    the model wrote one, and neither of them the file it named. That is F-50's own defect
    (the argv that runs is not the argv that was written, and the gate authorises the rewritten
    one) one character class over, and it is worse than a mis-parse: it moved a real VERDICT,
    turning a `cat <run_dir>/a\xa0b` that the main policy denied — the NBSP fails its path
    shape — into an allow on a two-operand argv whose halves each pass."""
    result = _parsed(f"w -n a{blank}b")
    assert result is not None, f"U+{ord(blank):04X} made an ordinary command untokenizable"
    assert result[0] == ["w", "-n", f"a{blank}b"], (
        f"U+{ord(blank):04X} split a word bash keeps whole — the executor would run an argv "
        "the model did not write, and the gate would have authorised that one"
    )


@pytest.mark.parametrize("blank", [" ", "\t"])
def test_the_characters_the_shell_DOES_split_on_still_split(blank):
    """The control the test above needs: pinning "do not split on X" is satisfied by a scanner
    that never splits at all, which would collapse every command into a single argv word."""
    assert _parsed(f"w -n a{blank}b")[0] == ["w", "-n", "a", "b"]


def test_an_unquoted_operator_is_still_an_operator():
    """The control the test above needs: if quoting were ignored the other way round, every
    pipeline in the tree would collapse into one argv and this file would still be green."""
    stages = [s for p in bash_exec.parse("a | b && c") for s in p.stages]
    assert [s.argv for s in stages] == [["a"], ["b"], ["c"]]


# --------------------------------------------------------------------------- #
# The same invariant, at the layer that actually decides.
# --------------------------------------------------------------------------- #
def test_the_gate_does_not_rewrite_the_command_before_it_parses_it():
    """`decide_bash` is the entry point; `bash_exec.parse` is a step inside it.

    Pinning the scanner alone is not enough, and this is the case that proves it: the scanner's
    blank set was narrowed to bash's on the reasoning that `\r`, NBSP and the Unicode spaces
    belong INSIDE a word — and one call above it the gate did `command.strip()`, which is the
    Unicode predicate, deleting exactly those characters before the scanner ever saw them. The
    fix held at the layer under test and was undone at the layer that ships. So the argv the
    GATE authorises is what this asserts on, since that tuple is what crosses into the box.

    Every #955 defect is two rules where the code needs one, and every one of them has been
    found at a seam rather than inside a function. This is the seam.
    """
    from defender.agents import GATHER_DEF
    from defender.runtime.agent_definition import compile_policy_for
    from defender.runtime.permission import decide_bash

    run_dir = Path(tempfile.mkdtemp()) / "run"
    run_dir.mkdir(parents=True)
    defender_dir = run_dir / "defender"
    defender_dir.mkdir()
    target = run_dir / "report.md"
    target.write_text("x", encoding="utf-8")
    policy = compile_policy_for(GATHER_DEF, run_dir=run_dir, defender_dir=defender_dir)

    for blank in _NOT_SHELL_BLANKS:
        cmd = f"cat {target}{blank}"
        decision = decide_bash(
            cmd, policy=policy, run_dir=run_dir, defender_dir=defender_dir,
        )
        if decision.pipelines is None:
            # Refused — always this executor's prerogative, and it means no argv was
            # authorised, which cannot be the wrong argv.
            continue
        gate_argv = [s.argv for p in decision.pipelines for s in p.stages]
        scanner_argv = [s.argv for p in bash_exec.parse(cmd) for s in p.stages]
        assert gate_argv == scanner_argv, (
            f"U+{ord(blank):04X}: the gate authorised {gate_argv} while the scanner reads "
            f"{scanner_argv} — the command was rewritten between the two, so the argv that "
            "runs is not the one the scanner's word-boundary rule was verified against"
        )


# --------------------------------------------------------------------------- #
# The differential: for everything we accept, bash says what it MEANS.
# --------------------------------------------------------------------------- #
_CANDIDATES = [
    f"{_SHIM} -c {v}{sp}{redir}"
    for v in ("2", "20", "x")
    for sp in (" ", "")
    for redir in (">/dev/null", ">&1", "2>/dev/null", "2>&1", "> /dev/null", ">& 1")
] + [
    f"{_SHIM} {arg}" for arg in ("2>/dev/null", "2 >/dev/null", "2>&1", "2 >&1", "2")
] + [
    f"{_SHIM} -n 2>/dev/null", f"{_SHIM} -n 2 2>/dev/null", f"{_SHIM} 2 2>&1",
] + [
    # The comment question, against the same oracle. `#` was absent from this alphabet, which
    # is why the differential was green while `w a # ; w b` ran a stage bash comments away.
    f"{_SHIM} a # b", f"{_SHIM} a #b", f"{_SHIM} a# b", f"{_SHIM} a #",
    f"{_SHIM} a # ; {_SHIM} b", f"{_SHIM} a '#' b", f"{_SHIM} -c 2 # 2>/dev/null",
    f"{_SHIM} a )2>/dev/null", f"{_SHIM} a;2>/dev/null",
] + [
    # The separator question and the fd question, on ONE candidate each. A character bash does
    # not split on, glued to the `2` of a redirect, is where the two defects meet: split the
    # word and `a\r2>` becomes the word `a` plus an fd-2 redirect, where bash sees the word
    # `a\r2` and a redirect of STDOUT — an operand lost AND the routing inverted, which is
    # exactly what `_bash_meaning` is here to catch. `\r` is the member of `shlex.whitespace`
    # that bash's IFS does not carry, so it is the one a scanner copied from `shlex` gets wrong.
    f"{_SHIM} -n a\rb", f"{_SHIM} -n a\rb 2>/dev/null", f"{_SHIM} a\xa0b 2>&1",
]


@pytest.fixture(scope="module")
def shim_dir():
    if shutil.which("bash") is None:
        pytest.skip("the differential oracle IS bash; without it this asserts nothing")
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / _SHIM
        path.write_text(_SHIM_SRC, encoding="utf-8")
        path.chmod(0o755)
        # The bash path is resolved ONCE, here, rather than per candidate: `shutil.which`
        # walks the whole PATH with a stat per directory, and the candidate matrix is a
        # cross product that only grows.
        yield Path(d), shutil.which("bash")


def _bash_meaning(shim: tuple[Path, str], cmd: str):
    """What bash DOES with `cmd`: the argv it passed the shim, and where the shim's stderr
    marker landed. `None` if bash itself refuses the text."""
    shim_dir, bash = shim
    argv_file = shim_dir / "argv.out"
    argv_file.unlink(missing_ok=True)
    # The shim dir goes in FRONT of the inherited PATH rather than replacing it: `subprocess`
    # resolves the executable against the PATH in `env`, so a bare replacement loses bash too.
    env = {
        **os.environ,
        "PATH": f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "W_ARGV": str(argv_file),
    }
    if subprocess.run([bash, "-n", "-c", cmd], capture_output=True).returncode != 0:
        return None
    proc = subprocess.run(
        [bash, "-c", cmd], capture_output=True, text=True, env=env, cwd=shim_dir,
    )
    # BYTES, not `read_text`: text mode translates a lone `\r` (and `\r\n`) to `\n`, and
    # the split below is on `\n` — so an argv word bash kept whole came back as TWO words
    # and the oracle agreed with a parse that had split it. The one character this file
    # exists to police is the one the reader would have silently rewritten.
    raw = argv_file.read_bytes().decode("utf-8") if argv_file.exists() else ""
    words = raw.split("\n")
    argv = [_SHIM] + words[:words.index("ARGV_END")] if "ARGV_END" in words else None
    if "ERR" in proc.stdout:
        where = "stdout"
    elif "ERR" in proc.stderr:
        where = "capture"
    else:
        where = "devnull"
    return argv, where


@pytest.mark.parametrize("cmd", _CANDIDATES)
def test_what_we_accept_means_what_bash_means(shim_dir, cmd):
    """The direction #897's file does not assert, and the only one that could see F-50.

    #897 tests that text bash REJECTS, we refuse. F-50 lived where bash and we both said yes
    and meant different things: bash ran `w -c 2` with stdout on /dev/null, we ran `w -c` with
    stderr on /dev/null. Same verdict, different command. So for every candidate we accept,
    ask bash what it actually ran and where the stderr went, and require both to match.

    The converse stays unasserted, exactly as over there: we deliberately refuse plenty that
    bash accepts (every stdout redirect, for one — this executor does not implement it)."""
    ours = _parsed(cmd)
    if ours is None:
        return                      # refusing more than bash is this executor's prerogative
    theirs = _bash_meaning(shim_dir, cmd)
    assert theirs is not None, f"we accepted {cmd!r} and bash will not even parse it"
    argv, where = theirs
    assert argv is not None, f"we accepted {cmd!r} but bash never ran the command in it"
    assert ours[0] == argv, (
        f"{cmd!r}: we would run {ours[0]}, bash runs {argv} — the executor and the gate share "
        "this parse, so neither can see the substitution"
    )
    assert ours[1] == where, (
        f"{cmd!r}: we route stderr to {ours[1]!r}, bash routes it to {where!r}"
    )
