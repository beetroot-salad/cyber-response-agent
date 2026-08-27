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


#: What `_parsed` reports for a candidate that parses to anything other than ONE stage. A
#: DISTINCT value from the `None` that means "we refuse it", and distinct on purpose: every
#: differential below reads `None` as "refused, nothing to compare" and returns early, so one
#: shared sentinel makes a stage-count regression — a word boundary moving until one stage
#: becomes two, which is the class this whole file exists to catch — read as a refusal and skip
#: the bash comparison in silence. Reported rather than raised, so a multi-stage candidate is a
#: candidate and not a crash; `_single` is what turns the report into a loud failure at the call
#: sites that meant to hand this file a single-stage command.
MULTI_STAGE = object()


def _parsed(cmd: str):
    """`(argv, stderr)` of the single stage `cmd` parses to, `None` if we refuse it, or
    `MULTI_STAGE` if it parses to anything other than exactly one stage."""
    try:
        pipelines = bash_exec.parse(cmd)
    except bash_exec.BashExecError:
        return None
    stages = [s for p in pipelines for s in p.stages]
    if len(stages) != 1:
        return MULTI_STAGE
    return stages[0].argv, stages[0].stderr


def _single(cmd: str):
    """`_parsed(cmd)` for a caller that means a SINGLE-STAGE candidate: the multi-stage report
    becomes a failure here rather than silently taking the "we refused it" branch."""
    result = _parsed(cmd)
    assert result is not MULTI_STAGE, (
        f"{cmd!r} parses to more than one stage, so this differential compared nothing. One "
        "stage becoming two is a word boundary that moved — the defect class this file is "
        "about — and reading it as a refusal is how that regression would stay green."
    )
    return result


# --------------------------------------------------------------------------- #
# The properties, which need no bash.
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("operand", ["2", "20", "1", "0", "9", "x"])
def test_the_verdict_does_not_depend_on_the_value_of_an_operand(operand):
    """The headline property, stated over values rather than over the one value that broke.

    A gate whose answer moves with an argument's VALUE is answering a question no grant asks.
    `head -c 2 >/dev/null` was accepted and `head -c 20 >/dev/null` refused, which is not a
    distinction any policy in this tree can express — and the accepted one ran `head -c`."""
    assert _single(f"head -c {operand} >/dev/null") is None, (
        f"a spaced `>` redirect was accepted after the operand {operand!r} — the fd prefix is "
        "being read off the previous token, so the verdict moves with an argument's value"
    )
    assert _single(f"head -c {operand} >& 1") is None


@pytest.mark.parametrize("cmd", [
    "head -c 2 >/dev/null",
    "cat /etc/hosts 2 >/dev/null",
    "tail -n 2 >&1",
    "cut -f 2 >& 1",
])
def test_an_accepted_command_never_loses_an_operand(cmd):
    """The second half of the defect: when the fd test fired wrongly, it POPPED the operand.

    Whatever the verdict, the argv that survives parse must be the argv the model wrote. A
    refusal satisfies this; a silent rewrite does not, and the executor and the gate share
    this parse, so neither could see the substitution."""
    result = _single(cmd)
    if result is None:
        return
    argv, _stderr = result
    words = [w for w in cmd.split() if w not in (">", ">&") and not w.startswith(">")]
    assert argv == words, f"{cmd!r} parsed to {argv} — an operand was dropped"


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
    result = _single(cmd)
    assert result is not None, f"{cmd!r} was refused — the fd redirect itself broke"
    argv, got = result
    assert got == stderr
    assert argv == cmd.split()[:-1], f"{cmd!r} parsed to {argv}"


@pytest.mark.parametrize("cmd", ["echo '2' >/dev/null", 'echo "2" >/dev/null', "foo2>/dev/null"])
def test_a_quoted_or_suffixed_two_is_not_an_fd(cmd):
    """Bash's IO_NUMBER is an UNQUOTED digit run that starts its own word. A quoted `2` is an
    ordinary argument and `foo2>` is the word `foo2`; in both, bash redirects stdout, which
    this executor does not implement — so the answer is a refusal, never a stderr redirect."""
    assert _single(cmd) is None


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
    parsed = _single(cmd)
    assert parsed is not None, f"{cmd!r} was refused — a quoted operator is an ordinary word"
    assert parsed[0] == argv, f"{cmd!r} parsed to {parsed[0]}"


def test_an_unquoted_operator_is_still_an_operator():
    """The control the test above needs: if quoting were ignored the other way round, every
    pipeline in the tree would collapse into one argv and this file would still be green."""
    stages = [s for p in bash_exec.parse("a | b && c") for s in p.stages]
    assert [s.argv for s in stages] == [["a"], ["b"], ["c"]]


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
]


@pytest.fixture(scope="module")
def shim_dir():
    if shutil.which("bash") is None:
        pytest.skip("the differential oracle IS bash; without it this asserts nothing")
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / _SHIM
        path.write_text(_SHIM_SRC, encoding="utf-8")
        path.chmod(0o755)
        yield Path(d)


def _inner_c_argument(cmd: str) -> str | None:
    """The `-c` argument of a `bash -c '<...>'`/`sh -c '<...>'` candidate, extracted with
    `shlex` — deliberately NOT `bash_exec`, so the oracle's own precheck cannot inherit a bug
    from the very thing it exists to catch. `None` for anything that is not exactly that shape."""
    try:
        tokens = shlex.split(cmd)
    except ValueError:
        return None
    if len(tokens) == 3 and tokens[0] in ("bash", "sh") and tokens[1] == "-c":
        return tokens[2]
    return None


def _bash_meaning(shim_dir: Path, cmd: str):
    """What bash DOES with `cmd`: the argv it passed the shim, and where the shim's stderr
    marker landed. `None` if bash itself refuses the text, OR if it is a `bash -c`/`sh -c`
    wrapper whose INNER payload is independently broken — the outer `bash -n -c "<outer>"`
    reports nothing about a nested `-c '<inner>'` payload's own syntax (#959 pj3), so a second,
    independent precheck runs over the extracted inner text too.

    Every evidence channel here is read in BINARY (#959 M6(b)): `Path.read_text` and
    `subprocess.run(text=True)` both universal-newline-translate a bare `\\r` into the very
    delimiter the argv recovery splits on, so a `\\r` divergence was reported clean by the
    oracle that exists to catch it (#955's blind spot 2, still live before this fix)."""
    argv_file = shim_dir / "argv.out"
    argv_file.unlink(missing_ok=True)
    # The shim dir goes in FRONT of the inherited PATH rather than replacing it: `subprocess`
    # resolves the executable against the PATH in `env`, so a bare replacement loses bash too.
    bash = shutil.which("bash")
    env = {
        **os.environ,
        "PATH": f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "W_ARGV": str(argv_file),
    }
    if subprocess.run([bash, "-n", "-c", cmd], capture_output=True, timeout=60).returncode != 0:
        return None
    inner = _inner_c_argument(cmd)
    if inner is not None and subprocess.run(
        [bash, "-n", "-c", inner], capture_output=True, timeout=60,
    ).returncode != 0:
        return None
    proc = subprocess.run(
        [bash, "-c", cmd], capture_output=True, env=env, cwd=shim_dir, timeout=60,
    )
    raw = argv_file.read_bytes() if argv_file.exists() else b""
    words = raw.split(b"\n")
    argv = (
        [_SHIM] + [w.decode("utf-8", "surrogateescape") for w in words[:words.index(b"ARGV_END")]]
        if b"ARGV_END" in words else None
    )
    stdout = proc.stdout.decode("utf-8", "surrogateescape")
    stderr = proc.stderr.decode("utf-8", "surrogateescape")
    if "ERR" in stdout:
        where = "stdout"
    elif "ERR" in stderr:
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
    ours = _single(cmd)
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


# ============================================================================================ #
# #959 — the wrapper seam, the blank alphabet, and the oracle's own evidence channels.
#
# Folding the standalone `hooks/_cmd_segments` wrapper step into `parse` (M3) puts the wrapper under this
# differential for the first time: today neither this corpus nor #897's contains a wrapper
# word, a carriage return, or any blank but an ordinary space (claims c9, x12), so the three
# classes this change touches have never been put to bash at all.
#
# Blind spot (2) is still live in the file that was said to have closed it: line 199 recovers
# the recorded argv with `read_text(encoding="utf-8")`, whose universal-newline translation
# turns a bare `\r` into the very delimiter line 200 splits on — so a `\r` in an argument is
# recovered as two entries and the oracle certifies the `\r` divergence CLEAN. Every blank
# below is built from its codepoint for the same reason the corpus is: a literal in a docstring
# is a character a later edit can normalise into a space.
# ============================================================================================ #

import ast as _ast  # noqa: E402
import sys as _sys  # noqa: E402

_CR = chr(0x000D)
_NBSP = chr(0x00A0)
_THIS_FILE = Path(__file__).resolve()

#: WRAPPER SHAPES ARE GONE FROM THIS DIFFERENTIAL (#971), and the list is kept as an empty
#: tuple with this note rather than deleted, because "why is there no wrapper coverage here"
#: is the question a later reader will ask.
#:
#: The oracle asks bash what a command it ACCEPTS actually ran. The parse accepts no wrapper any
#: more: `bash -c '<payload>'` is three ordinary words whose first is an ungranted program, and
#: `timeout N <cmd>` likewise, so there is no folded command for bash to be answerable about.
#: Asking anyway would compare the wrong things — the oracle measures which argv reached the
#: shim, and a wrapper we pass through reaches it one exec level below what we model.
#:
#: What is left to pin is that those shapes DENY, and that is
#: `test_959_wrapper_fold.py::test_no_word_is_parsed_as_a_wrapper`'s, over a wider shape list
#: than this file ever carried.
_WRAPPER_CANDIDATES: list[str] = []


def _stages(cmd: str):
    """Every stage `cmd` parses to, as argv lists — the multi-stage shape `_parsed` refuses."""
    return [list(s.argv) for p in bash_exec.parse(cmd) for s in p.stages]


def _bash_argv_bytes(shim_dir: Path, cmd: str) -> list[str] | None:
    """The argv bash passed the shim, recovered from the evidence file IN BINARY.

    Deliberately not `_bash_meaning`: that recovery is itself under repair here (M6(b)), and a
    test of the SCANNER that recovers its evidence through a normalising read is green whenever
    the two make the same mistake — which is exactly how a `\r` divergence stayed certified
    clean. `None` when bash never ran the shim."""
    bash = shutil.which("bash")
    argv_file = shim_dir / "argv.bytes"
    argv_file.unlink(missing_ok=True)
    env = {
        **os.environ,
        "PATH": f"{shim_dir}{os.pathsep}{os.environ.get('PATH', '')}",
        "W_ARGV": str(argv_file),
    }
    subprocess.run(
        [bash, "-c", cmd], capture_output=True, env=env, cwd=shim_dir, timeout=60,
    )
    if not argv_file.exists():
        return None
    entries = argv_file.read_bytes().split(b"\n")
    if b"ARGV_END" not in entries:
        return None
    return [_SHIM] + [e.decode("utf-8", "surrogateescape")
                      for e in entries[:entries.index(b"ARGV_END")]]


@pytest.mark.parametrize("cmd", _WRAPPER_CANDIDATES)
def test_a_wrapper_shape_we_accept_means_what_bash_means(shim_dir, cmd):
    """The differential's corpus carries wrapper shapes — `bash -c '<candidate>'`, including the
    glued-operator spelling — so for every wrapper the parse accepts, real bash is asked what it
    actually ran and where its stderr went, and the two must agree.

    This is the direction that can see the wrapper defect: `bash -c 'echo a '2>/dev/null` is a
    shape both sides accept and mean differently, and an oracle comparing accept/reject verdicts
    is structurally blind to it whatever its corpus."""
    ours = _single(cmd)
    if ours is None:
        return                      # refusing more than bash is this executor's prerogative
    theirs = _bash_meaning(shim_dir, cmd)
    assert theirs is not None, f"we accepted {cmd!r} and bash will not even parse it"
    argv, where = theirs
    assert argv is not None, f"we accepted {cmd!r} but bash never ran the command in it"
    assert ours[0] == argv, (
        f"{cmd!r}: we would run {ours[0]}, bash runs {argv} — the wrapper the gate strips and "
        "the wrapper bash honours are not the same wrapper"
    )
    assert ours[1] == where, f"{cmd!r}: we route stderr to {ours[1]!r}, bash routes it to {where!r}"


def test_the_oracle_tells_the_inner_shells_stderr_from_the_outer_shells(shim_dir):
    """When the corpus runs bash inside bash, the oracle still tells where the stderr marker
    landed for the command under test rather than for the shell wrapping it."""
    assert _bash_meaning(shim_dir, f"bash -c '{_SHIM} a'")[1] == "capture"
    assert _bash_meaning(shim_dir, f"bash -c '{_SHIM} a 2>/dev/null'")[1] == "devnull"
    assert _bash_meaning(shim_dir, f"bash -c '{_SHIM} a 2>&1'")[1] == "stdout"
    # ...and the argv is the inner command's, not the wrapping shell's.
    assert _bash_meaning(shim_dir, f"bash -c '{_SHIM} a'")[0] == [_SHIM, "a"]


def test_the_scanner_ends_a_word_exactly_where_bash_ends_one(shim_dir):
    r"""No character ends a word here that does not end one in bash: a carriage return inside an
    operand is part of that operand, so `cat /run/report.md\rx` names one file and is not
    authorised as a two-operand command that opens a different one. The same holds at a word
    edge (`cat P\r`), across an operator run (`cat P\r| wc -c`), and for a line that is one
    `\r` and nothing else, which is a one-character word and not zero tokens.

    Rejected: the current `_WORD_SEPARATORS`, which contains `\r` because the shlex lexer it
    replaced did — bash's own blank set is space and tab only. Bash is the oracle here, and it
    is asked with the shim rather than assumed."""
    for cmd in (
        f"{_SHIM} a{_CR}b",
        f"{_SHIM} P{_CR}",
        f"{_SHIM} {_CR}x",
        f"{_SHIM} a{_CR}b c{_CR}d",
    ):
        ours = _single(cmd)
        assert ours is not None, f"{cmd!r} was refused — a carriage return is an ordinary byte"
        theirs = (_bash_argv_bytes(shim_dir, cmd), None)
        assert theirs[0] is not None, f"bash never ran the shim for {cmd!r}"
        assert ours[0] == theirs[0], (
            f"{cmd!r}: we would run {ours[0]}, bash runs {theirs[0]} — the scanner ends a word "
            "where bash does not, so the argv the gate authorises is not the argv the text names"
        )
    # A line that is one carriage return is a one-character word, not zero tokens.
    assert _stages(_CR) == [[_CR]]


def test_our_blank_set_is_the_blank_set_bash_splits_on(shim_dir):
    """The differential's alphabet carries blanks derived from both sides of the comparison —
    `str.isspace()` together with the scanner's own set — so every character one side calls a
    word separator is put to real bash, and a character bash does not split on does not end a
    word here either. The blank must be rendered GLUED to an adjacent token with no separator: a
    space-separated blank cannot exercise the property, and if the corpus renderer cannot do
    that today it gains the machinery."""
    ours_side = set(bash_exec._WORD_SEPARATORS)
    pythons_side = {chr(cp) for cp in range(0x110000) if chr(cp).isspace()}
    alphabet = sorted((ours_side | pythons_side) - {"\n"})
    assert len(alphabet) > 25, "the alphabet collapsed — this asserts nothing over one character"

    disagreements = []
    for blank in alphabet:
        cmd = f"{_SHIM} a{blank}b"          # GLUED: no separator between the blank and a word
        ours = _single(cmd)
        if ours is None:
            continue
        theirs = _bash_argv_bytes(shim_dir, cmd)
        if theirs is None:
            continue
        if ours[0] != theirs:
            disagreements.append((hex(ord(blank)), ours[0], theirs))
    assert not disagreements, (
        "these characters end a word for us and not for bash (or the reverse): "
        f"{disagreements}"
    )


def test_the_oracle_never_normalises_its_own_subject(shim_dir):
    r"""The oracle recovers bash's recorded argv as bytes: nothing between bash and the
    assertion rewrites a byte, so a carriage return in an argument arrives as a carriage return
    and cannot be laundered into the delimiter the recovery then splits on.

    Today's `Path.read_text(encoding="utf-8")` does worse than erase the character — universal
    newline translation treats a bare `\r` as its own line ending, so it phantom-splits entries
    and shifts the `ARGV_END` alignment for everything after them (four expected entries
    recovered as five). The oracle then reports the same wrong argv our own scanner produces,
    and certifies the divergence clean."""
    argv, _where = _bash_meaning(shim_dir, f"{_SHIM} a{_CR}b tail")
    assert argv == [_SHIM, f"a{_CR}b", "tail"], (
        "the recorded argv came back split at the carriage return. bash passed ONE argument; "
        "the recovery invented two, so the oracle agrees with the bug it exists to catch"
    )


def test_no_channel_the_oracle_reads_evidence_through_rewrites_a_byte(shim_dir, tmp_path):
    r"""The binary read is a property of the oracle, not of one line: the stdout and stderr
    capture beside the argv file is held to the same rule, because
    `subprocess.run(..., text=True)` normalises exactly as `read_text` does. No channel between
    bash and the assertion — delimiter, end marker, encoding, capture — may rewrite a byte.

    The normalisation is re-probed here against the real primitives rather than cited, so the
    day the taxonomy changes this test says so instead of quietly passing."""
    evidence = tmp_path / "evidence"
    evidence.write_bytes(b"a" + _CR.encode() + b"b\nARGV_END\n")
    assert evidence.read_bytes().split(b"\n")[0] == b"a" + _CR.encode() + b"b"
    assert evidence.read_text(encoding="utf-8").split("\n")[0] == "a", (
        "read_text no longer universal-newline-translates a bare CR — the claim this demand "
        "rests on has changed and the whole M6(b) argument should be re-examined"
    )
    bash = shutil.which("bash")
    printed = subprocess.run(
        [bash, "-c", "printf 'a\\rb\\n'"], capture_output=True, timeout=60,
    )
    assert printed.stdout == b"a" + _CR.encode() + b"b\n"
    decoded = subprocess.run(
        [bash, "-c", "printf 'a\\rb\\n'"], capture_output=True, text=True, timeout=60,
    )
    assert decoded.stdout != printed.stdout.decode("utf-8"), (
        "text=True no longer rewrites a bare CR — same re-examination as above"
    )

    # ...so no channel THE ORACLE recovers evidence through may be read through either of them.
    # Scanned over this module's helpers only: a `test_` body may hold the rewrite deliberately,
    # as the four assertions above do, and reading this file's own source is not an evidence
    # channel between bash and an assertion.
    tree = _ast.parse(_THIS_FILE.read_bytes().decode("utf-8"))
    helpers = [
        node for node in tree.body
        if isinstance(node, (_ast.FunctionDef, _ast.AsyncFunctionDef))
        and not node.name.startswith("test_")
    ]
    normalising = []
    for helper in helpers:
        for node in _ast.walk(helper):
            if not isinstance(node, _ast.Call) or not isinstance(node.func, _ast.Attribute):
                continue
            if node.func.attr == "read_text":
                normalising.append((helper.name, "read_text", node.lineno))
            if node.func.attr == "run":
                for kw in node.keywords:
                    if kw.arg == "text" and getattr(kw.value, "value", None) is True:
                        normalising.append((helper.name, "subprocess text=True", node.lineno))
    assert not normalising, (
        f"these evidence reads normalise their subject: {normalising}. A carriage return in an "
        "argument, in stdout or in stderr must reach the assertion as the byte bash wrote - and "
        "the argv recovery splitting on the delimiter is where the laundering lands."
    )


def test_a_candidate_whose_inner_c_payload_is_broken_is_reported_not_silently_accepted(shim_dir):
    """The oracle prechecks the text it is about to trust: a second, independent `bash -n -c`
    over the EXTRACTED INNER text, because the existing outer `bash -n -c "<outer>"` reports
    nothing at all about a nested `-c '<inner>'` payload's syntax. A candidate whose inner
    payload is broken is skipped and reported, never silently accepted into the corpus. The
    helper must also accept a multi-stage candidate rather than raising: `bash -c 'cat x | wc
    -l'` is the shape a model most plausibly writes and is exactly where an argv divergence
    would hide.

    The blindness is re-probed here rather than cited (claim pj3): four broken inner payloads
    nested inside a well-formed outer, each also handed to `bash -n -c` directly as the
    control."""
    bash = shutil.which("bash")
    broken = ("if true; then", "{ echo a", "echo a |", "for i in")
    for inner in broken:
        outer = f"bash -c '{inner}'"
        nested = subprocess.run([bash, "-n", "-c", outer], capture_output=True, timeout=60)
        direct = subprocess.run([bash, "-n", "-c", inner], capture_output=True, timeout=60)
        blind = f"the outer syntax check now reports on the inner payload {inner!r} — the " \
                "premise of the inner precheck has changed"
        assert nested.returncode == 0, blind
        assert not nested.stderr, blind
        assert direct.returncode != 0, f"{inner!r} is not actually broken"
        assert _bash_meaning(shim_dir, outer) is None, (
            f"the oracle admitted {outer!r}, whose inner payload bash refuses to parse. The "
            "outer precheck is structurally blind to it, so the candidate silently becomes a "
            "test of nothing."
        )
    # A multi-stage payload inside quotes is a candidate, not a crash: the helper reports on it.
    # Since #971 nothing unpacks the quotes, so it is ONE stage - `bash` with a long argument -
    # and the pipe inside them is not a pipe. The property under test is unchanged: the helper
    # must REPORT rather than raise, because a raise is a green-looking coverage gap.
    multi = f"bash -c '{_SHIM} a | {_SHIM} b'"
    assert _stages(multi) == [["bash", "-c", f"{_SHIM} a | {_SHIM} b"]], (
        "a quoted payload is one argument; the `|` inside it must not become a stage boundary"
    )
    _parsed(multi)


def test_the_oracle_harness_bounds_its_own_subprocess_calls():
    """The oracle harness bounds its own subprocess calls explicitly, so a candidate that does
    not terminate — or a composed candidate whose child outlives the parent the harness waits on
    — turns a hung suite into a failed test rather than polluting the next candidate's evidence
    file.

    Adding wrapper shapes makes this differential run bash inside bash, which is what brings the
    unbounded wait within reach of a corpus entry."""
    tree = _ast.parse(_THIS_FILE.read_text(encoding="utf-8"))
    unbounded = []
    for node in _ast.walk(tree):
        if (
            isinstance(node, _ast.Call)
            and isinstance(node.func, _ast.Attribute)
            and node.func.attr == "run"
            and isinstance(node.func.value, _ast.Name)
            and node.func.value.id == "subprocess"
        ):
            bound = next((kw for kw in node.keywords if kw.arg == "timeout"), None)
            if bound is None:
                unbounded.append(node.lineno)
            elif isinstance(bound.value, _ast.Constant):
                assert bound.value.value <= 300, (
                    f"line {node.lineno}: a bound of {bound.value.value}s is long enough that a "
                    "hung candidate reads as a hung suite"
                )
    assert not unbounded, (
        f"these subprocess calls carry no timeout: lines {unbounded}. The oracle IS a "
        "subprocess, and an unbounded wait on one is how a corpus addition hangs the suite "
        "instead of failing it."
    )
    assert _sys.version_info >= (3, 10)
