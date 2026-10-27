"""#955 F-50 — the fd prefix is a property of the raw text, not of the previous token."""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from defender.execution import bash_exec
from defender.tests.support.tenancy import _tenants1106 as T1106

_SHIM = "w"
_SHIM_SRC = """#!/bin/sh
for a in "$@"; do printf '%s\\n' "$a" >> "$W_ARGV"; done
printf 'ARGV_END\\n' >> "$W_ARGV"
printf 'OUT\\n'
printf 'ERR\\n' >&2
"""


#: What `_parsed` reports for a candidate that parses to anything other than ONE stage. A
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


# The properties, which need no bash.
@pytest.mark.parametrize("operand", ["2", "20", "1", "0", "9", "x"])
def test_the_verdict_does_not_depend_on_the_value_of_an_operand(operand):
    """The headline property, stated over values rather than over the one value that broke."""
    assert _single(f"head -c {operand} >/dev/null") is None, (
        f"a spaced `>` redirect was accepted after the operand {operand!r} — the fd prefix is "
        "being read off the previous token, so the verdict moves with an argument's value"
    )
    assert _single(f"head -c {operand} >& 1") is None


@pytest.mark.parametrize(("cmd", "argv"), [
    # The spaced spellings, which this executor REFUSES — `>`/`>&` after a bare `2` is a
    # redirect of STDOUT, which is not on this surface. `None` is the whole assertion.
    ("head -c 2 >/dev/null", None),
    ("cat /etc/hosts 2 >/dev/null", None),
    ("tail -n 2 >&1", None),
    ("cut -f 2 >& 1", None),
    ("head -c 2 2>/dev/null", ["head", "-c", "2"]),
    ("cat /etc/hosts 2>/dev/null", ["cat", "/etc/hosts"]),
    ("tail -n 2 2>&1", ["tail", "-n", "2"]),
    ("cut -f 2 2>&1", ["cut", "-f", "2"]),
    ("cut -f 22 2>&1", ["cut", "-f", "22"]),
    ("echo 2 2>/dev/null", ["echo", "2"]),
])
def test_an_accepted_command_never_loses_an_operand(cmd, argv):
    """The second half of the defect"""
    result = _single(cmd)
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
    result = _single(cmd)
    assert result is not None, f"{cmd!r} was refused — the fd redirect itself broke"
    argv, got = result
    assert got == stderr
    assert argv == cmd.split()[:-1], f"{cmd!r} parsed to {argv}"


@pytest.mark.parametrize("cmd", [
    "echo '2' >/dev/null", 'echo "2" >/dev/null', "foo2>/dev/null",
    "echo a\r2>/dev/null", "echo a\xa02>/dev/null",
])
def test_a_quoted_or_suffixed_two_is_not_an_fd(cmd):
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
    """The same defect as F-50, in the other direction"""
    parsed = _single(cmd)
    assert parsed is not None, f"{cmd!r} was refused — a quoted operator is an ordinary word"
    assert parsed[0] == argv, f"{cmd!r} parsed to {parsed[0]}"


@pytest.mark.parametrize(("cmd", "argv"), [
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
    """F-50's own class, on the third fact the raw text has to answer."""
    parsed = _parsed(cmd)
    assert parsed is not None, f"{cmd!r} was refused — a comment is not a lexing failure"
    assert parsed[0] == argv, f"{cmd!r} parsed to {parsed[0]}"


@pytest.mark.parametrize("cmd", [
    "w a|#b",
    "w a&&#b",
    "w >#x",
    "w 2>#x",
    "w a)2>/dev/null",
    "w a(2>/dev/null",
])
def test_incomplete_operators_and_parenthesized_fd_prefixes_fail_closed(cmd):
    assert _parsed(cmd) is None


@pytest.mark.parametrize("cmd", ["w a;2>/dev/null", "w a 2>/dev/null"])
def test_a_real_operator_boundary_still_admits_the_fd(cmd):
    """The control: the refusal above must be about the PAREN, not about narrowing the
    predecessor set until no fd redirect is ever recognised again."""
    assert _parsed(cmd) is not None


#: Characters `str.isspace()` OR `shlex.whitespace` calls whitespace and BASH does not. The
_NOT_SHELL_BLANKS = [
    "\r",
    "\x0b", "\x0c", "\x1c", "\x1f", "\x85", "\xa0", "\u2003", "\u3000",
]


#: The same question as `_NOT_SHELL_BLANKS`, asked so that RECALL cannot answer it.
_ISSPACE_CEILING = 0x3000

_CANDIDATE_BLANKS = sorted(
    {c for c in map(chr, range(_ISSPACE_CEILING + 1)) if c.isspace()}
    | set(shlex.shlex("").whitespace)
)


@pytest.mark.parametrize("blank", _CANDIDATE_BLANKS, ids=lambda c: f"U+{ord(c):04X}")
def test_our_word_boundary_is_bash_s_word_boundary(shim_dir, blank):
    """For every character either library calls whitespace, we split iff bash splits."""
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
    """A character the shell does not split on stays inside its word."""
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


# The same invariant, at the layer that actually decides.
def test_the_gate_does_not_rewrite_the_command_before_it_parses_it(tmp_path):
    """`decide_bash` is the entry point"""
    from defender.investigation.agent_definition import compile_policy_for
    from defender.investigation.permission import decide_bash

    run_dir = tmp_path / "run"
    run_dir.mkdir()
    defender_dir = tmp_path / "defender"
    defender_dir.mkdir()
    target = run_dir / "report.md"
    target.write_text("x", encoding="utf-8")
    policy = compile_policy_for(T1106.fixture_gather_def(), run_dir=run_dir, defender_dir=defender_dir)
    plain = decide_bash(
        f"cat {target}", policy=policy, run_dir=run_dir, defender_dir=defender_dir,
    )
    assert plain.pipelines is not None, "the gate refused the ordinary host-path control"

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


# The differential: for everything we accept, bash says what it MEANS.
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
        yield Path(d), shutil.which("bash")


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


def _bash_meaning(shim: tuple[Path, str], cmd: str):
    """What bash DOES with `cmd`"""
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
    """The direction #897's file does not assert, and the only one that could see F-50."""
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


# #959 — the wrapper seam, the blank alphabet, and the oracle's own evidence channels.


_CR = chr(0x000D)
_NBSP = chr(0x00A0)
_THIS_FILE = Path(__file__).resolve()

#: WRAPPER SHAPES ARE GONE FROM THIS DIFFERENTIAL (#971), and so is the test that consumed


def _stages(cmd: str):
    """Every stage `cmd` parses to, as argv lists — the multi-stage shape `_parsed` refuses."""
    return [list(s.argv) for p in bash_exec.parse(cmd) for s in p.stages]


def _bash_argv_bytes(shim: tuple[Path, str], cmd: str) -> list[str] | None:
    """The argv bash passed the shim, recovered from the evidence file IN BINARY."""
    shim_dir, bash = shim
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


def test_the_scanner_ends_a_word_exactly_where_bash_ends_one(shim_dir):
    """No character ends a word here that does not end one in bash"""
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
    """The differential's alphabet carries blanks derived from both sides of the comparison — `str.isspace()` together with the scanner's own set — so..."""
    ours_side = set(bash_exec._BLANKS)
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
