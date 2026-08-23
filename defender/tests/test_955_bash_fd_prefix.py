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
    result = _parsed(cmd)
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
    result = _parsed(cmd)
    assert result is not None, f"{cmd!r} was refused — the fd redirect itself broke"
    argv, got = result
    assert got == stderr
    assert argv == cmd.split()[:-1], f"{cmd!r} parsed to {argv}"


@pytest.mark.parametrize("cmd", ["echo '2' >/dev/null", 'echo "2" >/dev/null', "foo2>/dev/null"])
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


def _bash_meaning(shim_dir: Path, cmd: str):
    """What bash DOES with `cmd`: the argv it passed the shim, and where the shim's stderr
    marker landed. `None` if bash itself refuses the text."""
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
    if subprocess.run([bash, "-n", "-c", cmd], capture_output=True).returncode != 0:
        return None
    proc = subprocess.run(
        [bash, "-c", cmd], capture_output=True, text=True, env=env, cwd=shim_dir,
    )
    raw = argv_file.read_text(encoding="utf-8") if argv_file.exists() else ""
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
