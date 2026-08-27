r"""#959 - the wrapper folded into the parser (M3); #971 - and then out of it entirely.

`hooks/_cmd_segments.unwrap` was a second parser: it flattened the whole command with
`shlex.split` and then decided what the `bash -c` argument had been, which is why
`bash -c 'echo a '2>/dev/null` was allowed as `[['echo','a']]` with stderr on /dev/null while
real bash's `-c` argument is `echo a 2` and the redirect belongs to the outer shell. #959
replaced it with a match by TOKEN INDEX over the one scanner's records.

#971 DELETES THE STEP. Both arms - the `timeout N` prefix and the `bash -c` payload - are gone,
for one reason that does not depend on which words are folded: A FOLD DELETES TEXT AHEAD OF THE
DECISION, so the command the gate judges can differ from the command the model wrote, and every
way of mis-reading the shape is a way of WIDENING what the gate allows. A pass-through has no
such direction of failure - the worst a mis-read can do is refuse. The prefix arm went with two
demonstrated deny->allow holes behind it; the `-c` arm was faithful (bash really does run the
payload) and went anyway, because faithful-today was a property of four conditions that kept
needing repair rather than of the design.

So what this file pins is an ABSENCE, plus the things that were true underneath the step and
outlived it: a quoted argument is one token and keeps its own contents, a newline inside one is
an unclosed quote, and parens still reach argv as ordinary words. `bash`, `sh` and `timeout` are
ungranted programs, and the lane's capability reason is what answers them.
"""
from __future__ import annotations

import ast
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import bash_exec  # noqa: E402
from defender.runtime import permission  # noqa: E402
from defender.tests import _baseline_959 as base  # noqa: E402

CR = base.CR
NBSP = base.NBSP
REPORT = base.REPORT
DEFENDER = Path(__file__).resolve().parents[1]
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


# --------------------------------------------------------------------------- #
# #971 - no word is a wrapper, and what that leaves the parser doing.
# --------------------------------------------------------------------------- #
def test_no_word_is_parsed_as_a_wrapper():
    r"""#971: neither `bash` nor `sh` is recognised, so no text is extracted from a command
    before the gate decides about it. They are ungranted programs and the lane's capability
    reason - which names the programs the lane does have - answers every shape they appear in.

    WHY THE `-c` FOLD WENT, given that it was FAITHFUL where the `timeout` prefix fold was not.
    Bash really does run a `-c` payload, so extracting it was not wrong the way deleting a
    prefix was. What it was, was the last remaining way for the command the GATE JUDGED to
    differ from the command the MODEL WROTE - and that difference is the thing every finding on
    this surface has been about. It was held closed by four conditions (the wrapper must be the
    whole command, the payload exactly one argument, the extracted text never re-folded, and
    nothing at all may follow the closing quote), three of which had already needed a repair.
    Deleting the arm deletes the conditions with it: a pass-through has nothing to get wrong.

    The shapes below are the ones #959's own enumerated set spent members 3 and 5 on, plus every
    spelling its `UNTOKENIZABLE_REASON` cause (5) used to list. They all answer the same message
    now, and it is the message that tells the model what to do instead."""
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
    # The reason itself must stop describing a step the parser does not take: a model told its
    # wrapper "did not fold to a single command string" would go on trying to spell one.
    for word in ("bash -c", "wrapper", "-lc"):
        assert word not in permission.UNTOKENIZABLE_REASON.replace(
            "`bash -c '<cmd>'` is refused as an ungranted program", ""
        ), f"the lexing reason still describes a wrapper step ({word!r})"


def test_a_newline_inside_a_quoted_argument_is_the_unclosed_quote_it_looks_like():
    r"""A quoted argument carrying a newline is refused for the reason every cross-line quote is
    refused - a quoted string cannot span lines - and the refusal has to EXPLAIN that, because a
    model that pretty-printed a SQL or JSON argument needs to know what to fix.

    This is what is left of member 5 (#959 F5), and it needed a message of its own back when a
    `-c` payload was extracted before the lines were split. It does not any more: `parse` splits
    physical lines FIRST, so the quote is simply never closed on its own line and cause (1) -
    the general rule - is both the true answer and the useful one."""
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
    r"""#971: `timeout` is an ORDINARY UNGRANTED WORD. The parse leaves it in the argv, no
    grant matches it, and the lane's capability reason answers - the same answer any other
    unavailable program gets, on the same turn, with no text rewritten before the decision.

    Why the prefix fold went, rather than being repaired again: it deleted text AHEAD OF the
    decision, so every way of mis-reading a prefix was a way of WIDENING what the gate allows.
    `timeout\n5 cat P` (the prefix straddling a line boundary) and `timeout --foreground cat P`
    (a prefix carrying no duration at all) each folded to `cat P` and reached an ALLOW for a
    command real `timeout` never runs. Pass-through has no such direction of failure: the worst
    a mis-read can do is refuse.

    And the fold bought nothing real. The stripped prefix was DISCARDED, never executed - there
    is no `timeout` binary in the box - so a bound the model asked for was silently dropped and
    the command ran under the runtime's own deadline instead. Honouring it would have meant
    granting a word that turns the rest of the argv into a new program, which is the one shape
    a per-stage grant ladder must never be permissive about."""
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


def test_a_blank_glued_to_an_ungranted_word_is_not_blamed_for_the_refusal():
    """The composition #971 retires: `<NBSP>timeout '5' cat P` was refused BECAUSE of the blank
    while the same text without it was allowed, so the blank had to be named (RC2). It is not
    refused for the blank any more - `timeout` is ungranted either way - and the invisible-
    character machinery must stay quiet about it rather than blame a character that changes
    nothing. Naming it would send the model hunting for a stray codepoint in a command whose
    real problem is the program it names."""
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



# --------------------------------------------------------------------------- #
# C3 / C4 - what the removal leaves behind.
# --------------------------------------------------------------------------- #
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


def test_the_gate_hands_the_raw_command_straight_to_the_parse():
    """The production dependent survives the removal: the gate applies NO wrapper step before
    parsing - it hands the raw command straight through - so no shape can reach the box as a
    silently different command, and `unwrap`'s non-idempotence is unreachable because there is
    no unwrapping left anywhere on the path."""
    gate = (DEFENDER / "runtime" / "permission" / "bash.py").read_text(encoding="utf-8")
    imported = {
        alias.name
        for node in ast.walk(ast.parse(gate)) if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if (node.module or "").endswith("_cmd_segments")
    }
    assert "unwrap" not in imported, (
        "the gate still imports the standalone wrapper step, so there are still two parsers on "
        "the path and the fold has not happened"
    )
    # ...and the raw text is what reaches the parse: a wrapper word is a word.
    assert _parsed(f"bash -c 'cat {REPORT}'") == [[["bash", "-c", f"cat {REPORT}"]]]
    assert _argv(f"bash -c 'cat {REPORT}'") is None, "a refused command hands the box nothing"


def test_no_call_site_pairs_a_wrapper_step_with_the_parse():
    """The test dependents survive it too: no call site in the tree pairs a wrapper step with
    the parse any more. The three real pairings are `test_permission.py:801-802`,
    `test_grant_gate_575.py:1070/1078` and `test_bash_exec.py:15/29` - three, not the four the
    design lists - and `test_bash_exec.py:28` carries its own `cmd.strip()` ahead of the unwrap,
    a fifth trim that a migration following the doc's list literally would leave standing. The
    fourth site the doc names, `e2e/test_540_box_boundary.py:362`, is an in-box IMPORT probe and
    is not a call site at all; it breaks differently, silently, inside a box."""
    hits = _identifier_hits("unwrap", skip={"test_959_wrapper_fold.py"})
    assert not hits, (
        f"the standalone wrapper step still has call sites: {hits}. Every one of them pairs a "
        "second parser with the real one, which is the defect this change removes."
    )
    bash_exec_test = (TESTS / "test_bash_exec.py").read_text(encoding="utf-8")
    assert "cmd.strip()" not in bash_exec_test, (
        "the fifth trim is still standing in `test_bash_exec.py` - it is not on the design's "
        "list of sites to migrate, which is exactly how it would survive the migration"
    )


def test_bash_exec_still_imports_only_the_standard_library():
    """`bash_exec` imports nothing from this tree at module scope: the wrapper's code is
    ABSORBED, not imported, so the module still loads inside the box with only its own file on
    the path and the mount constraint #958 retired stays retired. This is a prevention demand,
    not a diagnosis one - no diagnostic shape is asserted for the failure, because the in-box
    import census cannot exist before the code does.

    The one live pin for this property today is `live`-marked and therefore excluded by the CI
    marker expression, so CI alone would not catch a violation. This puts the same question to
    the real interpreter, hermetically: copy the module out on its own and import it."""
    source = DEFENDER / "runtime" / "bash_exec.py"
    tree = ast.parse(source.read_text(encoding="utf-8"))
    local = []
    for node in tree.body:  # MODULE SCOPE only - the lazy in-function imports are deliberate
        if isinstance(node, ast.Import):
            local += [a.name for a in node.names if a.name.startswith("defender")]
        elif isinstance(node, ast.ImportFrom) and (node.module or "").startswith("defender"):
            local.append(node.module)
    assert not local, f"`bash_exec` imports {local} at module scope; the box mounts one file"

    with tempfile.TemporaryDirectory() as tmp:
        shutil.copy(source, Path(tmp) / "bash_exec.py")
        proc = subprocess.run(
            [sys.executable, "-c", "import bash_exec; bash_exec.parse('echo hi')"],
            cwd=tmp, capture_output=True, text=True, timeout=60,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": ""},
        )
    assert proc.returncode == 0, (
        "the module does not import with only its own file on the path - which is exactly the "
        f"condition inside the box:\n{proc.stderr[-800:]}"
    )


def test_the_shim_name_constants_survive_the_move():
    """`NON_ADAPTER_SHIMS`, `OPERATOR_TOOLS` and `ADAPTER_RE` are still importable from
    `defender.hooks._cmd_segments`, because the four production modules and the test files that
    read them are not part of this change. The three private helpers that go
    (`_skip_timeout_prefix`, `_unwrap_bash_c`, `_strip_prefix_from_raw`) have zero references
    outside their own module, so removing them leaves no stale reference behind."""
    from defender.hooks import _cmd_segments as seg

    assert "defender-invlang" in seg.NON_ADAPTER_SHIMS
    assert "defender-policy" in seg.OPERATOR_TOOLS
    assert seg.ADAPTER_RE.search("scripts/adapters/elastic_adapter.py")
    for gone in ("_skip_timeout_prefix", "_unwrap_bash_c", "_strip_prefix_from_raw", "unwrap"):
        assert not hasattr(seg, gone), (
            f"`{gone}` is still in the shim module - the wrapper's code moves into the parser, "
            "it is not left behind as a second answer to the same question"
        )
    # The consumers still read what stayed: the shim grants still decide as they did.
    assert _bash("defender-invlang enum types").allow


def test_the_paren_fall_through_still_fails_closed_a_layer_up():
    """`(` and `)` still break a word without being operators the grammar accepts, so
    `cat <(id)` still reaches argv as ordinary words and is still refused by the guard that
    reads argv. The deliberate fall-through `test_540_exec_seam.py` pins is not what this change
    touches, and a token-record refactor must not quietly change the token stream that pin
    asserts on.

    Inside quotes the parens are not even words of their own any more - there is no payload to
    re-scan (#971) - so the wrapper spelling is refused one layer earlier, as an ungranted
    program. Both still refuse, which is the property; only the layer moved."""
    assert _parsed("cat <(id)") == [[["cat", "<(", "id", ")"]]]
    assert _parsed("bash -c 'cat <(id)'") == [[["bash", "-c", "cat <(id)"]]]
    for cmd in ("cat <(id)", "bash -c 'cat <(id)'"):
        d = _bash(cmd)
        why = (f"{cmd!r}: the parens reach argv as ordinary words and the argv-reading guard "
               "is what refuses them - a capability refusal, not a lexing one")
        assert not d.allow, why
        assert d.reason == base.MAIN.deny_reason, why
