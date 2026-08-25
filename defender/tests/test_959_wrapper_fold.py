r"""#959 - the wrapper folds into the parser (M3), and what the removal leaves behind.

`hooks/_cmd_segments.unwrap` is the second parser: it flattens the whole command with
`shlex.split` and then decides what the `bash -c` argument was, which is why
`bash -c 'echo a '2>/dev/null` is allowed today as `[['echo','a']]` with stderr on /dev/null
while real bash's `-c` argument is `echo a 2` and the redirect belongs to the outer shell. The
fold replaces that with a match by TOKEN INDEX over the one scanner's records, and the `-c`
argument becomes its own token's resolved value, re-scanned as the inner command, with that
token's SPAN saying where it ends — which is what makes an operator after it visible at all.

The folded step is `_wrapper_span` (F3 renamed the role: it works in SPANS of the original text.
Read that per arm, because the design body said it for the wrong one and this file's own
assertions were what caught it, RC7: the `timeout` prefix's remainder IS the raw slice from the
next token's start offset, while the `-c` argument is a single token that is RESOLVED and
re-scanned. Re-scanning that argument's raw span would parse its quotes as part of the program
name.) If the implementation picks another name, the spec-graph id moves with
it in the same commit - an alias would disable the check for that concept rather than paper
over it.
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
# M3 - the `-c` argument is a span, and the wrapper must be the whole command.
# --------------------------------------------------------------------------- #
def test_the_c_argument_is_the_token_its_span_bounds_not_a_rejoin_of_several():
    r"""The inner command of a `bash -c` wrapper is the `-c` argument's OWN TOKEN, resolved once
    and re-scanned as the inner command - never a re-join of several tokens that have already
    been resolved. Its SPAN is what tells the parser where that token ends, which is how an
    operator sitting after it becomes visible at all; the span is exact regardless of which
    character sits at the boundary, because the offsets come from the matched token's own
    position and not from a character-class test.

    THE DESIGN SAID `line[start:end]` HERE AND IT IS FALSE FOR THIS ARM (RC7). A `-c` argument's
    raw span includes its quotes - which is exactly what `test_scan_returns_one_frozen_record_
    per_token_with_value_span_and_kind` asserts a span is - so re-scanning it yields ONE argv
    word: `bash -c 'cat /run/report.md'` would parse to a program whose name contains a space.
    Every assertion below was already written for the resolved reading, which is what caught it.

    What the raw-slice rule was protecting is NOT reopened, and the next reader must not "fix"
    this back: the concern is re-joining SEVERAL resolved tokens, where the glue between them is
    destroyed and unrecoverable. Resolving ONE token loses nothing - it is exactly what a shell
    hands the program - and the re-join is still forbidden here. The raw slice remains right for
    the other arm, `test_the_timeout_prefix_is_skipped_by_token_index_and_the_rest_is_a_raw_slice`,
    where the remainder is many tokens whose glue must survive."""
    # A rejoin of resolved tokens loses the inner quoting: `"a  b"` would come back as `a b`.
    assert _parsed("bash -c 'echo \"a  b\"'") == [[["echo", "a  b"]]]
    assert _parsed("bash -c 'echo a\\ b'") == [[["echo", "a b"]]]
    # ...and the boundary character does not decide where the slice ends.
    assert _parsed("bash -c 'echo P" + CR + "'") == [[["echo", "P" + CR]]]
    assert _parsed("bash -c 'echo " + NBSP + "P'") == [[["echo", NBSP + "P"]]]


def test_an_operator_outside_the_c_argument_refuses_the_wrapper():
    """When an operator sits outside the `-c` argument - `bash -c 'echo a '2>/dev/null`, where
    bash's own `-c` argument is `echo a 2` and the redirect belongs to the outer shell - the
    wrapper is not the whole command and the parse refuses it, instead of handing the inner
    shell a redirect the outer shell owned.

    Rejected: today's answer, which is ALLOW, with `[['echo','a']]` and stderr on /dev/null
    crossing into the box while real bash runs `echo a 2` with the outer redirect taking
    stdout. This is verdict-change member 3 and it is the fix's own headline case."""
    for cmd in ("bash -c 'echo a '2>/dev/null", f"bash -c 'cat {REPORT} '2>/dev/null"):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} is still allowed with an argv bash does not run"
        assert d.reason == permission.UNTOKENIZABLE_REASON
        assert d.pipelines is None
    # The positive control: the same operator INSIDE the `-c` argument belongs to the inner
    # command and is still accepted, with the stderr routing the text asks for.
    d = _bash(f"bash -c 'cat {REPORT} 2>/dev/null'")
    assert d.allow
    assert [st.stderr for pl in d.pipelines for st in pl.stages] == ["devnull"]


def test_a_bash_c_wrapper_with_anything_after_it_is_refused():
    """A `bash -c` wrapper must be the WHOLE command: `bash -c 'ls'` followed by a second
    physical line is refused, because the `-c` argument does not claim the text after it, and so
    is a stray word after the `-c` string on the same line. The wrapper decision is taken over
    the whole command and cannot live inside the per-line scan - a first-line-only fold reads
    `bash -c 'ls'` as a complete wrapper and silently loses line 2."""
    for cmd in (
        "bash -c 'ls'\ncat /etc/hosts",
        f"bash -c 'cat {REPORT}'\nwc -l",
        f"bash -c 'cat {REPORT}' extra",
        "bash -c 'echo a' bash -c 'echo b'",
    ):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} was allowed - a wrapper that is not the whole command"
        assert d.reason == permission.UNTOKENIZABLE_REASON, f"{cmd!r}"
    # The positive control: the wrapper that IS the whole command still parses to its inner
    # pipelines, so the refusals above are not everything having stopped working.
    assert _argv(f"bash -c 'cat {REPORT} | wc -c'") == [[["cat", REPORT], ["wc", "-c"]]]


def test_a_timeout_prefix_on_the_first_line_leaves_every_later_line_in_the_parse():
    """A `timeout N` prefix does NOT claim the rest of the text: a prefix that uses up its own
    physical line leaves every later line in the parse, so `timeout 5\\ncat P` is still the two
    lines it names. Recognising a prefix does not evaluate whether the remainder is granted - a
    later line no grant admits still denies on the ordinary capability reason.

    This arm and `bash -c`'s answer opposite ways, which is why the one demand sentence that
    carried both was split in two: a prefix does not claim the text after it, a `-c` argument
    does."""
    assert _argv(f"timeout 5\ncat {REPORT}") == [[["cat", REPORT]]]
    d = _bash(f"timeout 5 cat {REPORT}\nls -la")
    assert not d.allow
    assert d.reason == base.MAIN.deny_reason, (
        "a later line no grant admits denies on the CAPABILITY reason - recognising the prefix "
        "is not a judgement about the remainder"
    )


def test_the_timeout_prefix_is_skipped_by_token_index_and_the_rest_is_a_raw_slice():
    """A `timeout N` prefix is skipped by counting tokens, and what is parsed is the raw line
    from the next token's start offset - no string surgery re-derives where the prefix ended.
    The duration token is matched on its RESOLVED value, not its raw span: `'5'`'s raw span
    fails a digit test while its resolved value passes, and F4 requires `timeout '5' cat x` to
    be accepted."""
    assert _parsed(f"timeout 5 cat {REPORT}") == [[["cat", REPORT]]]
    assert _parsed(f"timeout   5   cat {REPORT}") == [[["cat", REPORT]]]
    assert _parsed("timeout 5 echo 'a  b'") == [[["echo", "a  b"]]], (
        "the rest of the line is a RAW slice; a rejoin of resolved tokens loses the inner glue"
    )
    assert _parsed(f"timeout '5' cat {REPORT}") == [[["cat", REPORT]]], (
        "the duration is matched on its resolved value - matching the raw span is what makes a "
        "quoted duration unmatchable, and it is the surgery M1's offsets exist to delete"
    )


def test_a_quoted_timeout_prefix_is_the_timeout_program_bash_would_run():
    r"""A `timeout` prefix whose own words are quoted - `timeout '5' cat x`, `"timeout" 5 cat x`
    - is the same prefix bash would run, so it is skipped like any other, and
    `UNTOKENIZABLE_REASON` cause (5) no longer names it. Composed with a leading or trailing
    divergent blank the outcome is the union of the two accepted changes and nothing new:
    ` timeout '5' cat x` is still refused, because the leading blank corrupts the first token
    and the wrapper is not recognised at all (restated worked example 4).

    Rejected: today's answer, refused as untokenizable, because the prefix is matched against
    the RAW text rather than the token values. This is verdict-change member 4 and the one
    member that moves deny->allow; the `bash`/`sh` arm is already value-matched today, so the
    widening is confined to the `timeout` arm."""
    assert _argv(f"timeout '5' cat {REPORT}") == [[["cat", REPORT]]]
    assert _argv(f'"timeout" 5 cat {REPORT}') == [[["cat", REPORT]]]
    assert "timeout" not in permission.UNTOKENIZABLE_REASON, (
        "cause (5) still names a quoted `timeout` prefix as a refusal, and the parser no "
        "longer refuses it - F4 strikes the clause TOGETHER WITH the test pinning it, or the "
        "only sentence the model is ever shown about this is a sentence about nothing"
    )
    # The composition with member 1: refused, and NOT for the lexing reason any more - the
    # wrapper is not recognised at all, so it is an ordinary ungranted first word.
    for cmd in (NBSP + f"timeout '5' cat {REPORT}", f"timeout '5' cat {REPORT}" + NBSP):
        d = _bash(cmd)
        assert not d.allow
        assert d.reason != permission.UNTOKENIZABLE_REASON, (
            f"{cmd!r}: the quoted prefix is accepted now, so what refuses this command is the "
            "divergent blank - and blaming the quoting sends the model to fix its quotes"
        )
        # ...and saying so means SAYING SO: not-the-lexing-reason is satisfied by the generic
        # capability deny, which names nothing. The character is invisible, so the codepoint is
        # the only thing that can be said about it - the same obligation the whole invisible
        # class carries (RC2), asserted here because this docstring already demanded it.
        assert re.search(rf"U\+0*{ord(NBSP):04x}\b", d.reason, re.IGNORECASE), (
            f"{cmd!r}: the refusal never names U+00A0, so the one thing the model cannot see is "
            "the one thing it is not told"
        )


def test_a_newline_inside_the_c_argument_is_the_unclosed_quote_it_looks_like():
    r"""A `bash -c` argument carrying a newline is refused for the reason every other cross-line
    quote is refused - a quoted string cannot span lines - instead of being flattened into one
    token and re-split into a pipeline per line. The refusal must reach the model as a reason
    that EXPLAINS THE NEWLINE, not as a generic parse failure: a model that sends a multi-line
    `-c` payload today gets an allow, and after this change it needs to know what to fix.

    Rejected: today's answer, allowed, with `bash -c 'cat /run/report.md\nwc -l'` parsing to two
    pipelines. This is verdict-change member 5."""
    d = _bash(f"bash -c 'cat {REPORT}\nwc -l'")
    assert not d.allow, "a multi-line `-c` payload is still flattened into two pipelines"
    assert d.pipelines is None
    assert d.reason != _generic_lexing_reason(), (
        "the refusal is the generic parse failure an unbalanced quote earns. F5's obligation "
        "is that this narrowing explains ITSELF: the model sent a payload that worked "
        "yesterday, and the reason it now reads has to name the newline it must collapse"
    )
    assert re.search(r"newline|line break|one line", d.reason, re.IGNORECASE), (
        "the refusal never names the newline the model has to remove"
    )


def test_a_newline_in_a_c_argument_that_is_also_independently_unbalanced_keeps_the_generic_cause():
    """F5's obligation binds when the newline is WHY the scan failed. Where the `-c` argument
    carries a separately unbalanced quote that fails first, the generic cause (1) wording is the
    correct one and the newline explanation is not owed - a design-introduced narrowing and a
    genuine syntax bug must not be conflated in either direction."""
    d = _bash('bash -c "cat \'a\nb"')
    assert not d.allow
    assert d.reason == _generic_lexing_reason(), (
        "the `-c` argument here carries an unbalanced quote of its own, which fails first; "
        "explaining a newline to a model whose real mistake is an open quote sends it to fix "
        "the wrong thing"
    )


def test_every_wrapper_shape_the_lexing_reason_names_is_still_refused_for_that_reason():
    """Every wrapper shape `UNTOKENIZABLE_REASON` cause (5) still names after F4's strike - a
    bare `bash`, `bash script.sh`, `sh -lc ...`, a stray word after the `-c` string, a second
    complete wrapper following the first - is still refused with the LEXING reason after the
    fold, and the reason's own sentence still matches what the parser does. A bare `timeout`, by
    contrast, still denies on the POLICY reason: that asymmetry is today's, it is not in the
    enumerated set, and a folded implementation that unifies the two arms has made an
    unenumerated verdict change.

    AND THE MATCHER RECOGNISES A WRAPPER BY ITS FIRST TOKEN, so a trailing character the model
    cannot see, landing on a LATER token, may not change which reason answers (RF-E8,
    human-resolved at the third verify loop). `bash -c 'cat P' extra<U+00A0>` is a stray word
    after the `-c` string whether or not that word ends in a no-break space; the shape is still
    recognisably a wrapper, so cause (5) still names it and the model still reads the message
    that says what is actually wrong.

    THIS IS AN OBLIGATION ON THE IMPLEMENTATION, NOT AN OBSERVATION. An M4+M6+M2 simulation
    reports these shapes falling through to the capability deny - but that simulation parses
    WITHOUT the fold, which is the very code the answer depends on, so it cannot settle it. The
    rejected reading was to let them fall through: 182 more shapes into member 8, and the model
    loses the specific message in exactly the way the previous three findings were about. The
    corpus records all seven shapes x 26 characters as verdict-neutral BY DECISION.

    AND THE DECISION HAS A BOUNDARY, WHICH IS THE OTHER END OF THE COMMAND. Prepend the same
    character and the answer inverts: `<U+00A0>bash -c '<cmd>' extra` has a first token no matcher
    recognises as `bash` on any implementation this spec permits - matching is on resolved values
    and exact - so the wrapper is not recognised, the shape is an ordinary ungranted command, and
    it leaves the lexing reason. That is member 8 by OBSERVATION (26/26 executed, and determined
    rather than chosen, because the fold's absence cannot change a token nothing recognises). The
    two ends of one command give opposite answers for the same seven shapes, which is why neither
    end could be swept as a stand-in for the other."""
    for cmd in (
        "bash", "sh", f"bash {REPORT}", "sh -lc 'ls'",
        f"bash -c 'cat {REPORT}' extra", "bash -c 'echo a' bash -c 'echo b'",
        "bash -x -c 'echo hi'", "bash -c'echo hi'",
    ):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} left the lexing reason cause (5) names"
        assert d.reason == permission.UNTOKENIZABLE_REASON, (
            f"{cmd!r} left the lexing reason cause (5) names"
        )
    assert "bash -c" in permission.UNTOKENIZABLE_REASON

    # The first-token rule, over every shape whose last token is not the wrapper word and every
    # character the model cannot see. Swept from the corpus's own table so the two cannot drift.
    for name, shape in base.WRAPPER_LATER_TOKEN_SHAPES:
        for blank in base.DIVERGENT_BLANKS:
            d = _bash(shape + blank)
            assert not d.allow, f"{name} + U+{ord(blank):04X} became an allow"
            assert d.reason == permission.UNTOKENIZABLE_REASON, (
                f"{name} + U+{ord(blank):04X}: the wrapper is recognised by its FIRST token, so "
                "an invisible character on a later one may not move this refusal onto the "
                "capability path - the model would lose the one message that names what is "
                "actually wrong with the command it sent"
            )

    # The boundary: the same character at the OTHER end takes the wrapper word with it, so the
    # first-token rule has nothing to recognise and the refusal leaves this reason.
    for name, shape in base.WRAPPER_LATER_TOKEN_SHAPES:
        for blank in base.DIVERGENT_BLANKS:
            d = _bash(blank + shape)
            assert not d.allow, f"leading U+{ord(blank):04X} + {name} became an allow"
            assert d.reason != permission.UNTOKENIZABLE_REASON, (
                f"leading U+{ord(blank):04X} + {name}: the first token is not `bash` any more, so "
                "there is no wrapper to recognise and no cause (5) to keep - this is the boundary "
                "of the first-token rule, not an instance of it"
            )

    for cmd in ("timeout", "timeout --"):
        d = _bash(cmd)
        assert not d.allow
        assert d.reason == base.MAIN.deny_reason, (
            f"{cmd!r} moved to the lexing reason. The asymmetry is today's - `unwrap('timeout')` "
            "returns the empty string, which parses to zero pipelines and falls through to the "
            "policy reason, where a bare `bash` raises - and reason identity is part of the "
            "verdict"
        )


def test_the_wrapper_step_applies_exactly_once_and_never_to_the_text_it_extracts():
    """Wrapper recognition applies once, at the top level, and never re-runs over the slice it
    just extracted: `timeout 5 timeout 3 cat x` still denies, `bash -c 'timeout 5 cat x'` still
    denies, and a `timeout` appearing as the first word INSIDE a `-c` argument is ordinary text
    to the outer match.

    Rejected: looping to a fixed point, or re-applying recognition to the extracted `-c` slice -
    which turns two of today's denies into allows, a deny->allow widening on a security gate
    that is in nobody's enumerated set and would be reached by accident rather than by
    decision. Nothing in the design says "once", and folding makes recursion the easier thing
    to write by mistake."""
    for cmd in (
        f"timeout 5 timeout 3 cat {REPORT}",
        f"bash -c 'timeout 5 cat {REPORT}'",
        "bash -c 'bash -c \"echo hi\"'",
    ):
        assert not _bash(cmd).allow, f"{cmd!r} became an allow - recognition ran more than once"
    # ...and the extracted text keeps the wrapper word as an ordinary word in the argv.
    assert _parsed(f"bash -c 'timeout 5 cat {REPORT}'") == [[["timeout", "5", "cat", REPORT]]]
    # The positive control: ONE application still happens, on both arms and composed.
    assert _argv(f"timeout 5 cat {REPORT}") == [[["cat", REPORT]]]
    assert _argv(f"bash -c 'cat {REPORT}'") == [[["cat", REPORT]]]
    assert _argv("timeout 5 bash -c 'echo hi'") == [[["echo", "hi"]]]


def test_a_bare_wrapper_word_denies_with_the_reason_class_it_denies_with_today():
    """A bare `bash` or `sh` denies with the LEXING reason (cause (5) names it); a bare `timeout`
    denies with the POLICY reason, because `unwrap('timeout')` returns the empty string, which
    parses to zero pipelines and falls through. Reason identity is part of the verdict, and this
    shape is not in the enumerated set, so neither arm may move."""
    assert _bash("bash").reason == permission.UNTOKENIZABLE_REASON
    assert _bash("sh").reason == permission.UNTOKENIZABLE_REASON
    assert _bash("timeout").reason == base.MAIN.deny_reason
    assert _bash("timeout --").reason == base.MAIN.deny_reason


def test_a_timeout_prefix_that_consumes_no_duration_shaped_token_is_not_a_wrapper():
    """The wrapper step advances past `timeout` only when at least one duration- or flag-shaped
    token is actually consumed, so `timeout cat report.md` is not a recognised wrapper and is
    refused - where today it is allowed and executes `cat report.md`, while the real `timeout`
    would read `cat` as its duration, refuse, and run nothing (`invalid time interval 'cat'`,
    rc 125). `timeout --` and a bare `timeout` reach the same disposition through the same arm.

    Rejected: modelling coreutils' real duration grammar too (the `s`/`m`/`h`/`d` suffix, and
    `-k`/`-s` each taking a value), which would flip `timeout 5s cat x` and
    `timeout -s KILL 5 cat x` deny->allow - a widening on a security gate, each member
    enumerated by hand, and scope beyond this change. And rejected: declining the fix, which
    ships the live bug certified clean by a differential whose corpus contains no `timeout` at
    all."""
    for cmd in (f"timeout cat {REPORT}", "timeout echo hi"):
        d = _bash(cmd)
        assert not d.allow, (
            f"{cmd!r} is authorised as the command with the wrapper word removed - an argv the "
            "real `timeout` would refuse to run at all"
        )
    assert _bash("timeout --").reason == _bash("timeout").reason, (
        "a bare `timeout` and `timeout --` reach the same refusal through the same arm"
    )
    # The positive control: a prefix that DOES consume a duration- or flag-shaped token is
    # still recognised, on both the plain and the quoted spelling.
    assert _argv(f"timeout 5 cat {REPORT}") == [[["cat", REPORT]]]
    assert _argv(f"timeout 0.5 cat {REPORT}") == [[["cat", REPORT]]]
    assert _argv(f"timeout '5' cat {REPORT}") == [[["cat", REPORT]]]
    # ...and the arms this change does NOT take stay where they are: the real grammar is still
    # unmodelled, so these keep denying rather than quietly widening.
    assert not _bash(f"timeout 5s cat {REPORT}").allow
    assert not _bash(f"timeout -s KILL 5 cat {REPORT}").allow


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
    """The production dependent survives the removal: the gate no longer applies a wrapper step
    before parsing - it hands the raw command straight to the parse - so a shape that used to be
    unwrapped once cannot survive as a silently different command, and `unwrap`'s
    non-idempotence stops being reachable through the gate at all."""
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
    # ...and the non-idempotence is unreachable: one application, so the second prefix stays.
    assert not _bash(f"timeout 5 timeout 3 cat {REPORT}").allow
    assert _argv(f"timeout 5 cat {REPORT}") == [[["cat", REPORT]]]


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
    reads argv - whether the stage came from a bare command or from a wrapper's extracted text.
    The deliberate fall-through `test_540_exec_seam.py` pins is not what this change touches, and
    a token-record refactor must not quietly change the token stream that pin asserts on."""
    assert _parsed("cat <(id)") == [[["cat", "<(", "id", ")"]]]
    assert _parsed("bash -c 'cat <(id)'") == [[["cat", "<(", "id", ")"]]]
    for cmd in ("cat <(id)", "bash -c 'cat <(id)'"):
        d = _bash(cmd)
        why = (f"{cmd!r}: the parens reach argv as ordinary words and the argv-reading guard "
               "is what refuses them - a capability refusal, not a lexing one")
        assert not d.allow, why
        assert d.reason == base.MAIN.deny_reason, why
