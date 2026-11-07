"""#959 — downstream of the bash decision: the box handoff, the operand set's consumers, the audit
row, refusal reasons and the operator's view.

#959 - one scanner: the token record stream, the unquoter, the blanks and the `\r`.

#971 — no word is a wrapper: `bash -c` and `timeout` reach the gate as ordinary ungranted words.
A fold would delete text ahead of the decision, so a mis-read could only widen what is allowed.
"""
from __future__ import annotations

import copy
import dataclasses
import io
import json
import re
from contextlib import redirect_stdout
from pathlib import Path

import pytest

pytest.importorskip('pydantic_ai')
from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared.contracts._spec1077 import fixture_run
from defender.tests.support.runtime.state._1255_view import model_path
from defender.investigation import permission  # noqa: E402
from defender.investigation.agent_definition import bind  # noqa: E402
from defender.execution.box_codec import BoxResult  # noqa: E402
from defender.investigation.tools import _tool_bash  # noqa: E402
from defender.cli import policy_cli  # noqa: E402
from defender.knowledge import _query_rules  # noqa: E402
from defender.investigation import record_query  # noqa: E402
from defender.tests.support.sandbox import _baseline_959 as base
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.execution import bash_exec  # noqa: E402
from defender.investigation.permission import bash as pbash  # noqa: E402
from defender.investigation.permission import command_shape  # noqa: E402


CR = base.CR


NBSP = base.NBSP


REPORT = base.REPORT


_bash = base.decide_bash


class Box:
    """The execution seam, faked at the value the run is handed."""

    def __init__(self, result: BoxResult):
        self.result = result
        self.calls: list[dict] = []

    def run_parsed(self, pipelines, *, command, cwd, timeout):
        self.calls.append({
            "pipelines": pipelines,
            "snapshot": copy.deepcopy(pipelines),
            "command": command,
            "cwd": cwd,
            "timeout": timeout,
        })
        return self.result


def _gather_scene(tmp_path: Path, result: BoxResult):
    """A real gather deps (lead `l-1`) over a real run dir, with the box seam handed a fake."""
    lead_id = "l-1"
    run = tmp_path / fixture_uuid("run")
    dfn = tmp_path / "tree" / "defender"
    (run / "gather_raw" / lead_id).mkdir(parents=True)
    dfn.mkdir(parents=True)
    payload = run / "gather_raw" / lead_id / "0.json"
    payload.write_text("{}", encoding="utf-8")
    # This folder went through no driver, so the run state is started here (#1235): the
    # shim-failure row's seq and `system=` attribution are read from it.
    from defender.investigation.run_state import RunState

    box = Box(result)
    deps = dataclasses.replace(
        bind(T1106.fixture_gather_def(), run, defender_dir=dfn, box=box),
        run=fixture_run(run), lead_id=lead_id, run_state=RunState(run, "r959-downstream"),
    )
    return deps, box, payload


# The operand set the four post-decision consumers read.
def test_the_operand_set_the_four_post_decision_consumers_read_is_the_one_the_gate_authorised(
    tmp_path,
):
    """Refusal, untrusted frame, output ceiling and overflow hint all read the operand set the gate authorised."""
    deps, _box, payload = _gather_scene(tmp_path, BoxResult(0, b"x" * 20000, b""))

    opened = _tool_bash(deps, f"cat {model_path(payload, run_dir=deps.run_dir)}")
    assert "untrusted" in opened, "the payload operand did not reach the frame decision"
    # The hint names the operand as the model handed it (its model path), not the host path.
    assert model_path(payload, run_dir=deps.run_dir) in opened, "the overflow hint names a file the operand set did not carry"
    assert len(opened) < 12000, "the payload operand's capture ceiling was not applied"

    # ...and a command that opens nothing takes the other branch of all four: no frame, the
    # authored ceiling, and the hint that has no path to name.
    deps2 = dataclasses.replace(deps, box=Box(BoxResult(0, b"y" * 20000, b"")))
    opened_nothing = _tool_bash(deps2, "echo hi")
    assert "untrusted" not in opened_nothing
    assert len(opened_nothing) > 12000, "the capture ceiling was applied to a command with no operand"

    deps3 = dataclasses.replace(deps, box=Box(BoxResult(0, b"z", b"")))
    with pytest.raises(ModelRetry) as refusal:
        _tool_bash(deps3, f"cat {model_path(payload, run_dir=deps.run_dir)}" + NBSP)
    assert "untrusted" not in str(refusal.value)


def test_the_audit_rows_system_attribution_derives_from_the_authorised_operand_set(tmp_path):
    deps, _box, payload = _gather_scene(tmp_path, BoxResult(1, b"", b"boom"))
    run = deps.run_dir
    record_query.append_query_row(
        deps.run_state, run=fixture_run(deps.run_state.run_dir), lead_id="l-1", system="elastic", verb="query", query_id="elastic.q", params={},
        raw_command="seed", payload_text="{}", exit_code=0, payload_status="ok",
        payload_digest="d", system_key="",
    )
    _tool_bash(deps, f"cat {model_path(payload, run_dir=deps.run_dir)} | defender-sql 'SELECT 1'")
    rows = [json.loads(line) for line in (run / "executed_queries.jsonl").read_text().splitlines()]
    shim = [r for r in rows if r["query_id"] == _query_rules.BASH_SHIM_QUERY_ID]
    assert len(shim) == 1, "the shim-failure row never reached the queries table"
    assert shim[0]["system"] == "elastic", (
        "the row is not attributed to the system of the authorised payload operand"
    )
    assert shim[0]["system"] == record_query.system_for_payload_operands(deps.run_state, [payload])

    # ...and a reduce that opened no run payload attributes to nothing rather than guessing.
    deps2 = dataclasses.replace(deps, box=Box(BoxResult(1, b"", b"boom")))
    _tool_bash(deps2, "echo hi | defender-sql 'SELECT 1'")
    rows2 = [json.loads(line) for line in (run / "executed_queries.jsonl").read_text().splitlines()]
    assert rows2[-1]["system"] == ""


# The object that crosses into the box.
def test_the_object_the_gate_authorised_is_the_object_the_box_runs(tmp_path):
    deps, box, payload = _gather_scene(tmp_path, BoxResult(0, b"ok", b""))
    m_payload = model_path(payload, run_dir=deps.run_dir)
    cmd = f"cat {m_payload}"
    _tool_bash(deps, cmd)
    assert len(box.calls) == 1
    sent = box.calls[0]
    # The decomposition the box receives, stated literally in the model view.
    assert [[list(st.argv) for st in pl.stages] for pl in sent["pipelines"]] == \
        [[["cat", m_payload]]], "the box ran something other than what the gate authorised"
    assert sent["command"] == cmd

    # ...and an argv entry carrying the character the scanner no longer splits on crosses as
    # the one operand the text names.
    deps2 = dataclasses.replace(deps, box=Box(BoxResult(0, b"ok", b"")))
    _tool_bash(deps2, "echo a" + CR + "b")
    crossed = deps2.box.calls[0]["pipelines"]
    assert [list(st.argv) for pl in crossed for st in pl.stages] == [["echo", "a" + CR + "b"]], (
        "the operand that crossed into the box is not the one the gate authorised"
    )


def test_nothing_mutates_the_authorised_pipelines_between_authorisation_and_execution(tmp_path):
    deps, box, payload = _gather_scene(tmp_path, BoxResult(1, b"", b"boom"))
    m_payload = model_path(payload, run_dir=deps.run_dir)
    _tool_bash(deps, f"cat {m_payload} | defender-sql 'SELECT 1'")
    sent = box.calls[0]
    live = [[list(st.argv) for st in pl.stages] for pl in sent["pipelines"]]
    at_receipt = [[list(st.argv) for st in pl.stages] for pl in sent["snapshot"]]
    assert live == at_receipt, "the authorised pipelines were mutated after they crossed into the box"
    # ...and what crossed is still the command's own decomposition, in the model view.
    assert live == [[["cat", m_payload], ["defender-sql", "SELECT 1"]]], live


# What the model is told, and what the operator can see.
def _names_codepoint(reason: str, char: str) -> bool:
    """Does `reason` name `char` the only way a reason can name a character nobody can see -
    by its codepoint? `U+00A0`, any case, leading zeros optional."""
    return re.search(rf"U\+0*{ord(char):04x}\b", reason, re.IGNORECASE) is not None


def test_a_command_refused_only_for_an_invisible_character_is_told_so():
    """The refusal names the invisible character by codepoint; refusals it did not move keep their reason."""
    for blank in base.DIVERGENT_BLANKS:
        for position, cmd in (
            ("trailing, in an operand", f"cat {REPORT}" + blank),
            ("leading, in the program name", blank + f"cat {REPORT}"),
            ("after a separator", f"cat {REPORT} |" + blank),
        ):
            d = _bash(cmd)
            assert not d.allow, (
                f"U+{ord(blank):04X} {position} still authorises a command the text does not name"
            )
            assert d.reason != base.MAIN.deny_reason, (
                f"a command refused only for U+{ord(blank):04X} ({position}) got the generic "
                "capability deny"
            )
            assert _names_codepoint(d.reason, blank), (
                f"the refusal of {cmd!r} never names U+{ord(blank):04X}"
            )
    for cmd in (f"cat {REPORT}" + CR + "x", f"cat {REPORT}" + CR + "\nwc -l",
                f"cat {REPORT} |" + CR, f"cat {REPORT} &&" + CR):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} is still authorised as a command the text does not name"
        assert _names_codepoint(d.reason, CR), f"{cmd!r}: the refusal never names U+000D"
    for arm, shape, moves_trailing, moves_leading in base.LEXING_ARMS:
        for label, build, moves in (
            ("trailing", lambda b, sh=shape: sh + b, moves_trailing),
            ("leading", lambda b, sh=shape: b + sh, moves_leading),
        ):
            for blank in base.DIVERGENT_BLANKS:
                d = _bash(build(blank))
                if not moves:
                    # The control: where the character did not move the refusal, the specific
                    # message stays, which is what scopes this obligation to what actually moved.
                    assert d.reason == permission.UNTOKENIZABLE_REASON, (
                        f"{arm} ({label} U+{ord(blank):04X}): an unmoved refusal left its own arm"
                    )
                    continue
                assert not d.allow, f"{arm} ({label} U+{ord(blank):04X}) became an allow"
                assert _names_codepoint(d.reason, blank), (
                    f"{arm} ({label} U+{ord(blank):04X}): the refusal moved off its arm but does "
                    "not name the character"
                )
    for name, shape in base.WRAPPER_LATER_TOKEN_SHAPES:
        for blank in base.DIVERGENT_BLANKS:
            d = _bash(blank + shape)
            assert not d.allow, f"leading U+{ord(blank):04X} + {name} became an allow"
            assert not _names_codepoint(d.reason, blank), (
                f"leading U+{ord(blank):04X} + {name}: names a codepoint, though {shape!r} is "
                "refused without it"
            )
            assert _bash(shape).reason == d.reason, f"{name}: the leading blank changed the message"

    # The controls. An ordinary capability refusal keeps the plain reason...
    assert _bash("ls -la").reason == base.MAIN.deny_reason
    assert not _names_codepoint(_bash("ls -la").reason, CR)
    # ...and a command already refused for the same operand before this change does not move.
    assert _bash(f"cat '{REPORT}" + CR + "'").reason == base.MAIN.deny_reason


def test_the_serialised_verdict_an_operator_reads_carries_the_argv_half(capsys):
    cmd = f"cat {REPORT} | wc -c"
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = policy_cli.main(
            ["explain", "main", cmd, "--json", "--run-dir", "/run", "--defender-dir", "/dfn"],
        )
    assert rc == 0
    out = json.loads(buf.getvalue())
    assert out["allow"] is True
    assert out["grant"] == ["cat", "wc"]
    assert "pipelines" in out, "`policy_cli explain --json` does not serialise the pipelines"
    assert out["pipelines"] == [[["cat", REPORT], ["wc", "-c"]]], (
        "the serialised pipelines are not the argv the gate authorised"
    )
    # The refused side carries the same shape rather than dropping the field.
    buf = io.StringIO()
    with redirect_stdout(buf):
        policy_cli.main(
            ["explain", "main", "ls -la", "--json", "--run-dir", "/run", "--defender-dir", "/dfn"],
        )
    refused = json.loads(buf.getvalue())
    assert refused["allow"] is False
    assert "pipelines" in refused


_parsed = base.parsed_argv


def _argv(cmd: str):
    """The pipelines the gate authorised, as nested argv - `None` when it refused."""
    d = _bash(cmd)
    if d.pipelines is None:
        return None
    return [[list(st.argv) for st in pl.stages] for pl in d.pipelines]


def test_a_quote_that_never_closes_still_ends_the_scan_with_no_tokens():
    """An unclosed quote scans to nothing and is refused with the lexing reason, also inside a `-c` argument."""
    assert bash_exec._scan("cat 'x") is None
    with pytest.raises(bash_exec.UntokenizableCommand):
        bash_exec.parse("cat 'x")
    for cmd in (f"cat {REPORT} | grep 'unterminated", f"bash -c 'cat {REPORT}"):
        d = _bash(cmd)
        assert not d.allow
        assert d.pipelines is None
        assert d.reason == permission.UNTOKENIZABLE_REASON, f"{cmd!r} lost the lexing reason"


def test_a_blank_command_is_answered_ahead_of_the_parse_not_by_its_result():
    """A blank command allows; an empty parse would deny (`_decide_readers([])` is `None`), so the allow comes first."""
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
    d = _bash(cmd)
    assert d.allow, f"{cmd!r} stopped being the allowed no-op"
    assert d.pipelines is None


@pytest.mark.parametrize("blank", [base.NBSP, base.VT, base.FF, base.LSEP],
                         ids=["nbsp", "vt", "ff", "u2028"])
def test_a_command_of_only_unicode_blanks_is_a_word_bash_would_try_to_run(blank):
    d = _bash(blank)
    assert not d.allow, f"U+{ord(blank):04X} alone was answered as a blank command; bash runs it as a word"


def test_a_no_break_space_at_either_end_is_part_of_the_word_it_touches():
    """A blank at either end belongs to its word, as in bash, so the trimmed command is never what is authorised."""
    for blank in (NBSP, base.VT, base.FF):
        assert not _bash(blank + "cat " + REPORT).allow
        assert not _bash("cat " + REPORT + blank).allow
    # Glued to a wrapper word, the blank makes the first token not `timeout`/`bash` at all.
    assert not _bash("timeout" + NBSP + "5 cat " + REPORT).allow
    assert not _bash("bash" + NBSP + "-c 'ls'").allow
    # The allow-side half, which a check reading only allow/deny cannot see: where the grant
    # shape ends in a bare VALUE the command stays allowed - with the blank in the argv.
    assert _argv("echo hi" + NBSP) == [[["echo", "hi" + NBSP]]]


def test_a_divergent_blank_inside_a_quoted_argument_is_part_of_that_argument():
    """A quoted argument is one token, blanks included; `bash -c '<U+00A0>cat x'` is refused only as ungranted `bash`."""
    inner = NBSP + "cat " + REPORT
    assert _parsed("bash -c '" + inner + "'") == [[["bash", "-c", inner]]], (
        "the quoted argument is one token and keeps its blank; nothing re-scans its contents"
    )
    for cmd in ("bash -c '" + inner + "'", "bash -c '" + NBSP + "'"):
        d = _bash(cmd)
        assert not d.allow
        assert d.reason == base.MAIN.deny_reason, cmd


# The carriage return, and the two layers that must agree about it.
def test_the_boundary_decision_and_the_value_resolution_agree_about_the_removed_separator():
    """Scanner and unquoter agree on a CR mid-word, at an edge or alone: the unquoter has no blank set of its own."""
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


# One module decides, and it still decides.
def test_the_unquoter_has_no_notion_of_whitespace():
    """`_word_value` only resolves quoting: an unquoter built on `shlex.split` would split on the CR."""
    assert bash_exec._word_value("A" + CR + "B") == "A" + CR + "B"


def test_the_unquoter_resolves_every_quoting_form_the_lexer_resolved():
    """The hand-rolled unquoter matches the POSIX lexer on every quoting form the grammar admits."""
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
    """The lexing reason still names causes (3) and (4) where they fire; a blank after a connector moves the refusal off them."""
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
            f"{cmd!r} still gets the line-boundary reason; the blank after the connector is a word"
        )


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
