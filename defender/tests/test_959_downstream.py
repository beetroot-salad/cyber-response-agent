"""#959 - everything downstream of the decision"""
from __future__ import annotations

from dataclasses import replace as _with_live_run_1165
from defender.tests._spec1077 import fixture_run as _live_run_1165

from defender.tests._spec1077 import fixture_run

import copy
import dataclasses
import io
import json
import re
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from defender.tests._1255_view import model_path

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.box_codec import BoxResult  # noqa: E402
from defender.runtime.tools import _tool_bash  # noqa: E402
from defender.scripts import policy_cli  # noqa: E402
from defender import _query_rules  # noqa: E402
from defender.scripts.gather_tools import record_query  # noqa: E402
from defender.tests import _baseline_959 as base  # noqa: E402
from defender.tests import _tenants1106 as T1106  # noqa: E402

CR = base.CR
NBSP = base.NBSP
REPORT = base.REPORT
DEFENDER = Path(__file__).resolve().parents[1]


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


def _bash(cmd: str, policy=None):
    return permission.decide_bash(
        cmd, policy=policy or base.MAIN, run_dir=base.RUN, defender_dir=base.DFN,
    )


def _argv_of(decision):
    if decision.pipelines is None:
        return None
    return [[list(st.argv) for st in pl.stages] for pl in decision.pipelines]


def _gather_scene(tmp_path: Path, result: BoxResult, *, lead_id: str = "l-1"):
    """A real gather deps over a real run dir, with the box seam handed a fake."""
    run = tmp_path / "run"
    dfn = tmp_path / "tree" / "defender"
    (run / "gather_raw" / lead_id).mkdir(parents=True)
    dfn.mkdir(parents=True)
    payload = run / "gather_raw" / lead_id / "0.json"
    payload.write_text("{}", encoding="utf-8")
    from defender.runtime.run_state import RunState

    box = Box(result)
    deps = dataclasses.replace(
        _with_live_run_1165(bind(T1106.fixture_gather_def(), run, defender_dir=dfn, box=box), run=_live_run_1165(run)), lead_id=lead_id,
        run_state=RunState(run, "r959-downstream"),
    )
    return deps, box, payload


# FK8 - the operand set the four post-decision consumers read.
def test_the_operand_set_the_four_post_decision_consumers_read_is_the_one_the_gate_authorised(
    tmp_path,
):
    """The operand set is walked once from the authorised decision and threaded, and every consumer downstream of the decision sees THAT set"""
    deps, _box, payload = _gather_scene(tmp_path, BoxResult(0, b"x" * 20000, b""))

    opened = _tool_bash(deps, f"cat {model_path(payload, run_dir=deps.run_dir)}")
    assert "untrusted" in opened, "the payload operand did not reach the frame decision"
    # #1255 C5: the hint names the operand as the model handed it (its model path), never the
    # host path this used to assert.
    assert model_path(payload, run_dir=deps.run_dir) in opened, "the overflow hint names a file the operand set did not carry"
    assert len(opened) < 12000, (
        "the capture ceiling the payload operand chose was not applied - the ceiling is a "
        "property of the DATA the command opened, read off the same operand set"
    )

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
        "the row's attribution is not the system of the payload the AUTHORISED operand set "
        "named - a row that disagrees with the execution about which file was opened sends the "
        "curator at the wrong system"
    )
    assert shim[0]["system"] == record_query.system_for_payload_operands(deps.run_state, [payload])

    # ...and a reduce that opened no run payload attributes to nothing rather than guessing.
    deps2 = dataclasses.replace(deps, box=Box(BoxResult(1, b"", b"boom")))
    _tool_bash(deps2, "echo hi | defender-sql 'SELECT 1'")
    rows2 = [json.loads(line) for line in (run / "executed_queries.jsonl").read_text().splitlines()]
    assert rows2[-1]["system"] == ""


_PARITY = (
    ("/run/report.md", True),
    ("/dfn/lessons/a.md", True),
    ("/etc/hosts", False),                       # outside every root: confine
    ("/run/.env", False),                        # denylist
    ("/run/gather_raw/l-1/0.json", False),       # not in MAIN's shapes
    ("/run/wire_logs/llm_requests.jsonl", False),
    ("/run/../etc/passwd", False),               # resolve, then confine
)


# The object that crosses into the box.
def test_the_object_the_gate_authorised_is_the_object_the_box_runs(tmp_path):
    """The pipelines the gate authorised are the pipelines the box runs"""
    deps, box, payload = _gather_scene(tmp_path, BoxResult(0, b"ok", b""))
    m_payload = model_path(payload, run_dir=deps.run_dir)
    cmd = f"cat {m_payload}"
    _tool_bash(deps, cmd)
    assert len(box.calls) == 1
    sent = box.calls[0]
    # #1255 C8/C11: the decomposition the box receives, stated literally in the model view — how
    # the gate's own functions spell their inputs is the implementer's choice (C11).
    assert [[list(st.argv) for st in pl.stages] for pl in sent["pipelines"]] == \
        [[["cat", m_payload]]], "the box ran something other than what the gate authorised"
    assert sent["command"] == cmd

    # ...and an argv entry carrying the character the scanner no longer splits on crosses as
    # the one operand the text names.
    deps2 = dataclasses.replace(deps, box=Box(BoxResult(0, b"ok", b"")))
    _tool_bash(deps2, "echo a" + CR + "b")
    crossed = deps2.box.calls[0]["pipelines"]
    assert [list(st.argv) for pl in crossed for st in pl.stages] == [["echo", "a" + CR + "b"]], (
        "the operand the gate authorised is not the operand that crossed the wire - a carriage "
        "return is part of the word it touches, and nothing re-encodes an argv entry here"
    )


def test_nothing_mutates_the_authorised_pipelines_between_authorisation_and_execution(tmp_path):
    """Nothing mutates the authorised pipeline objects between the authorisation and the execution"""
    deps, box, payload = _gather_scene(tmp_path, BoxResult(1, b"", b"boom"))
    m_payload = model_path(payload, run_dir=deps.run_dir)
    _tool_bash(deps, f"cat {m_payload} | defender-sql 'SELECT 1'")
    sent = box.calls[0]
    live = [[list(st.argv) for st in pl.stages] for pl in sent["pipelines"]]
    at_receipt = [[list(st.argv) for st in pl.stages] for pl in sent["snapshot"]]
    assert live == at_receipt, (
        "the authorised pipelines were mutated after they crossed into the box - the audit "
        "path and the operand walk read this object graph and must not write to it"
    )
    # ...and what crossed is still the command's own decomposition, in the model view (#1255
    # C8/C11: stated literally — the gate's own input spelling is the implementer's choice).
    assert live == [[["cat", m_payload], ["defender-sql", "SELECT 1"]]], live


# What the model is told, and what the operator can see.
def _names_codepoint(reason: str, char: str) -> bool:
    """Does `reason` name `char` the only way a reason can name a character nobody can see -
    by its codepoint? `U+00A0`, any case, leading zeros optional."""
    return re.search(rf"U\+0*{ord(char):04x}\b", reason, re.IGNORECASE) is not None


def test_a_command_refused_only_for_an_invisible_character_is_told_so():
    """A command refused only because a character the model cannot see is now part of a word is told WHICH character"""
    for blank in base.DIVERGENT_BLANKS:
        for position, cmd in (
            ("trailing, in an operand", f"cat {REPORT}" + blank),
            ("leading, in the program name", blank + f"cat {REPORT}"),
            ("after a separator", f"cat {REPORT} |" + blank),
        ):
            d = _bash(cmd)
            assert not d.allow, (
                f"U+{ord(blank):04X} {position} still authorises a command the text does not "
                "name - the refusal this reason explains has not happened yet"
            )
            assert d.reason != base.MAIN.deny_reason, (
                f"a command refused only for U+{ord(blank):04X} ({position}) was refused with "
                "the generic capability deny; the model cannot see the character and has no way "
                "to find it"
            )
            assert _names_codepoint(d.reason, blank), (
                f"the refusal of {cmd!r} never names U+{ord(blank):04X}. It cannot be shown, so "
                "the codepoint is the only thing that can be said about it"
            )
    for cmd in (f"cat {REPORT}" + CR + "x", f"cat {REPORT}" + CR + "\nwc -l",
                f"cat {REPORT} |" + CR, f"cat {REPORT} &&" + CR):
        d = _bash(cmd)
        assert not d.allow, f"{cmd!r} is still authorised as a command the text does not name"
        assert _names_codepoint(d.reason, CR), (
            f"{cmd!r}: the refusal never names U+000D. A CRLF paste is by far the likeliest "
            "carriage return a model sends, and after this change every one of them carrying a "
            "path operand under a `cat`-shaped grant is refused"
        )
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
                        f"{arm} ({label} U+{ord(blank):04X}): a refusal this spec records as "
                        "unmoved left its own arm"
                    )
                    continue
                assert not d.allow, f"{arm} ({label} U+{ord(blank):04X}) became an allow"
                assert _names_codepoint(d.reason, blank), (
                    f"{arm} ({label} U+{ord(blank):04X}): this command was refused with a message "
                    "naming its problem before the change and is refused with one that names "
                    "nothing after it. The character is what moved the refusal off that arm, so "
                    "the reason has to say which character"
                )
    for name, shape in base.WRAPPER_LATER_TOKEN_SHAPES:
        for blank in base.DIVERGENT_BLANKS:
            d = _bash(blank + shape)
            assert not d.allow, f"leading U+{ord(blank):04X} + {name} became an allow"
            assert not _names_codepoint(d.reason, blank), (
                f"leading U+{ord(blank):04X} + {name}: a codepoint is named for a command that "
                f"is refused with it and without it ({shape!r} is refused on its own)"
            )
            assert _bash(shape).reason == d.reason, (
                f"{name}: the blank changed the message after all, so it IS part of the answer "
                "and the obligation to name it is back"
            )

    # The controls. An ordinary capability refusal keeps the plain reason...
    assert _bash("ls -la").reason == base.MAIN.deny_reason
    assert not _names_codepoint(_bash("ls -la").reason, CR)
    # ...and a command already refused for the same operand before this change does not move.
    assert _bash(f"cat '{REPORT}" + CR + "'").reason == base.MAIN.deny_reason


def test_the_serialised_verdict_an_operator_reads_carries_the_argv_half(capsys):
    """The one tool that prints a decision for a human reports the WHOLE verdict"""
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
    assert "pipelines" in out, (
        "`policy_cli explain --json` serialises allow/grant/reason and never the pipelines, so "
        "the one surface a human audits cannot see the argv the gate authorised"
    )
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
