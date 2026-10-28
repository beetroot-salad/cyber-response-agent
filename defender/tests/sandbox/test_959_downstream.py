"""#959 — downstream of the bash decision: the box handoff, the operand set's consumers, the audit
row, refusal reasons and the operator's view."""
from __future__ import annotations
from defender.tests.support.shared._fixture_uuid import fixture_uuid

from defender.tests.support.shared.contracts._spec1077 import fixture_run

import copy
import dataclasses
import io
import json
import re
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from defender.tests.support.runtime.state._1255_view import model_path

pytest.importorskip("pydantic_ai")

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender.investigation import permission  # noqa: E402
from defender.investigation.agent_definition import bind  # noqa: E402
from defender.execution.box_codec import BoxResult  # noqa: E402
from defender.investigation.tools import _tool_bash  # noqa: E402
from defender.cli import policy_cli  # noqa: E402
from defender.knowledge import _query_rules  # noqa: E402
from defender.investigation import record_query  # noqa: E402
from defender.tests.support.sandbox import _baseline_959 as base
from defender.tests.support.tenancy import _tenants1106 as T1106

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
