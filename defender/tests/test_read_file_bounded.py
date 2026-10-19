from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests._1255_view import model_path

from defender.tests._frames680 import assert_one_frame, frame_salt_of

_DEFENDER = Path(__file__).resolve().parents[1]

pytest.importorskip("pydantic_ai")

from defender.runtime import permission, tools  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
    ToolSet, compile_policy_for,
)
from defender.runtime.driver import MAIN_DEF  # noqa: E402
from defender.tests import _tenants1106  # noqa: E402
from defender.runtime.permission import AgentPolicy  # noqa: E402

CAP = tools._read_char_cap()
_PATH = "/run/gather_raw/l-1/0.json"


def _main_policy(tmp: Path) -> AgentPolicy:
    return compile_policy_for(MAIN_DEF, run_dir=tmp / "run", defender_dir=_DEFENDER)


def _gather_policy(tmp: Path) -> AgentPolicy:
    return compile_policy_for(
        _tenants1106.fixture_gather_def(), run_dir=tmp / "run", defender_dir=_DEFENDER)


def _admits(policy: AgentPolicy, command: str, run_dir: Path) -> bool:
    """Whether the agent's own gate would actually run `command` — the assertion that
    turns "the hint mentions jq" into "the hint names a command this agent can run"."""
    return permission.decide_bash(
        command, policy=policy, run_dir=run_dir, defender_dir=_DEFENDER,
    ).allow


_MAIN_HINT = "Reduce it in a pipe, write the result to a file, then read that"


def _hinted_command(hint: str) -> str:
    """The runnable command out of a hint, with the `<filter>` placeholder bound (a
    literal `<` is a redirect token the parser rejects before the allowlist sees it)."""
    return hint.rsplit("\n", 1)[1].strip().replace("'<filter>'", "'.a'")


def test_overflow_hint_main_pipes_into_defender_sql_and_names_the_write_sink(tmp_path) -> None:
    """main has `jq` AND a write tool. The reducer must be PIPED: `jq '<filter>' <path>`
    is denied (main/gather `jq` is stdin-compute-only), which the last assertion pins."""
    run = tmp_path / "run"
    pol = _main_policy(tmp_path)
    hint = tools._overflow_filter_hint(str(run / "big.json"), pol)
    assert "defender-sql" in hint
    assert "write the result" in hint
    assert _admits(pol, _hinted_command(hint), run)


@pytest.mark.parametrize("policy_of", [_main_policy, _gather_policy], ids=["main", "gather"])
def test_overflow_hint_offers_a_reduction_correct_for_any_payload_shape(tmp_path, policy_of) -> None:
    """#1138 O8: the reduction the hint hands over has to be right whatever the payload's shape."""
    run = tmp_path / "run"
    pol = policy_of(tmp_path)
    hint = tools._overflow_filter_hint(str(run / "big.json"), pol)
    assert "DESCRIBE data" in hint, hint
    assert "count(*)" not in hint, f"the hint offers a whole-payload count: {hint!r}"
    assert _admits(pol, _hinted_command(hint), run)


def test_a_captured_payload_is_read_at_the_CAPTURE_ceiling() -> None:
    """The property the shared constant used to carry, kept after #832 split it."""
    from defender.runtime.payload_view import passthrough_max_bytes

    assert tools._cap_for(Path("/run/gather_raw/l-1/0.json")) == passthrough_max_bytes()


def test_an_authored_file_is_read_at_the_AUTHORED_cap() -> None:
    """The complement, and the reason the split exists: `SKILL.md` is the runtime agent's own
    spec and every authored file in the tree fits under this cap with room to spare."""
    assert tools._cap_for(Path("/w/defender/SKILL.md")) == CAP
    assert tools._cap_for(Path("/run/alert.json")) == CAP, (
        "alert.json is the run's INPUT, not a capture — it is read whole"
    )
    assert (_DEFENDER / "SKILL.md").stat().st_size < CAP


def test_under_cap_verbatim() -> None:
    text = "a SKILL\nwith a few lines\n"
    assert tools._bounded_read(text, "/x/SKILL.md", cap=CAP, filter_hint=_MAIN_HINT) == text


def test_at_cap_verbatim() -> None:
    text = "x" * CAP
    assert tools._bounded_read(text, "/x/f.json", cap=CAP, filter_hint=_MAIN_HINT) == text


def test_over_cap_truncates_head_and_appends_notice(tmp_path) -> None:
    path = _PATH
    text = "y" * (CAP + 5000)
    out = tools._bounded_read(
        text, path, cap=CAP,
        filter_hint=tools._overflow_filter_hint(path, _main_policy(tmp_path)),
    )
    head, _, note = out.partition("\n\n[read_file]")
    assert head == "y" * CAP
    assert note
    assert "too large to read whole" in out
    assert "defender-sql" in out
    assert path in out
    assert str(CAP + 5000) in out


def test_char_slice_never_splits_multibyte() -> None:
    text = "é" * (CAP + 100)
    out = tools._bounded_read(text, "/p.json", cap=CAP, filter_hint=_MAIN_HINT)
    head = out.split("\n\n[read_file]")[0]
    assert head == "é" * CAP
    head.encode("utf-8")


def _read_file_tool_output(run_dir: Path, path: Path) -> str:
    """Drive the real `read_file` tool through a FunctionModel that issues one
    read_file call, and return the ToolReturn content the model would see. No
    network — the model is scripted, so this needs no API key."""
    import asyncio

    from pydantic_ai import Agent
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.messages import ModelRequest, ModelResponse, TextPart, ToolCallPart

    calls: list[int] = []

    def _model_fn(messages, info):  # noqa: ANN001 — pydantic_ai FunctionDef shape
        calls.append(1)
        if len(calls) == 1:
            return ModelResponse(parts=[ToolCallPart("read_file", {"path": model_path(path, run_dir=run_dir, defender_dir=_DEFENDER)})])
        return ModelResponse(parts=[TextPart("done")])

    agent = Agent(deps_type=tools.AgentDeps)
    tools.register_tools(agent, ToolSet(read=True))
    deps = tools.AgentDeps(
        run_dir=run_dir, defender_dir=_DEFENDER, run_id="t",
        policy=compile_policy_for(MAIN_DEF, run_dir=run_dir, defender_dir=_DEFENDER),
        cwd_anchor=run_dir,
    )
    result = asyncio.run(agent.run("go", deps=deps, model=FunctionModel(_model_fn)))

    for msg in result.all_messages():
        if isinstance(msg, ModelRequest):
            for part in msg.parts:
                if getattr(part, "tool_name", None) == "read_file":
                    return part.content
    raise AssertionError("no read_file ToolReturn found")


def test_oversized_untrusted_read_caps_before_wrapping(tmp_path) -> None:
    """The load-bearing ordering: read_file caps FIRST, then untrusted-wraps, so"""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    alert = run_dir / "alert.json"
    alert.write_text("y" * (CAP + 5000))

    out = _read_file_tool_output(run_dir, alert)

    # #875: the delimiter is minted at wrap time, so it is read off the return.
    salt = frame_salt_of(out, "untrusted")
    opener, closer = f"<run-{salt}-untrusted>", f"</run-{salt}-untrusted>"
    assert out.startswith(opener), "untrusted read was not wrapped"
    assert out.rstrip().endswith(closer), "closing delimiter missing/truncated"
    assert "[read_file]" in out, "oversized read was not capped"
    assert out.index("[read_file]") < out.index(closer)
    assert len(out) < CAP + 2000


def test_under_cap_untrusted_read_is_verbatim_and_wrapped(tmp_path) -> None:
    """A small untrusted file comes back whole (no notice) but still wrapped."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    alert = run_dir / "alert.json"
    alert.write_text('{"id": 1}')

    out = _read_file_tool_output(run_dir, alert)
    assert_one_frame(out, '{"id": 1}', "untrusted")
    assert "[read_file]" not in out
