"""Tests for runtime.tools._bounded_read — the read_file char cap (#303).

read_file must not pull a multi-MB gather payload whole into the model's
context (a hard 200K-token overflow). _bounded_read caps the returned view at
the SAME constant that bounds record_query's passthrough, so a later read of
the persisted payload can't defeat that cap. Under the ceiling a file comes
back verbatim (every authored SKILL/lesson/doc fits with room to spare); over
it, the head plus a notice carrying the true size and a filter-first
resolution, since the overflowing files are single-document JSON dumps a line
window can't page.

The resolution is spelled in the CALLER'S OWN bash lane (`_overflow_filter_hint`,
derived from `policy.bash_allow` + `policy.write_allow`, never from a single capability
bit). It is always a PIPE: every reader's `jq`/`defender-sql` is stdin-compute-only, so
`jq '<filter>' <path>` is denied for main and gather and must never be advertised. main
gets `cat … | jq` plus the write-the-result step; gather gets the same pipe WITHOUT that
step (it has `jq` but no write tool); the judge gets `cat … | defender-sql` (no `jq` at
all); a reader-less agent (actor / oracle / verify / curators) is pointed at
`read_file(pattern=)`. A hint naming a program the agent cannot run, or a step it cannot
take, is worse than no hint — so every branch is pinned against a REAL compiled policy,
and the commands are asserted to pass that policy's own `decide_bash`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

_DEFENDER = Path(__file__).resolve().parents[1]

pytest.importorskip("pydantic_ai")

from defender.runtime import permission, tools  # noqa: E402
from defender.runtime.agent_definition import (  # noqa: E402
    RunScope, ToolSet, bind, compile_policy_for,
)
from defender.runtime.driver import GATHER_DEF, MAIN_DEF  # noqa: E402
from defender.runtime.permission import AgentPolicy  # noqa: E402

CAP = tools._read_char_cap()
_PATH = "/run/gather_raw/l-1/0.json"


def _main_policy(tmp: Path) -> AgentPolicy:
    return compile_policy_for(MAIN_DEF, run_dir=tmp / "run", defender_dir=_DEFENDER)


def _gather_policy(tmp: Path) -> AgentPolicy:
    return compile_policy_for(GATHER_DEF, run_dir=tmp / "run", defender_dir=_DEFENDER)


def _judge_policy(tmp: Path) -> AgentPolicy:
    from defender.learning.pipeline.judge.engine_pydantic import JUDGE_DEF
    return bind(JUDGE_DEF, tmp / "run", scope=RunScope(add_dirs=())).policy


def _admits(policy: AgentPolicy, command: str, run_dir: Path) -> bool:
    """Whether the agent's own gate would actually run `command` — the assertion that
    turns "the hint mentions jq" into "the hint names a command this agent can run"."""
    return permission.decide_bash(
        command, policy=policy, run_dir=run_dir, defender_dir=_DEFENDER,
    ).allow


# The main-lane hint, for the `_bounded_read` tests below. `_bounded_read` stays
# hint-agnostic — the branching lives in `_overflow_filter_hint`, pinned just below.
_MAIN_HINT = "Reduce it in a pipe, write the result to a file, then read that"


def _hinted_command(hint: str) -> str:
    """The runnable command out of a hint, with the `<filter>` placeholder bound (a
    literal `<` is a redirect token the parser rejects before the allowlist sees it)."""
    return hint.rsplit("\n", 1)[1].strip().replace("'<filter>'", "'.a'")


def test_overflow_hint_main_pipes_into_jq_and_names_the_write_sink(tmp_path) -> None:
    """main has `jq` AND a write tool. The reducer must be PIPED: `jq '<filter>' <path>`
    is denied (main/gather `jq` is stdin-compute-only), which the last assertion pins."""
    run = tmp_path / "run"
    pol = _main_policy(tmp_path)
    hint = tools._overflow_filter_hint(str(run / "big.json"), pol)
    assert "jq" in hint
    assert "write the result" in hint
    assert _admits(pol, _hinted_command(hint), run)


def test_overflow_hint_gather_pipes_into_jq_without_the_write_sink(tmp_path) -> None:
    """gather has `jq` but NO write tool (`write_allow == ()`), so it must not be told to
    write the filtered result to a file — a step it cannot take."""
    run = tmp_path / "run"
    pol = _gather_policy(tmp_path)
    assert not pol.write_allow, "premise: gather has no writer"
    hint = tools._overflow_filter_hint(str(run / "big.json"), pol)
    assert "jq" in hint
    assert "write the result" not in hint
    assert _admits(pol, _hinted_command(hint), run)


def test_overflow_hint_judge_pipes_into_defender_sql(tmp_path) -> None:
    """The judge has NO `jq` and NO write tool, so it must be told to aggregate through
    `defender-sql`. A hint naming a program it cannot run is worse than none."""
    run = tmp_path / "run"
    pol = _judge_policy(tmp_path)
    hint = tools._overflow_filter_hint(str(run / "big.json"), pol)
    assert "defender-sql" in hint
    assert "jq" not in hint
    assert "write the result" not in hint
    assert _admits(pol, _hinted_command(hint), run)


def test_overflow_hint_reducer_less_agent_points_at_its_read_tool() -> None:
    """The actor / oracle / verify / curators have no bash reducer: both `jq` and
    `defender-sql` name programs they cannot run, so the only reduction left is their read
    tool's own `pattern=` substring fold. The hint names the DEFAULT read tool here."""
    hint = tools._overflow_filter_hint(_PATH, AgentPolicy())
    assert "jq" not in hint
    assert "defender-sql" not in hint
    assert "pattern=" in hint
    assert "read_file(" in hint  # the default reader's tool


def test_overflow_hint_names_the_callers_read_tool_not_a_constant() -> None:
    """The rule that bans a hint naming a dead PROGRAM bans one naming a dead TOOL. The
    curators traded `read_file` for the scoped `lesson_read` (#559) AND have no bash reducer,
    so they are exactly the agent that lands on this branch — a hardcoded `read_file` would
    hand them an instruction they cannot execute. The tool name comes from the caller, and the
    overflow notice tag agrees with it."""
    hint = tools._overflow_filter_hint(_PATH, AgentPolicy(), "lesson_read")
    assert "lesson_read(" in hint  # the curator's ACTUAL read tool …
    assert "read_file(" not in hint  # … not the one it no longer has
    assert "pattern=" in hint  # …with the substring fold it does have
    over = tools._bounded_read(
        "x" * (tools._read_char_cap() + 10), _PATH, filter_hint=hint, read_tool="lesson_read",
    )
    assert "[lesson_read]" in over  # the notice tag agrees with the hint
    assert "[read_file]" not in over


def test_overflow_hint_never_advertises_jq_over_a_file_operand(tmp_path) -> None:
    """The regression this branch exists to prevent, stated directly: the pre-#569 hint
    was `jq '<filter>' {path}`, which EVERY agent's gate denies — main/gather because
    their `jq` takes no file operand, the judge because it has no `jq`."""
    run = tmp_path / "run"
    target = str(run / "big.json")
    for pol in (_main_policy(tmp_path), _gather_policy(tmp_path), _judge_policy(tmp_path)):
        assert not _admits(pol, f"jq '.a' {target}", run)
        assert f"jq '<filter>' {target}" not in tools._overflow_filter_hint(target, pol)


def test_cap_matches_passthrough() -> None:
    """The read cap IS record_query's passthrough cap — one shared source so
    the on-disk read can't defeat the capture's bound."""
    from defender.scripts.gather_tools.record_query import _passthrough_max_bytes

    assert _passthrough_max_bytes() == CAP


def test_under_cap_verbatim() -> None:
    text = "a SKILL\nwith a few lines\n"
    assert tools._bounded_read(text, "/x/SKILL.md", filter_hint=_MAIN_HINT) == text


def test_at_cap_verbatim() -> None:
    text = "x" * CAP
    assert tools._bounded_read(text, "/x/f.json", filter_hint=_MAIN_HINT) == text


def test_over_cap_truncates_head_and_appends_notice(tmp_path) -> None:
    path = _PATH
    text = "y" * (CAP + 5000)
    out = tools._bounded_read(
        text, path, filter_hint=tools._overflow_filter_hint(path, _main_policy(tmp_path)),
    )
    head, _, note = out.partition("\n\n[read_file]")
    assert head == "y" * CAP  # head is exactly the first CAP chars, verbatim
    assert note  # a notice was appended
    assert "too large to read whole" in out
    assert "jq" in out
    assert path in out  # the hint carries the file it refers to
    # full size surfaced so the model knows the scale it can't see
    assert str(CAP + 5000) in out


def test_notice_reports_true_line_count() -> None:
    # a single giant line (the real payload shape) — line count is 1, and there
    # is no offset/limit paging suggestion because paging a 1-line file is a no-op
    blob = "z" * (CAP + 1000)
    out = tools._bounded_read(blob, "/p.json", filter_hint=_MAIN_HINT)
    assert "/ 1 line(s)" in out
    assert "offset" not in out
    assert "limit" not in out
    # a multi-line oversized file reports its real line count
    lined = ("line\n" * ((CAP // 5) + 200))
    out2 = tools._bounded_read(lined, "/p.json", filter_hint=_MAIN_HINT)
    assert f"/ {lined.count(chr(10)) + 1} line(s)" in out2


def test_char_slice_never_splits_multibyte() -> None:
    # a head ending on a multibyte boundary: slicing by char (not byte) keeps it
    # a valid str — re-encoding must not raise.
    text = "é" * (CAP + 100)
    out = tools._bounded_read(text, "/p.json", filter_hint=_MAIN_HINT)
    head = out.split("\n\n[read_file]")[0]
    assert head == "é" * CAP
    head.encode("utf-8")  # would raise on a split surrogate; chars are intact


def _read_file_tool_output(run_dir: Path, path: Path, salt: str) -> str:
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
            return ModelResponse(parts=[ToolCallPart("read_file", {"path": str(path)})])
        return ModelResponse(parts=[TextPart("done")])

    agent = Agent(deps_type=tools.AgentDeps)
    tools.register_tools(agent, ToolSet(read=True))  # the test exercises read_file only
    deps = tools.AgentDeps(
        run_dir=run_dir, defender_dir=_DEFENDER, run_id="t", salt=salt,
        policy=compile_policy_for(MAIN_DEF, run_dir=run_dir, defender_dir=_DEFENDER),
    )
    result = asyncio.run(agent.run("go", deps=deps, model=FunctionModel(_model_fn)))

    for msg in result.all_messages():
        if isinstance(msg, ModelRequest):
            for part in msg.parts:
                if getattr(part, "tool_name", None) == "read_file":
                    return part.content
    raise AssertionError("no read_file ToolReturn found")


def test_oversized_untrusted_read_caps_before_wrapping(tmp_path) -> None:
    """The load-bearing ordering: read_file caps FIRST, then untrusted-wraps, so
    the head (and the appended notice) land INSIDE the salted delimiters — never
    a full multi-MB dump, and never a wrap whose closing tag was truncated away.
    Driven through the real `read_file` tool, so a refactor that inverted the
    order (wrap then cap) would fail here, not just in a comment."""
    salt = "SALT123"
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    # alert.json is an untrusted read (permission.is_untrusted_read) that the main
    # session is allowed to read — unlike gather_raw, which it's clamped from.
    alert = run_dir / "alert.json"
    alert.write_text("y" * (CAP + 5000))

    out = _read_file_tool_output(run_dir, alert, salt)

    opener, closer = f"<run-{salt}-untrusted>", f"</run-{salt}-untrusted>"
    assert out.startswith(opener), "untrusted read was not wrapped"
    assert out.rstrip().endswith(closer), "closing delimiter missing/truncated"
    assert "[read_file]" in out, "oversized read was not capped"
    # the notice (hence the bounded head) sits INSIDE the wrap, not after it —
    # this is what cap-before-wrap buys, and what a reorder would break.
    assert out.index("[read_file]") < out.index(closer)
    # and the full dump never reached the model: the wrapped body is the bounded
    # head + a short notice, not CAP+5000 chars.
    assert len(out) < CAP + 2000


def test_under_cap_untrusted_read_is_verbatim_and_wrapped(tmp_path) -> None:
    """A small untrusted file comes back whole (no notice) but still wrapped."""
    salt = "SALT123"
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    alert = run_dir / "alert.json"
    alert.write_text('{"id": 1}')

    out = _read_file_tool_output(run_dir, alert, salt)
    assert out == f'<run-{salt}-untrusted>\n{{"id": 1}}\n</run-{salt}-untrusted>'
    assert "[read_file]" not in out
