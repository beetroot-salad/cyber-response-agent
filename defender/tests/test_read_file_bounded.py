"""Tests for runtime.tools._bounded_read — the read_file char cap (#303).

read_file must not pull a multi-MB gather payload whole into the model's
context (a hard 200K-token overflow). _bounded_read caps the returned view at
the SAME constant that bounds record_query's passthrough, so a later read of
the persisted payload can't defeat that cap. Under the ceiling a file comes
back verbatim (every authored SKILL/lesson/doc fits with room to spare); over
it, the head plus a notice carrying the true size and the filter-first
resolution (jq/grep), since the overflowing files are single-document JSON
dumps a line window can't page.
"""
from __future__ import annotations

from pathlib import Path

import pytest

_DEFENDER = Path(__file__).resolve().parents[1]

pytest.importorskip("pydantic_ai")

from defender.runtime import tools  # noqa: E402

CAP = tools._READ_CHAR_CAP


def test_cap_matches_passthrough() -> None:
    """The read cap IS record_query's passthrough cap — one shared constant so
    the on-disk read can't defeat the capture's bound."""
    from defender.scripts.gather_tools.record_query import PASSTHROUGH_MAX_BYTES

    assert CAP == PASSTHROUGH_MAX_BYTES


def test_under_cap_verbatim() -> None:
    text = "a SKILL\nwith a few lines\n"
    assert tools._bounded_read(text, "/x/SKILL.md") == text


def test_at_cap_verbatim() -> None:
    text = "x" * CAP
    assert tools._bounded_read(text, "/x/f.json") == text


def test_over_cap_truncates_head_and_appends_notice() -> None:
    text = "y" * (CAP + 5000)
    out = tools._bounded_read(text, "/run/gather_raw/l-1/0.json")
    head, _, note = out.partition("\n\n[read_file]")
    assert head == "y" * CAP  # head is exactly the first CAP chars, verbatim
    assert note  # a notice was appended
    assert "too large to read whole" in out
    assert "jq" in out
    assert "/run/gather_raw/l-1/0.json" in out
    # full size surfaced so the model knows the scale it can't see
    assert str(CAP + 5000) in out


def test_notice_reports_true_line_count() -> None:
    # a single giant line (the real payload shape) — line count is 1, and there
    # is no offset/limit paging suggestion because paging a 1-line file is a no-op
    blob = "z" * (CAP + 1000)
    out = tools._bounded_read(blob, "/p.json")
    assert "/ 1 line(s)" in out
    assert "offset" not in out
    assert "limit" not in out
    # a multi-line oversized file reports its real line count
    lined = ("line\n" * ((CAP // 5) + 200))
    out2 = tools._bounded_read(lined, "/p.json")
    assert f"/ {lined.count(chr(10)) + 1} line(s)" in out2


def test_char_slice_never_splits_multibyte() -> None:
    # a head ending on a multibyte boundary: slicing by char (not byte) keeps it
    # a valid str — re-encoding must not raise.
    text = "é" * (CAP + 100)
    out = tools._bounded_read(text, "/p.json")
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

    agent = Agent(deps_type=tools.RunDeps)
    tools.register_tools(agent)
    deps = tools.RunDeps(
        run_dir=run_dir, defender_dir=_DEFENDER, run_id="t", salt=salt, is_main_session=True
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
