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

import sys
from pathlib import Path

import pytest

_DEFENDER = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_DEFENDER))

pytest.importorskip("pydantic_ai")

from runtime import tools  # noqa: E402

CAP = tools._READ_CHAR_CAP


def test_cap_matches_passthrough() -> None:
    """The read cap IS record_query's passthrough cap — one shared constant so
    the on-disk read can't defeat the capture's bound."""
    from record_query import PASSTHROUGH_MAX_BYTES

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
    assert "jq" in out and "/run/gather_raw/l-1/0.json" in out
    # full size surfaced so the model knows the scale it can't see
    assert str(CAP + 5000) in out


def test_notice_reports_true_line_count() -> None:
    # a single giant line (the real payload shape) — line count is 1, and there
    # is no offset/limit paging suggestion because paging a 1-line file is a no-op
    blob = "z" * (CAP + 1000)
    out = tools._bounded_read(blob, "/p.json")
    assert "/ 1 line(s)" in out
    assert "offset" not in out and "limit" not in out
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
