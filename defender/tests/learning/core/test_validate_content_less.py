"""The report-disposition keyword gate matches on what a value RENDERS as (an NBSP-padded keyword is
accepted, a content-less or look-alike one refused), plus the `_text` helpers behind it (#722)."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender._text import as_str, is_content_less, strip_zero_width
from defender.learning import loop
from defender.learning.core.config import RunUnprocessable


def _report(tmp_path: Path, disposition: str) -> Path:
    p = tmp_path / "report.md"
    p.write_text(
        f"---\ndisposition: \"{disposition}\"\n---\n\nThe write-up.\n", encoding="utf-8"
    )
    return p


# the keyword gates — matched on what a value renders as


@pytest.mark.parametrize(("tag", "written"), [("clean", "benign"),
                                             ("nbsp-padded", "\u00a0benign\u00a0")])
def test_a_report_disposition_is_matched_on_what_it_renders_as(tmp_path, tag, written):
    assert loop.normalize_disposition(_report(tmp_path, written)) == "benign"


@pytest.mark.parametrize(
    ("tag", "written"),
    [
        ("not-a-keyword", "spicy"),
        ("content-less", "​"),
        # The read side does not coerce a zero-width- or BOM-laced disposition into the member
        # it resembles (#923).
        ("trailing-zwsp", "benign​"),
        ("bom", "﻿benign"),
    ],
)
def test_a_report_disposition_that_is_not_a_keyword_is_still_rejected(tmp_path, tag, written):
    with pytest.raises(RunUnprocessable, match="disposition="):
        loop.normalize_disposition(_report(tmp_path, written))


# the shared helper's own contract

def test_strip_zero_width_keeps_the_whitespace_callers_split_on():
    assert strip_zero_width("caught​﻿\x00") == "caught"
    assert strip_zero_width("caught. why\nbecause") == "caught. why\nbecause"
    assert strip_zero_width(" caught ") == " caught "
    assert strip_zero_width("") == ""
    # what survives is exactly what a reader sees, so the two helpers agree
    assert is_content_less(strip_zero_width("​﻿ \x00"))
    assert not is_content_less(strip_zero_width("​x"))


def test_as_str_answers_on_the_type_and_not_on_emptiness():
    """`as_str` turns any NON-STRING into `""`, not merely `None`."""
    assert as_str("elastic") == "elastic"
    assert as_str("") == ""
    for not_a_string in (None, 12345, True, ["a"], {"n": 1}, 1.5, b"bytes"):
        assert as_str(not_a_string) == "", f"{not_a_string!r} was passed through, not coerced"
