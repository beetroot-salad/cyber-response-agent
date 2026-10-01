"""#1120 piece 1 — a name the tenant's repo chose reaches a refusal escaped (code review, max;
spec R6: entry names get N16's escaping).

A tenant repo can commit a file whose name holds a terminal escape sequence or a newline. A
refusal naming it raw let `\\x1b[2K\\r[tenant.py] all checks passed` erase the real refusal
line and print a forged verdict.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender import _tenant
from defender.tests.tenant_1120_piece1 import _spec1120 as H

_FORGED = "\x1b[2K\r[tenant.py] all checks passed\n"


def _no_control_characters(text: str) -> None:
    assert not any(ord(c) < 0x20 or c == "\x7f" for c in text), repr(text)


def test_a_stray_top_level_name_is_shown_escaped(tmp_path: Path) -> None:
    """A top-level file named with an escape sequence: refused, the message carries no
    control character, and names the entry by its escaped form."""
    root = tmp_path / "data"
    H.adopted(root)
    (H.knowledge_dir(root) / _FORGED).write_text("", encoding="utf-8")
    text = H.accept_refusal(_tenant, root)
    _no_control_characters(text)
    assert repr(_FORGED) in text, text


@pytest.mark.parametrize("half", ["settings", "agent"])
def test_a_link_inside_a_half_is_named_escaped(tmp_path: Path, half: str) -> None:
    """A link inside a half whose name holds the escape sequence: refused as a link, with no
    control character in the message. A printable name is still shown as-is (the spec's
    `str(planted) in text` cells)."""
    root = tmp_path / "data"
    H.adopted(root)
    (H.knowledge_dir(root) / half / _FORGED).symlink_to("/etc/hostname")
    text = H.accept_refusal(_tenant, root)
    _no_control_characters(text)
    assert "is a link" in text, text
