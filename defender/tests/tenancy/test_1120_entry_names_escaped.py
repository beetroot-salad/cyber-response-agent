"""A name chosen by a tenant repo reaches a refusal escaped, so it cannot forge a verdict line."""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tenancy import _tenant
from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

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
    root = tmp_path / "data"
    H.adopted(root)
    (H.knowledge_dir(root) / half / _FORGED).symlink_to("/etc/hostname")
    text = H.accept_refusal(_tenant, root)
    _no_control_characters(text)
    assert "is a link" in text, text
