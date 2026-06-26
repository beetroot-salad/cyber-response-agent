"""Render the ## Query body for a handoff invocation.

The driver passes the rendered query to the agent so unbound
placeholders and wrong-shape bindings surface without forcing a
payload read.
"""
from __future__ import annotations

from pathlib import Path

from defender.learning.leads import lead_render  # type: ignore[import-not-found]


def _write_template(tmp_path: Path, query_body: str) -> Path:
    p = tmp_path / "t.md"
    p.write_text(
        "---\nid: x.y\n---\n\n## Goal\n\nx\n\n## Query\n\n"
        f"```bash\n{query_body}\n```\n"
    )
    return p


def test_render_substitutes_dollar_brace(tmp_path: Path):
    p = _write_template(tmp_path, "wazuh_cli.py --host ${host} --window ${window}")
    rendered = lead_render.render_query(p, {"host": "bastion-01", "window": "1h"})
    assert "bastion-01" in rendered
    assert "1h" in rendered
    assert "${host}" not in rendered


def test_render_substitutes_plain_brace(tmp_path: Path):
    p = _write_template(tmp_path, "process-list --pattern {pattern}")
    rendered = lead_render.render_query(p, {"pattern": "chrome"})
    assert "chrome" in rendered


def test_render_passes_through_unbound(tmp_path: Path):
    """Unknown placeholders stay verbatim — the leak must be visible."""
    p = _write_template(tmp_path, "wazuh_cli.py --host ${host} --user ${user}")
    rendered = lead_render.render_query(p, {"host": "bastion-01"})
    assert "bastion-01" in rendered
    assert "${user}" in rendered


def test_render_returns_empty_when_no_query_section(tmp_path: Path):
    p = tmp_path / "t.md"
    p.write_text("---\nid: x.y\n---\n\n## Goal\n\nno query here\n")
    assert lead_render.render_query(p, {}) == ""


def test_render_handles_fenceless_query_body(tmp_path: Path):
    p = tmp_path / "t.md"
    p.write_text(
        "---\nid: x.y\n---\n\n## Query\n\nplain text with ${param}\n\n## Common pitfalls\n\n- foo\n"
    )
    rendered = lead_render.render_query(p, {"param": "v"})
    assert "plain text with v" in rendered
