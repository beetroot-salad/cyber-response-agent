"""Tests for the lint_agent_retries gate: every pydantic_ai Agent built in production passes retries=."""
from __future__ import annotations

from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_agent_retries")


def _tree(tmp_path: Path, files: dict[str, str]) -> Path:
    root = tmp_path / "defender"
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


@pytest.mark.parametrize("src", [
    "from pydantic_ai import Agent\nA = Agent(m)\n",
    "from pydantic_ai import Agent as Ag\nA = Ag(m, model_settings=s)\n",
    "import pydantic_ai\nA = pydantic_ai.Agent(m)\n",
    "from pydantic_ai import Agent\nA = Agent(m, **opts)\n",
])
def test_a_construction_without_retries_is_found_however_it_is_spelled(tmp_path, src):
    found = _GATE.scan(_tree(tmp_path, {"x.py": src}))
    assert len(found) == 1, found
    assert "retries" in found[0], found


@pytest.mark.parametrize("rel, src", [
    ("x.py", "from pydantic_ai import Agent\nA = Agent(m, retries=3)\n"),
    ("x.py", "from mine import Agent\nA = Agent(m)\n"),
    ("tests/x.py", "from pydantic_ai import Agent\nA = Agent(m)\n"),
], ids=["with_retries", "unrelated_agent_class", "tests_are_not_swept"])
def test_a_construction_that_is_clean_or_out_of_scope_has_no_findings(tmp_path, rel, src):
    assert _GATE.scan(_tree(tmp_path, {rel: src})) == []


def test_a_file_that_does_not_parse_is_exit_2(tmp_path, capsys):
    root = _tree(tmp_path, {"x.py": "def (:\n"})
    assert _GATE.main(["--root", str(root)]) == 2
