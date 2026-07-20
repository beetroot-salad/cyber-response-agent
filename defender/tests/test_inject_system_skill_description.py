"""Tests for defender/hooks/inject_system_skill_description.py.

Driven through `read_description` — the function the live callers reach
(`descriptor_catalog` → `runtime/tools_gather.py:40`; the #289 experiment's
`run_arms.py:55`). These used to run through the module's `claude -p` PreToolUse
`main()`, which asserted a stdin/stdout hook contract nothing invokes any more;
the frontmatter shapes each one really pins are asserted directly now.

`descriptor_catalog` itself is pinned by `test_verbs_registry_containment.py` and
`tests/e2e/test_query_tool_611.py`.
"""
from __future__ import annotations

from pathlib import Path

from defender.hooks.inject_system_skill_description import read_description


def _write_skill(skills_dir: Path, name: str, description: str, *, block_scalar: bool = False) -> None:
    skill_dir = skills_dir / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    if block_scalar:
        indented = "\n".join("  " + line for line in description.splitlines())
        front = f"---\nname: defender-{name}\ndescription: |\n{indented}\n---\n"
    else:
        front = f"---\nname: defender-{name}\ndescription: {description}\n---\n"
    (skill_dir / "SKILL.md").write_text(front + "\n# body\n")


def test_reads_oneliner_description(tmp_path):
    _write_skill(tmp_path, "elastic", "Use elastic_adapter.py --help, not source reads.")

    assert read_description("elastic", skills_dir=tmp_path) == (
        "Use elastic_adapter.py --help, not source reads."
    )


def test_reads_block_scalar_description(tmp_path):
    _write_skill(
        tmp_path, "elastic",
        "Rule 1: --help, not source reads.\nRule 2: absolute paths only.",
        block_scalar=True,
    )

    desc = read_description("elastic", skills_dir=tmp_path)
    assert "Rule 1: --help, not source reads." in desc
    assert "Rule 2: absolute paths only." in desc


def test_block_scalar_with_blank_line_between_paragraphs(tmp_path):
    """Multi-paragraph block scalars survive — regression for the original
    regex that stopped at the first unindented blank line and silently
    dropped everything after it."""
    _write_skill(
        tmp_path, "elastic",
        "First paragraph names the system and when it applies.\n"
        "\n"
        "Second paragraph carries an extra runtime caveat.",
        block_scalar=True,
    )

    desc = read_description("elastic", skills_dir=tmp_path)
    assert "First paragraph names the system" in desc
    assert "Second paragraph carries an extra runtime caveat" in desc


def test_silent_noop_when_skill_file_missing(tmp_path):
    # No skill written under the injected skills_dir.
    assert read_description("elastic", skills_dir=tmp_path) is None


def test_path_traversal_via_system_name_is_blocked(tmp_path):
    """A name carrying separators resolves outside `skills_dir` and is rejected.

    The retired hook had a system-key regex restricting the name to
    identifier-shape chars, so a traversal payload never reached this function;
    the guard here is what held if it ever did, and it is now the only guard —
    so it is pinned on its own rather than behind that regex.
    """
    assert read_description("../../etc/passwd", skills_dir=tmp_path) is None
