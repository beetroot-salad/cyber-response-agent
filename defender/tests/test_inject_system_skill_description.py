"""Tests for defender/hooks/inject_system_skill_description.py."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path



HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "inject_system_skill_description.py"


def _load():
    spec = importlib.util.spec_from_file_location("inject_system_skill_description", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


def _hook_input(prompt: str) -> str:
    return json.dumps({"tool_name": "Task", "tool_input": {"prompt": prompt}})


def _gather_prompt(run_dir: Path, system: str) -> str:
    return (
        "Read defender/skills/gather/SKILL.md and follow it.\n\n"
        "## Dispatch\n"
        "```yaml\n"
        f"run_dir: {run_dir}\n"
        "position: 0\n"
        "goal: test\n"
        f"system: {system}\n"
        "```\n"
    )


def _write_skill(skills_dir: Path, name: str, description: str, *, block_scalar: bool = False) -> None:
    skill_dir = skills_dir / name
    skill_dir.mkdir(parents=True, exist_ok=True)
    if block_scalar:
        indented = "\n".join("  " + line for line in description.splitlines())
        front = f"---\nname: defender-{name}\ndescription: |\n{indented}\n---\n"
    else:
        front = f"---\nname: defender-{name}\ndescription: {description}\n---\n"
    (skill_dir / "SKILL.md").write_text(front + "\n# body\n")


def test_injects_oneliner_description(tmp_path):
    hook = _load()
    _write_skill(tmp_path, "elastic", "Use elastic_adapter.py --help, not source reads.")

    desc = hook.read_description("elastic", skills_dir=tmp_path)
    augmented = hook.build_augmented_prompt(_gather_prompt(tmp_path, "elastic"), "elastic", desc)
    assert "auto-injected from SKILL frontmatter" in augmented
    assert "Use elastic_adapter.py --help, not source reads." in augmented


def test_injects_block_scalar_description(tmp_path):
    hook = _load()
    _write_skill(
        tmp_path, "elastic",
        "Rule 1: --help, not source reads.\nRule 2: absolute paths only.",
        block_scalar=True,
    )

    desc = hook.read_description("elastic", skills_dir=tmp_path)
    augmented = hook.build_augmented_prompt(_gather_prompt(tmp_path, "elastic"), "elastic", desc)
    assert "Rule 1: --help, not source reads." in augmented
    assert "Rule 2: absolute paths only." in augmented


def test_block_scalar_with_blank_line_between_paragraphs(tmp_path):
    """Multi-paragraph block scalars survive — regression for the original
    regex that stopped at the first unindented blank line and silently
    dropped everything after it."""
    hook = _load()
    _write_skill(
        tmp_path, "elastic",
        "First paragraph names the system and when it applies.\n"
        "\n"
        "Second paragraph carries an extra runtime caveat.",
        block_scalar=True,
    )

    desc = hook.read_description("elastic", skills_dir=tmp_path)
    augmented = hook.build_augmented_prompt(_gather_prompt(tmp_path, "elastic"), "elastic", desc)
    assert "First paragraph names the system" in augmented
    assert "Second paragraph carries an extra runtime caveat" in augmented


def test_silent_noop_when_dispatch_has_no_system_field(tmp_path, monkeypatch, capsys):
    hook = _load()
    _write_skill(tmp_path, "elastic", "ignored")
    prompt_no_system = (
        "Read defender/skills/gather/SKILL.md and follow it.\n\n"
        "## Dispatch\n```yaml\nrun_dir: /tmp\nposition: 0\ngoal: x\n```\n"
    )
    monkeypatch.setattr(sys, "stdin", _StringIn(_hook_input(prompt_no_system)))

    assert hook.main() == 0
    assert capsys.readouterr().out == ""


def test_silent_noop_when_skill_file_missing(tmp_path):
    hook = _load()
    # No skill written under the injected skills_dir.
    assert hook.read_description("elastic", skills_dir=tmp_path) is None


def test_silent_noop_for_non_gather_task(monkeypatch, capsys):
    hook = _load()
    payload = json.dumps({
        "tool_name": "Task",
        "tool_input": {"prompt": "Some other subagent prompt without the marker"},
    })
    monkeypatch.setattr(sys, "stdin", _StringIn(payload))

    assert hook.main() == 0
    assert capsys.readouterr().out == ""


def test_path_traversal_via_system_field_is_blocked(tmp_path, monkeypatch, capsys):
    hook = _load()
    # Attacker-controlled prompt with a traversal payload.
    prompt = _gather_prompt(tmp_path, "../../etc/passwd")
    monkeypatch.setattr(sys, "stdin", _StringIn(_hook_input(prompt)))

    # The system-key regex restricts to identifier-shape chars, so this
    # never even reaches read_description. If it did, the path-traversal
    # guard would catch it: a name with separators resolves outside
    # skills_dir and is rejected.
    assert hook.main() == 0
    assert capsys.readouterr().out == ""
    assert hook.read_description("../../etc/passwd", skills_dir=tmp_path) is None


def test_preserves_other_tool_input_fields(monkeypatch, capsys):
    """main() copies the rest of tool_input through untouched, swapping only
    `prompt`. Driven end-to-end against a real system skill (`elastic`,
    resolved from the default SKILLS_DIR) so no module global is patched."""
    hook = _load()
    full_input = {
        "prompt": _gather_prompt(Path("/tmp"), "elastic"),
        "subagent_type": "general-purpose",
        "description": "Gather: companion alert scan",
    }
    payload = json.dumps({"tool_name": "Task", "tool_input": full_input})
    monkeypatch.setattr(sys, "stdin", _StringIn(payload))

    assert hook.main() == 0
    updated = json.loads(capsys.readouterr().out)["hookSpecificOutput"]["updatedInput"]
    assert updated["subagent_type"] == "general-purpose"
    assert updated["description"] == "Gather: companion alert scan"
    assert "auto-injected from SKILL frontmatter" in updated["prompt"]


class _StringIn:
    def __init__(self, s: str):
        self._s = s

    def read(self) -> str:
        return self._s
