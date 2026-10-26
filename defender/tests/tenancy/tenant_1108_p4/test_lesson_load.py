"""#1108 P4 slice S-B — O5: a lesson the model reads from the run copy is recorded in the run's
`lessons_loaded.jsonl` (recognised through `KnowledgePaths`' corpus dirs, not a `defender`
grandparent: P4-C7).

Entry: `run.main` over the real driver with replay models (see `test_run_isolation_e2e.py`),
the real `materialize`, production's unsandboxed box. Observation: the run's own
`lessons_loaded.jsonl`, read after the run. Control on the same channel: a non-lesson file of
the same copy (a system skill) is read in the same run and yields no row.
"""
from __future__ import annotations

import json

import pytest

from defender.tests.e2e import _replay_harness as R
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

pytestmark = pytest.mark.e2e


@pytest.fixture
def tenant(tmp_path, data_root):
    with B.run_tenant(tmp_path, data_root) as t:
        yield t


def _rows(run_dir) -> list[dict]:
    from defender.records import RunPaths

    path = RunPaths(run_dir).lessons_loaded
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def test_o5_a_lesson_read_from_the_run_copy_is_recorded_and_a_skill_read_is_not(
        tenant, tmp_path, monkeypatch):
    """O5: MAIN reads `/agent/lessons/fixture-owner-before-close.md` (the run copy) and the
    copy's `skills/cmdb/SKILL.md` with the typed `read_file` (the record's read door; a bash
    `cat` is not recorded today, before or after P4); the run records exactly one read row, for
    the lesson, by MAIN. Today a product-tree lesson read IS recorded (probed), so the channel
    is live."""
    lesson, skill = f"/agent/{B.LESSON_REL}", "/agent/skills/cmdb/SKILL.md"

    def read(path: str) -> R.Turn:
        return R.Turn(tool_calls=[("read_file", {"path": path})])

    main = R.ReplayFn([read(lesson), read(skill), R.Turn(text="done")])
    out = B.drive_main(tenant, tmp_path, monkeypatch, main=main)

    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    assert B.SEEDED_MARK in main.seen[1], "premise: the lesson read returned the copy's bytes"
    assert "Fixture CMDB reference" in main.seen[2], "premise: the skill read succeeded"
    reads = [r for r in _rows(out.run_dir) if r.get("kind") == "read"]
    assert [(r.get("lesson_name"), r.get("role")) for r in reads] == [
        ("fixture-owner-before-close", "main")], (
        f"O5: the run copy's lesson read is not recorded as exactly one MAIN read: {reads}")
