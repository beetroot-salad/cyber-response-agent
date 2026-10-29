"""#1342 O11: a job-lane run can write nowhere outside — the structural check that is P1b's
revisit trigger. Adding a write-capable verb class, grant, mount or tool fails it.

Explicit exemption: the launch-time knowledge publish (pushes to the tenant's forge) is lock-guarded,
safe to repeat and kept by #1081; it is not checked here."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest

DEFENDER = Path(__file__).resolve().parents[2]


def _shipped_adapters() -> list[str]:
    return sorted(p.stem for p in (DEFENDER / "integrations").glob("*_adapter.py"))


def test_o11_every_shipped_adapter_verb_is_read_class():
    """Each `VERBS` entry of every shipped adapter declares class `r`. (O11)"""
    from defender.kit.verbs import verb_class_of

    adapters = _shipped_adapters()
    assert len(adapters) >= 5, f"premise: the adapters were found: {adapters}"
    declared = {}
    for stem in adapters:
        module = importlib.import_module(f"defender.integrations.{stem}")
        for name, fn in getattr(module, "VERBS", {}).items():
            declared[(stem, name)] = verb_class_of(fn)
    assert declared, "premise: verbs were read"
    assert {k: v for k, v in declared.items() if v != "r"} == {}


def test_o11_the_grant_table_can_grant_only_the_read_class():
    """A disposition naming every role projects to read-class entries only, for every role. (O11)"""
    from defender.systems.verb_dispositions import KNOWN_ROLES, READ_CLASS, Disposition, grant_for

    everyone = Disposition(system="any", verb="write_things", roles=frozenset(KNOWN_ROLES))
    for role in sorted(KNOWN_ROLES):
        entries = grant_for(role, (everyone,)).entries
        assert entries, f"premise: {role} was granted the pair"
        assert {cls for _s, _v, cls in entries} == {READ_CLASS}


def test_o11_the_run_folder_is_the_lanes_only_writable_mount(tmp_path):
    """The run lane mounts everything read-only except the run folder. (O11)"""
    from defender.box._lifecycle import _run_lane_mounts

    run_dir = tmp_path / "runs" / "r"
    run_dir.mkdir(parents=True)
    mounts = _run_lane_mounts(run_dir, DEFENDER, tmp_path / "agent")
    assert len(mounts) >= 2, "premise: more than the run folder is mounted"
    assert [(m.what, m.source) for m in mounts if not m.readonly] == [("run dir", run_dir)]


def test_o11_the_job_entry_takes_no_ticket_writer_or_curation_seam():
    """The job entry composes refusing stubs itself: a caller cannot hand it a ticket writer or an enqueue. (O11)"""
    import inspect

    from defender import run as run_py

    params = inspect.signature(run_py.job_main).parameters
    assert "lifecycle" in params, "premise: the job entry takes its seams by keyword"
    assert not {"ticket_writer", "enqueue"} & set(params)


@pytest.mark.skip(reason="sketch: the reviewed role tool-name snapshot is the thorough pass's (SG-13)")
def test_o11_investigation_role_tools_match_the_reviewed_snapshot():
    """MAIN, gather, review and lead zero tool names equal a reviewed list. (O11)"""
