"""#1108 P4 operator CLIs, each case a wrong-but-green production variant: every CLI that logs in
reads the host secret file its tenant's live generation records (no flag, no default), and the CLIs
that show a tenant's knowledge read an export (the run's, or `current`), never the clone."""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, export_dir


def _tenant_cli():
    from defender.cli import tenant
    return tenant


# --- the run's map reads the export that run read ----------------------------------------------

def test_r6_the_workspace_map_of_a_run_reads_the_export_that_run_read(tmp_path, data_root, capsys):
    from defender.cli import workspace_map

    with B.run_tenant(tmp_path, data_root) as t:
        first = t.commit
        out = B.launch(t, tmp_path, publish=lambda *a, **k: B.fresh(first))
        assert out.rc == 0, out.text()
        t.merge(B.MERGE_FILES)
        second = t.publish().commit
        assert second != first
        # The map must show neither the later export nor the clone.
        capsys.readouterr()
        rc = workspace_map.main(["workspace_map.py", "--tenant", t.tenant_id, out.run_dir.name])
        text = capsys.readouterr().out
    assert rc == 0
    expected = export_dir(t.tenant, first) / "agent"
    agent_line = next(line for line in text.splitlines() if line.startswith("- AGENT_DIR:"))
    assert agent_line == f"- AGENT_DIR: `{expected}`", agent_line
    assert second not in text
    assert str(t.clone) not in text


# --- the CLIs that show knowledge read `current`'s export, not the clone ------------------------

def test_r6_the_trace_and_frontend_defaults_read_currents_export_not_the_clone(p4_tenant):
    from defender.cli.learning.trace_lesson import published_lessons_dir
    from defender.learning.frontend.serialize import published_agent_root

    t = p4_tenant
    export_agent = export_dir(t.tenant, t.commit) / "agent"
    assert published_agent_root(t.tenant) == export_agent
    assert published_lessons_dir(t.tenant_id) == export_agent / "lessons"
    assert Path(t.clone) not in published_agent_root(t.tenant).parents


# --- every login reads the secret file the live generation records ---------------------------

def _missing(tmp_path) -> Path:
    return tmp_path / "r6-no-such-dir" / "host-secret"


def _bind_missing_secret(t, tmp_path) -> Path:
    """Bind `t` to a live generation whose recorded host secret file is absent; returns that path."""
    from defender.tests.support.tenancy._active1214 import generation_fields

    missing = _missing(tmp_path)
    bind_forge(t, generations=[{**generation_fields(t.tenant_id, tmp_path / "secrets"), "host_secret_file": missing}])
    return missing


@pytest.mark.parametrize("command", ["update", "propose"])
def test_r6_tenant_cli_logs_in_from_the_secret_file_the_generation_records(p4_tenant, tmp_path, capsys,
                                                                           command):
    """With a forge-wired tenant, each command mints from the live generation's recorded host secret
    file: one that is not there is refused naming THAT path (there is no default), exit 1."""
    t = p4_tenant
    missing = _bind_missing_secret(t, tmp_path)
    argv = {"update": ["update", t.tenant_id],
            "propose": ["propose", t.tenant_id, str(_staged(tmp_path))]}[command]
    capsys.readouterr()
    rc = _tenant_cli().main(argv, directory=t.directory)
    said = capsys.readouterr()
    assert rc == 1, said
    assert str(missing) in said.err, said.err


def _staged(tmp_path) -> Path:
    staged = tmp_path / "staged" / "lessons"
    staged.mkdir(parents=True)
    (staged / "r6.md").write_text("---\nname: r6\n---\nbody\n", encoding="utf-8")
    return staged.parent


def test_r6_revert_lesson_logs_in_from_the_secret_file_the_generation_records(p4_tenant, tmp_path,
                                                                             caplog):
    from defender.cli.learning import revert_lesson

    t = p4_tenant
    missing = _bind_missing_secret(t, tmp_path)
    with caplog.at_level(logging.CRITICAL):
        rc = revert_lesson.main(["--tenant", t.tenant_id, "some-lesson"], directory=t.directory)
    assert rc == 2
    assert str(missing) in "\n".join(r.getMessage() for r in caplog.records), caplog.text


def test_r6_the_publish_child_logs_in_from_the_secret_file_the_generation_records(p4_tenant, tmp_path,
                                                                                 capsys):
    """The child is handed identifiers only: the secret file comes from the tenant's live generation."""
    from defender.learning.author import version_control as vc

    t = p4_tenant
    missing = _bind_missing_secret(t, tmp_path)
    capsys.readouterr()
    rc = vc.publish_child_main([t.tenant_id, "--data-root", str(t.data_root)], directory=t.directory)
    line = capsys.readouterr().out.strip().splitlines()[-1]
    assert rc == 0
    assert line.startswith("misconfigured"), line
    assert str(missing) in line, line
