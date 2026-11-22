"""#1108 P4 operator CLIs, each case a wrong-but-green production variant: every CLI that logs in
reads the host secret file its tenant's live generation records (no flag, no default), and (#1618) the CLIs
that show a tenant's knowledge read a copy of Forgejo's commit (main, or the run's own), never the clone."""
from __future__ import annotations

import logging
from pathlib import Path

import pytest

from defender.tests.support.learning.core._store1278 import (
    migrated_database,  # noqa: F401 — fixture the world needs
    world,  # noqa: F401 — fixture
)
from defender.tests.tenancy.knowledge_1618 import _readers_1618 as RD
from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_p4._support import bind_forge


def _tenant_cli():
    from defender.cli import tenant
    return tenant


# --- #1618: the tools that show knowledge read Forgejo's commit and leave nothing (F4, K4, K5) ------------------

@pytest.fixture
def k_scene(tmp_path, data_root):
    """The upgraded tenant (no clone, `exports/`, `current`); `main` at the seed."""
    with K.scene(tmp_path, data_root) as scene:
        yield scene


@pytest.fixture
def k_decoy(tmp_path, data_root):
    """A stale clone, `exports/<seed>/` and `current` the tools must ignore; `main` moved on (`MERGED_MARK`)."""
    with K.scene(tmp_path, data_root, decoy=True) as scene:
        yield scene


def _tracer(tenant):
    from defender.cli.learning import trace_lesson
    return trace_lesson.main, ["--tenant", tenant, "--all"]


def _page(tenant):
    from defender.learning.frontend import serialize
    return serialize.main, ["lessons_page.py", "--tenant", tenant]


def _policy(tenant, tmp_path):
    from defender.cli import policy_cli
    return policy_cli.main, ["show", "gather", "--run-dir", str(tmp_path / "policy-run"), "--tenant", tenant]


def _map(tenant, run_id):
    from defender.cli import workspace_map
    return workspace_map.main, ["workspace_map.py", "--tenant", tenant, run_id]


def test_1618_c5_the_lessons_page_and_the_tracer_show_mains_tip_not_the_clone_or_exports(k_decoy, tmp_path, capsys):
    """Both print the lesson as `main` holds it (`MERGED_MARK`) while the clone and the kept export hold the seed and a
    clone-only edit; each leaves nothing in the temporary folder and reached Forgejo. (F4, K8)"""
    t = k_decoy
    for make in (_page, _tracer):
        main, argv = make(t.tenant_id)
        ran = RD.run_tool(t, tmp_path, capsys, main, argv)
        assert ran.rc == 0, ran.err
        assert K.MERGED_MARK in ran.out, f"{make.__name__}: not main's tip"
        assert K.SEEDED_MARK not in ran.out
        assert K.CLONE_ONLY_MARK not in ran.out
        assert ran.requests > 0, "nothing was fetched from Forgejo"
        assert ran.left == [], f"{make.__name__} left {ran.left} in the temporary folder"


@pytest.mark.parametrize("tool", ["page", "tracer", "policy", "map"])
def test_1618_c5_k4_each_operator_tool_exits_non_zero_naming_why_when_forgejo_is_down(k_scene, tmp_path, capsys, tool):
    """The lessons page, the tracer, the policy CLI and the workspace map exit non-zero with a reason on stderr and no
    output from stale knowledge when Forgejo is unreachable; each succeeds with it up (control) and leaves nothing. (F4, K4)"""
    t = k_scene
    run_id = RD.plant_run(t, t.commit)
    make = {"page": lambda: _page(t.tenant_id), "tracer": lambda: _tracer(t.tenant_id),
            "policy": lambda: _policy(t.tenant_id, tmp_path), "map": lambda: _map(t.tenant_id, run_id)}[tool]
    main, argv = make()
    control = RD.run_tool(t, tmp_path, capsys, main, argv)
    assert control.rc == 0, f"control: {control.err}"
    assert control.out.strip()

    K.forge_down(t)
    ran = RD.run_tool(t, tmp_path, capsys, main, argv)

    assert ran.rc != 0, "the tool succeeded with Forgejo unreachable"
    assert ran.err.strip(), "no reason was given"
    assert "stale" not in ran.err.lower()
    assert K.SEEDED_MARK not in ran.out
    assert ran.left == [], f"left {ran.left}"


def test_1618_c5_the_policy_cli_projects_mains_grant_table_each_time_it_runs(k_scene, tmp_path, capsys):
    """`defender-policy show gather --tenant` shows `cmdb` while main grants it and not after a merge withholds it: the table
    is main's at each run, from a copy handed to the CLI, not a kept one. (F4, K8)"""
    from defender.tests.support.jobs._readiness1471 import grants_text

    def withhold(d: dict) -> None:
        for verb in d["cmdb"]:
            d["cmdb"][verb] = {"roles": [], "reason": "withheld for #1618"}

    t = k_scene
    main, argv = _policy(t.tenant_id, tmp_path)
    before = RD.run_tool(t, tmp_path, capsys, main, argv)
    assert before.rc == 0, before.err
    assert "cmdb" in before.out, "control: the table grants cmdb at the seed"

    K.advance_main(t, files={"settings/verb-grants.yaml": grants_text(withhold)})
    after = RD.run_tool(t, tmp_path, capsys, main, argv)

    assert after.rc == 0, after.err
    assert "cmdb" not in after.out, "the policy still shows a grant main withheld"
    assert before.left == [] == after.left


def test_1618_c6_the_workspace_map_of_a_run_shows_the_agent_tree_at_the_commit_that_run_read(k_scene, tmp_path, capsys):
    """The map is drawn over a copy of the run's recorded commit fetched by id (`cmdb` still has its `SKILL.md`), not main's
    later tip (where it is deleted); the copy is gone afterwards. (F4, K5)"""
    t = k_scene
    seed = t.commit
    run_id = RD.plant_run(t, seed)
    K.advance_main(t, files={"agent/skills/cmdb/SKILL.md": None})

    main, argv = _map(t.tenant_id, run_id)
    ran = RD.run_tool(t, tmp_path, capsys, main, argv)

    assert ran.rc == 0, ran.err
    lines = ran.out.splitlines()
    assert "- cmdb (SKILL.md)" in lines, "not the tree at the run's commit"
    assert "- cmdb" not in lines, "main's later tip was read"
    assert ran.requests > 0
    assert ran.left == [], f"left {ran.left}"


def test_1618_c6_k5_a_run_whose_recorded_commit_forgejo_does_not_serve_gets_no_map_and_a_reason_naming_it(k_scene, tmp_path,
                                                                                                          capsys):
    """The map for a run recorded at a commit Forgejo does not hold exits non-zero naming the commit (no empty map);
    the served commit above is the control. (F4, K5)"""
    t = k_scene
    run_id = RD.plant_run(t, K.ABSENT_COMMIT)
    main, argv = _map(t.tenant_id, run_id)

    ran = RD.run_tool(t, tmp_path, capsys, main, argv)

    assert ran.rc != 0
    assert K.ABSENT_COMMIT in ran.err, ran.err
    assert "System skills" not in ran.out
    assert ran.left == []


# --- every login reads the secret file the live generation records ---------------------------

def _missing(tmp_path) -> Path:
    return tmp_path / "r6-no-such-dir" / "host-secret"


def _bind_missing_secret(t, tmp_path) -> Path:
    """Bind `t` to a live generation whose recorded host secret file is absent; returns that path."""
    from defender.tests.support.tenancy._active1214 import generation_fields

    missing = _missing(tmp_path)
    bind_forge(t, generations=[{**generation_fields(t.tenant_id, tmp_path / "secrets"), "host_secret_file": missing}])
    return missing


@pytest.mark.postgres
def test_r6_revert_lesson_logs_in_from_the_secret_file_the_generation_records(
        world, tmp_path, caplog):  # noqa: F811 — the imported fixture
    """The revert reaches its login only past its store (#1278 Reverts: the revert claims a batch there), so the tenant
    is the world's: active in the database the CLI's store reads."""
    from defender.cli.learning import revert_lesson

    t = world.t
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
