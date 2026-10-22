from __future__ import annotations

from defender.tests.support.shared._fixture_uuid import fixture_uuid

from pathlib import Path

import pytest

from defender import run as run_py
from defender import box as box_mod
from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.support.sandbox._spec1092 import STOCK_ROOTFS, make_run_dir, plant_tree
from defender.tests.tenancy.tenant_1108_p2._support import MountedReadDocker

pytestmark = pytest.mark.e2e


@pytest.fixture(autouse=True)
def clean_box_env(monkeypatch):
    monkeypatch.delenv('DEFENDER_ALLOW_UNSANDBOXED', raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    # Inherited/stale shell values cannot select the agent path for a different run.
    monkeypatch.setenv('DEFENDER_AGENT_DIR', '/wrong/inherited/agent')


# #1108 P4 (O-A) retired P2's in-box `.tenant-id` check and the `agent` mount kind: identity is
# checked once, at publish, and the box mounts the run copy's `agent/` plus a staged token. The
# P2 cases that pinned the retired check moved:
#   - test_matching_identity_is_read_only_and_precedes_message_zero  -> tenant_1108_p4/
#     test_run_copy.py::test_o_a_the_run_box_mounts_its_copys_agent_and_token_only_and_reads_the_token_back
#     (the `.tenant-id` ending partitions are the publish's, P3 `parse_tenant_id_bytes`);
#   - test_wrong_or_malformed_box_identity_refuses_before_message_zero -> tenant_1108_p4/
#     test_run_copy.py::test_o_a_a_box_bound_to_another_copy_refuses_before_message_zero
#     (a merged wrong `.tenant-id` -> test_publish_child.py, stale:operator);
#   - test_orient_host_shims_receive_the_run_tenants_agent_path -> tenant_1108_p4/
#     test_run_isolation_e2e.py::test_o2_the_opening_messages_orientation_shows_the_copys_lessons.
# The unsandboxed opt-out case is rewritten below onto the run copy.


def test_explicit_unsandboxed_lane_hands_its_programs_the_run_copy_not_an_inherited_path(
        tmp_path, data_root, monkeypatch):
    """O3 opt-out, re-rooted by #1108 P4 (O-A/O2): under the explicit unsandboxed opt-out the
    bash lane's `DEFENDER_AGENT_DIR` is neither the inherited shell value nor the tenant's
    clone, and the files it names are the run copy's (the clone's working tree holds a
    different, unpublished lesson). No identity file is re-read (identity is checked at
    publish)."""
    import functools

    from defender.execution.bash_exec import parse
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    monkeypatch.setenv('DEFENDER_ALLOW_UNSANDBOXED', '1')
    observed: list[tuple[str, bytes]] = []

    def investigate(**kw):
        command = 'printenv DEFENDER_AGENT_DIR'
        seen = kw['box'].run_parsed(parse(command), command=command, cwd=Path('/'),
                                    timeout=10).out.decode().strip()
        command = f'cat {seen}/{B.LESSON_REL}'
        lesson = kw['box'].run_parsed(parse(command), command=command, cwd=Path('/'),
                                      timeout=10).out
        observed.append((seen, lesson))
        return {'output': 'p2-opt-out', 'requests': 0, 'truncated_by': None}

    def no_daemon(argv, **_kw):
        raise FileNotFoundError('docker: no daemon in this test')

    with B.run_tenant(tmp_path, data_root) as t:
        (B.clone_dir(t) / B.LESSON).write_text(B.lesson_text(B.CLONE_ONLY_MARK), encoding='utf-8')
        lifecycle = functools.partial(
            run_py._run_investigation_lifecycle, investigate=investigate,
            start_box=functools.partial(box_mod.start_box, docker=no_daemon))
        out = B.launch(t, tmp_path, publish=lambda *a, **k: B.fresh(t.commit),
                       lifecycle=lifecycle)
        clone_agent = B.clone_dir(t) / 'agent'
    assert out.reached, out.text()
    assert out.rc == 0, out.text()
    ((seen, lesson),) = observed
    assert seen != '/wrong/inherited/agent', 'fallback subprocess inherited the wrong agent path'
    assert seen != str(clone_agent), 'the opt-out lane was handed the tenant clone'
    assert B.SEEDED_MARK.encode() in lesson, (
        f'the agent half the fallback hands its programs is not the run copy: {lesson[-200:]!r}')
    assert B.CLONE_ONLY_MARK.encode() not in lesson


def test_box_request_and_oracle_lanes_do_not_require_a_run_tenant(tmp_path):
    """P2 scope: neither existing non-run lane gains an agent mount or identity requirement."""
    import shutil

    from defender.box._oracle import _make_runner, oracle_box_request

    root = tmp_path / 'learning-worktree'
    root.mkdir()
    (root / 'defender').mkdir()
    check = box_mod.CODE_CHECK_FILE
    shutil.copyfile(T.DEFENDER / check, root / 'defender' / check)
    scratch = tmp_path / 'oracle-scratch'
    scratch.mkdir()
    # The oracle's runner as production makes it: whatever the code check needs must come
    # from the oracle's own RUNNER_FILES, never from this fixture.
    runner = _make_runner()
    try:
        requests = [box_mod.BoxRequest(
            name='defender-drain-p2', workdir=root, env={},
            mounts=(box_mod.Mount(source=root, target=root, kind='code'),),
            spec=box_mod.BoxSpec(rootfs=STOCK_ROOTFS)),
            oracle_box_request(scratch, runner, env={})]
        # Pin a stock image at the existing BoxRequest seam; no real Docker/image is needed.
        from dataclasses import replace
        for request in requests:
            request = replace(request, spec=box_mod.BoxSpec(rootfs=STOCK_ROOTFS))
            docker = MountedReadDocker()
            box = box_mod.start_box(request, docker=docker)
            assert box.sandboxed
            assert all('.tenant-id' not in ' '.join(call) for call in docker.calls)
            assert all('/tenant/agent' not in m['target'] for m in docker.mounts())
            assert docker.env().get('DEFENDER_AGENT_DIR', '') != '/wrong/inherited/agent'
            box_mod.stop_box(box)
    finally:
        shutil.rmtree(runner, ignore_errors=True)


def test_daemon_path_translation_preserves_the_run_process_agent_target(tmp_path):
    """D2: translate only the bind source under DooD; the target is the model view's `/agent`
    (#1255 P1 — it used to keep Tenant.agent's spelling)."""
    defender_dir = plant_tree(tmp_path / 'tree', copy_code=False)
    run_dir = make_run_dir(tmp_path / 'runs')
    agent = tmp_path / 'tenants' / fixture_uuid("tenant:acme") / 'knowledge' / 'agent'
    agent.mkdir(parents=True)
    shared = ((tmp_path, Path('/daemon/shared')),)
    create = box_mod._create_argv('defender-run-p2', run_dir, defender_dir,
                                 box_mod.BoxSpec(rootfs=STOCK_ROOTFS), shared,
                                 tenant_agent=agent)
    expected = Path('/daemon/shared') / agent.relative_to(tmp_path)
    assert f'type=bind,source={expected},target=/agent,readonly' in create.argv
