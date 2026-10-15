"""O3: real run lifecycle refuses a wrong agent mount before the model's first request.

The host's accepted Tenant and the bytes visible through Docker are independent inputs.
No production setup is stubbed; only the existing start_box docker= and replay model seams
are injected. Request/drain and oracle lanes remain usable without any tenant agent half.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender import run as run_py
from defender.runtime import box as box_mod
from defender.runtime.box_codec import BOX_ENV_ALLOWLIST, BoxFault
from defender.tests import _tenants1106 as T
from defender.tests._spec1077 import fixture_run
from defender.tests._spec1092 import STOCK_ROOTFS, make_run_dir, plant_tree
from defender.tests.e2e import _replay_harness as R
from defender.tests.tenant_1108_p2._support import AgentReadDocker, MountedReadDocker, start_with, tree_bytes

pytestmark = pytest.mark.e2e


@pytest.fixture(autouse=True)
def clean_box_env(monkeypatch):
    monkeypatch.delenv('DEFENDER_ALLOW_UNSANDBOXED', raising=False)
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    # Inherited/stale shell values cannot select the agent path for a different run.
    monkeypatch.setenv('DEFENDER_AGENT_DIR', '/wrong/inherited/agent')


@pytest.fixture
def scene(tmp_path):
    tenant = T.fixture_tenant()
    run_tenant = T.run_tenant(tenant)
    run_dir = R.materialize(tmp_path / 'replay', R.GOLDEN_AB3)
    return tenant, run_tenant, run_dir


def _lifecycle(scene, docker, main, *, observed_env=None):
    tenant, run_tenant, run_dir = scene
    run = fixture_run(run_dir)

    def investigate(**kw):
        assert kw['run'] is run
        handed_run = kw['run']
        if observed_env is not None:
            from defender.runtime.bash_exec import parse
            command = 'printenv DEFENDER_AGENT_DIR'
            result = kw['box'].run_parsed(parse(command), command=command,
                                          cwd=handed_run.run_dir, timeout=10)
            observed_env.append(result.out.decode().strip())
        return R.drive(handed_run.run_dir, run_id=str(handed_run.id), main=main,
                       tenant=tenant, box=kw['box'])

    return run_py._run_investigation_lifecycle(
        run=run, model='test-model', model_override=None,
        defender_dir=T.DEFENDER, tenant=run_tenant, investigate=investigate,
        start_box=start_with(docker), stop_box=box_mod.stop_box,
    )


@pytest.mark.parametrize('ending', ['', '\n', '\r\n'])
def test_matching_identity_is_read_only_and_precedes_message_zero(scene, ending):
    """O3 positive: all three accepted tenant-id endings work through the box read-back."""
    tenant, _, _ = scene
    (tenant.agent / '.tenant-id').write_bytes((tenant.id + ending).encode())
    before = tree_bytes(tenant.agent)
    docker = AgentReadDocker(tenant.agent)
    main = R.ReplayFn([R.Turn(text='done')])
    _lifecycle(scene, docker, main)
    assert main.calls == 1, 'right identity must permit the model request'
    assert len(docker.identity_reads) == 1, 'run start never read the mounted identity'
    assert docker.identity_reads[0][-1] == str(tenant.agent / '.tenant-id')
    assert all(snapshot == before for snapshot in docker.snapshots)
    assert tree_bytes(tenant.agent) == before, 'startup dirtied the tenant clone'
    assert [m for m in docker.mounts() if m['source'] == str(tenant.agent)] == [
        {'source': str(tenant.agent), 'target': str(tenant.agent), 'readonly': True}]
    assert 'DEFENDER_AGENT_DIR' in BOX_ENV_ALLOWLIST
    assert docker.env()['DEFENDER_AGENT_DIR'] == str(tenant.agent)


@pytest.mark.parametrize('contents', [
    'another-tenant\n', '', ' fixture\n', 'fixture \n', 'fixture\n\n',
    '\ufefffixture\n', 'fixture\r', 'fixture\nother\n', 'x' * 129,
    None, b'\xff', 'directory', 'symlink',
], ids=['wrong-id', 'empty', 'leading-space', 'trailing-space', 'second-newline',
        'bom', 'bare-cr', 'second-line', 'oversize', 'missing', 'invalid-utf8', 'directory', 'symlink'])
def test_wrong_or_malformed_box_identity_refuses_before_message_zero(scene, tmp_path, contents):
    """O3/D3: wrong mounts and every tenant-id format partition fail closed before spending."""
    tenant, _, _ = scene
    wrong = tmp_path / 'daemon-mapped-agent'
    wrong.mkdir()
    if contents == 'directory':
        (wrong / '.tenant-id').mkdir()
    elif contents == 'symlink':
        (wrong / '.tenant-id').symlink_to(tenant.agent / '.tenant-id')
    elif contents is not None:
        # Use the actual accepted id so whitespace/format cases cannot pass as just mismatch.
        data = contents if isinstance(contents, bytes) else contents.replace('fixture', str(tenant.id)).encode()
        (wrong / '.tenant-id').write_bytes(data)
    before = tree_bytes(tenant.agent)
    docker = AgentReadDocker(tenant.agent, inside=wrong)
    main = R.ReplayFn([R.Turn(text='must never be requested')])
    with pytest.raises((BoxFault, SystemExit, run_py._tenant.TenantRefused)) as caught:
        _lifecycle(scene, docker, main)
    assert main.calls == 0, 'identity refusal came after message zero'
    diagnostic = str(caught.value)
    assert '.tenant-id' in diagnostic, 'refusal must name the failing identity file'
    if contents == 'another-tenant\n':
        assert 'another-tenant' in diagnostic, 'mismatch must report the found tenant'
        assert str(tenant.id) in diagnostic, 'mismatch must report the expected tenant'
    elif contents is None:
        assert any(word in diagnostic.lower() for word in ('missing', 'no such', 'could not read'))
    elif contents in ('directory', 'symlink'):
        assert any(word in diagnostic.lower() for word in ('regular', 'directory', 'link', 'could not read'))
    elif contents == 'x' * 129:
        assert any(word in diagnostic.lower() for word in ('128', 'larger', 'size', 'bytes'))
    elif isinstance(contents, bytes):
        assert any(word in diagnostic.lower() for word in ('utf', 'encoding', 'decode', 'exactly', '\\xff'))
    else:
        assert any(word in diagnostic.lower() for word in (
            'exactly', 'line ending', 'line', 'format', 'whitespace', 'space', 'empty', 'bom'))
    assert len(docker.identity_reads) == 1, 'host-side acceptance cannot prove a daemon bind'
    assert all(snapshot == before for snapshot in docker.snapshots)
    assert tree_bytes(tenant.agent) == before


@pytest.mark.parametrize('contents', ['right', 'another-tenant\n', None, 'directory'])
def test_explicit_unsandboxed_lane_reads_the_accepted_path_before_message_zero(
        scene, monkeypatch, contents):
    """O3 opt-out: after acceptance, a host read of the same path proves the expected id."""
    tenant, _, _ = scene
    marker = tenant.agent / '.tenant-id'
    marker.unlink()
    if contents == 'right':
        marker.write_bytes((tenant.id + '\r\n').encode())
    elif contents == 'directory':
        marker.mkdir()
    elif contents is not None:
        marker.write_text(contents, encoding='utf-8')
    before = tree_bytes(tenant.agent)
    monkeypatch.setenv('DEFENDER_ALLOW_UNSANDBOXED', '1')
    docker = AgentReadDocker(tenant.agent, fail_create=True)
    main = R.ReplayFn([R.Turn(text='done')])
    if contents == 'right':
        observed_env = []
        _lifecycle(scene, docker, main, observed_env=observed_env)
        assert main.calls == 1
        assert observed_env == [str(tenant.agent)], 'fallback subprocess inherited the wrong agent path'
    else:
        with pytest.raises((BoxFault, SystemExit, run_py._tenant.TenantRefused)) as caught:
            _lifecycle(scene, docker, main)
        diagnostic = str(caught.value)
        assert '.tenant-id' in diagnostic
        if contents == 'another-tenant\n':
            assert 'another-tenant' in diagnostic
            assert str(tenant.id) in diagnostic
        elif contents is None:
            assert any(word in diagnostic.lower() for word in ('missing', 'no such', 'could not read'))
        else:
            assert any(word in diagnostic.lower() for word in ('regular', 'directory', 'could not read'))
        assert main.calls == 0
    assert docker.identity_reads == [], 'an unboxed lane cannot prove identity through Docker'
    assert tree_bytes(tenant.agent) == before


def test_box_request_and_oracle_lanes_do_not_require_a_run_tenant(tmp_path):
    """P2 scope: neither existing non-run lane gains an agent mount or identity requirement."""
    from defender.runtime.box._oracle import oracle_box_request

    root = tmp_path / 'learning-worktree'
    root.mkdir()
    scratch = tmp_path / 'oracle-scratch'
    runner = tmp_path / 'oracle-runner'
    scratch.mkdir()
    runner.mkdir()
    requests = [box_mod.BoxRequest(
        name='defender-drain-p2', workdir=root, env={},
        mounts=(box_mod.Mount(source=root, target=root),),
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


def test_daemon_path_translation_preserves_the_run_process_agent_target(tmp_path):
    """D2: translate only the bind source under DooD; target/env keep Tenant.agent spelling."""
    defender_dir = plant_tree(tmp_path / 'tree', copy_code=False)
    run_dir = make_run_dir(tmp_path / 'runs')
    agent = tmp_path / 'tenants' / 'acme' / 'knowledge' / 'agent'
    agent.mkdir(parents=True)
    shared = ((tmp_path, Path('/daemon/shared')),)
    create = box_mod._create_argv('defender-run-p2', run_dir, defender_dir,
                                 box_mod.BoxSpec(rootfs=STOCK_ROOTFS), shared,
                                 tenant_agent=agent)
    expected = Path('/daemon/shared') / agent.relative_to(tmp_path)
    assert f'type=bind,source={expected},target={agent},readonly' in create.argv


def test_orient_host_shims_receive_the_run_tenants_agent_path(scene, monkeypatch):
    """D1 env wiring: host-side ORIENT shims receive Tenant.agent, before content re-root P4."""
    tenant, _, run_dir = scene
    monkeypatch.setenv('DEFENDER_AGENT_DIR', '/wrong/inherited/agent')
    calls = []

    def shim(argv, env):
        calls.append((list(argv), dict(env)))
        return 'P2-ORIENT-SHIM-CONTROL' if argv[:2] == ['defender-lessons', '--tags'] else ''

    main = R.ReplayFn([R.Turn(text='done')])
    R.drive(run_dir, run_id='p2-orient-env', main=main, tenant=tenant, orient_shim=shim)
    assert main.calls == 1
    assert calls, 'the actual orientation never invoked its shim runner'
    assert 'P2-ORIENT-SHIM-CONTROL' in main.seen[0], 'shim output never reached message zero'
    assert all(env.get('DEFENDER_AGENT_DIR') == str(tenant.agent) for _, env in calls)
