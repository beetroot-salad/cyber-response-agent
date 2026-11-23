from __future__ import annotations

import shlex
from pathlib import Path

import pytest

from defender.tests.support.tenancy import _tenants1106 as T
from defender.tests.e2e import _replay_harness as R

pytestmark = pytest.mark.e2e


@pytest.fixture
def read_scene(tmp_path):
    tenant = T.fixture_tenant()
    run_dir = R.materialize(tmp_path / 'replay', R.GOLDEN_AB3)
    return tenant, run_dir


def _put(root: Path, relative: str, marker: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(marker + '\n', encoding='utf-8')
    return path


def _agent(tenant) -> Path:
    """The tenant's agent half as this replay hands it to the driver: the half the test placed (#1618 K8: a `Tenant`
    names no knowledge path; `R.drive(tenant=...)` hands the driver `T.knowledge_half`, the placed folder)."""
    return T.placed_half(tenant, 'agent')


def _model(path: Path, *, tenant=None, run_dir: Path | None = None) -> str:
    for host, model in ((_agent(tenant) if tenant is not None else None, '/agent'), (T.DEFENDER, '/defender'),
                        (run_dir, '/runs/current')):
        if host is not None and Path(path).is_relative_to(host):
            return f"{model}/{Path(path).relative_to(host).as_posix()}"
    return str(path)


def _read_turn(surface, path):
    if surface == 'typed':
        return R.Turn(tool_calls=[('read_file', {'path': str(path)})])
    return R.Turn(tool_calls=[('bash', {'command': f'cat {shlex.quote(str(path))}'})])


def _drive_as(read_scene, role, turns):
    tenant, run_dir = read_scene
    model = R.ReplayFn([*turns, R.Turn(text='done')])
    if role == 'main':
        R.drive(run_dir, run_id='p2-read', main=model, tenant=tenant)
    else:
        main = R.ReplayFn([
            R.Turn(tool_calls=[('gather', {'lead_id': 'l-p2', 'system': 'cmdb',
                                          'goal': 'read tenant reference',
                                          'what_to_summarize': ['reference']})]),
            R.Turn(text='done')])
        R.drive(run_dir, run_id='p2-read', main=main, gather=model, tenant=tenant)
    assert model.calls == len(turns) + 1, 'the model never completed the observation sequence'
    return model


@pytest.mark.parametrize('role', ['main', 'gather'])
@pytest.mark.parametrize('surface', ['typed', 'bash'])
@pytest.mark.parametrize('relative', [
    'lessons/p2.md', 'skills/cmdb/SKILL.md', 'skills/gather/queries/cmdb/p2.md',
])
def test_own_tenant_corpus_reads_work_and_other_tenant_and_settings_reads_refuse(
        read_scene, tmp_path, role, surface, relative):
    """Same-path corpus bytes reach both roles and surfaces; other roots remain denied."""
    tenant, _ = read_scene
    mine = _put(_agent(tenant), relative, 'OWN-TENANT-P2-CONTENT')
    # This is just a neighboring physical tree; it need not bypass the one-tenant guard.
    other = _put(_agent(tenant).parents[2] / 'other' / 'knowledge' / 'agent',
                 relative, 'OTHER-TENANT-P2-CONTENT')
    settings = _put(T.placed_half(tenant, 'settings'), 'operator.md', 'SETTINGS-P2-CONTENT')
    checkout = T.DEFENDER / 'skills' / 'gather' / 'SKILL.md'
    checkout_mark = 'The query computes the answer server-side and returns it small and exact.'
    assert checkout_mark in checkout.read_text(encoding='utf-8')
    model = _drive_as(read_scene, role, [
        _read_turn(surface, _model(mine, tenant=tenant)), _read_turn(surface, other),
        _read_turn(surface, settings), _read_turn(surface, _model(checkout, tenant=tenant))])
    assert 'OWN-TENANT-P2-CONTENT' in model.seen[1], 'tenant read did not return its bytes'
    assert 'OTHER-TENANT-P2-CONTENT' not in '\n'.join(model.seen)
    assert 'Blocked' in model.seen[2], 'another tenant root was not explicitly refused'
    assert 'SETTINGS-P2-CONTENT' not in '\n'.join(model.seen)
    assert 'Blocked' in model.seen[3], 'settings half was not explicitly refused'
    assert checkout_mark in model.seen[4], 'a checkout file read did not return its bytes'


@pytest.mark.parametrize('role', ['main', 'gather'])
@pytest.mark.parametrize('surface', ['typed', 'bash'])
@pytest.mark.parametrize('relative', [
    'lessons/p2.env.md', 'skills/cmdb/tool.py',
    'skills/tacit-knowledge/registry.yaml', 'outside/p2.md',
])
def test_tenant_root_preserves_secret_extension_and_corpus_shape_denies(
        read_scene, role, surface, relative):
    """Adding a read root grants neither arbitrary files nor secrets."""
    tenant, _ = read_scene
    denied = _put(_agent(tenant), relative, 'DENIED-TENANT-P2-CONTENT')
    allowed = _put(_agent(tenant), 'lessons/control.md', 'CONTROL-TENANT-P2-CONTENT')
    model = _drive_as(read_scene, role, [_read_turn(surface, _model(denied, tenant=tenant)),
                                         _read_turn(surface, _model(allowed, tenant=tenant))])
    assert 'Blocked' in model.seen[1]
    assert 'DENIED-TENANT-P2-CONTENT' not in '\n'.join(model.seen)
    assert 'CONTROL-TENANT-P2-CONTENT' in model.seen[2], 'denial is not a blanket refusal'


@pytest.mark.parametrize('role', ['main', 'gather'])
@pytest.mark.parametrize('surface', ['typed', 'bash'])
def test_raw_payload_permissions_keep_the_existing_role_partition(read_scene, role, surface):
    """Adding tenant knowledge cannot hand MAIN the captured payloads GATHER owns."""
    tenant, run_dir = read_scene
    raw = _put(run_dir, 'gather_raw/l-abc123/0.json', 'ROLE-PAYLOAD-P2-CONTENT')
    allowed = _put(_agent(tenant), 'lessons/control.md', 'ROLE-CONTROL-P2-CONTENT')
    model = _drive_as(read_scene, role, [
        _read_turn(surface, _model(raw, tenant=tenant, run_dir=run_dir)),
        _read_turn(surface, _model(allowed, tenant=tenant))])
    if role == 'gather':
        assert 'ROLE-PAYLOAD-P2-CONTENT' in model.seen[1]
    else:
        assert 'Blocked' in model.seen[1]
        assert 'ROLE-PAYLOAD-P2-CONTENT' not in '\n'.join(model.seen)
    assert 'ROLE-CONTROL-P2-CONTENT' in model.seen[2]


def test_confined_curator_binding_keeps_tenant_knowledge_outside_its_read_scope(read_scene, tmp_path):
    """The confined learning role keeps its own corpus, without a global lift."""
    from defender.learning.author.curator_engine import CuratorDeps
    from defender import box as box_mod
    from defender.investigation import permission

    tenant, run_dir = read_scene
    repo = tmp_path / 'curator-worktree'
    tree = repo / 'defender'
    allowed = _put(tree, 'lessons/control.md', 'CURATOR-CONTROL-P2')
    denied = _put(_agent(tenant), 'lessons/p2.md', 'CURATOR-DENIED-P2')
    deps = CuratorDeps.for_run(run_dir, repo, allowed.parent,
                               box=box_mod.unboxed_executor())
    for path, expected in ((allowed, True), (denied, False)):
        assert permission.decide_read(path, run_dir=run_dir, defender_dir=tree,
                                      policy=deps.policy).allow is expected
        assert permission.decide_bash(f'cat {shlex.quote(str(path))}', policy=deps.policy,
                                      run_dir=run_dir, defender_dir=tree,
                                      cwd_anchor=deps.cwd_anchor).allow is expected
