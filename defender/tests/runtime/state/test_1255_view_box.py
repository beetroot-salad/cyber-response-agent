"""Check model-view mounts, environment, host independence, and unboxed execution."""
from __future__ import annotations

import dataclasses

from defender.tests.support.shared._locations_1210 import location_path

import functools
import os
import subprocess
from pathlib import Path

import pytest

from defender.episodes._episode_handle import Episode
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.records import RUN_LAYOUT
from defender.execution import bash_exec
from defender import box as box_mod
from defender.box import BoxFault, BoxSpec
from defender.tests.support.runtime.state import _1255_view as V
from defender.tests.support.tenancy import _tenants1106

ALERT = (Path(__file__).resolve().parents[3] / "tests" / "fixtures" / "e2e" / "golden-sshpivot-ab3"
         / "alert.json").read_bytes()
SPEC = BoxSpec(runtime="runc", rootfs=V.STATIC_ROOTFS)
EPISODE_ID = fixture_uuid("20261015t120000z-view-case-n7")


def _start(run_dir: Path, layout: V.Layout, docker: V.FakeDocker) -> None:
    """Record a real box create for this layout, then refuse it before execution."""
    agent, token = layout.staged()
    with pytest.raises(BoxFault, match="refused by the #1255 static check"):
        box_mod.start_box(run_dir, layout.checkout, spec=SPEC, docker=docker,
                          tenant_agent=agent, tenant_id=layout.tenant.id, staged_token=token)


def _created(run_dir: Path, layout: V.Layout) -> V.Create:
    docker = V.FakeDocker()
    _start(run_dir, layout, docker)
    return V.parse_create(docker.create)


def test_b1_the_run_box_uses_only_the_model_view(tmp_path):
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-box")
    create = _created(run_dir, layout)

    input_dir = run_dir / RUN_LAYOUT.alert_input_dir
    assert create.target_of(run_dir) is not None, (
        f"the run folder {run_dir} is not a bind source at all: {create.mounts}")
    assert create.target_of(run_dir) == V.MODEL_RUN, create.mounts
    assert not create.readonly_of(run_dir), "the run folder must stay the box's one writable tree"
    assert create.target_of(input_dir) == f"{V.MODEL_RUN}/{RUN_LAYOUT.alert_input_dir}", (
        create.mounts)
    assert create.readonly_of(input_dir)
    assert create.target_of(layout.checkout) == V.MODEL_DEFENDER, create.mounts
    assert create.readonly_of(layout.checkout)
    assert create.target_of(layout.staged()[0]) == V.MODEL_AGENT, create.mounts
    assert create.readonly_of(layout.staged()[0])


    assert create.workdir == V.MODEL_RUN, create.workdir
    for key, value in V.MODEL_ENV.items():
        assert key in create.env, f"{key} is not set on the box: {sorted(create.env)}"
        assert create.env[key] == value, f"{key}={create.env[key]!r}, expected {value!r}"
    assert f"{V.MODEL_DEFENDER}/bin" in create.env["PATH"].split(":"), create.env["PATH"]


    tokens = V.host_tokens(layout)

    unmasked = " ".join(create.argv)
    assert V.scan(unmasked, [str(location_path(layout.data_root))]), "control: the sources name the data root"
    assert V.scan(unmasked, [str(layout.checkout)]), "control: the sources name the checkout"
    hits = V.scan(" ".join(V.masked_create(create.argv)), tokens)
    assert not hits, "the box create command shows host layout:\n" + "\n".join(hits)


def test_b1_two_host_layouts_render_the_same_create_command(tmp_path):
    a = V.make_layout(tmp_path / "a", V.TENANT_A)
    b = V.make_layout(tmp_path / "b" / "deeper" / "still",
                      V.TENANT_B, checkout=V.mirror_checkout(tmp_path / "b" / "elsewhere" / "src"))
    # #1279 (A3): each host's setup mints its own run id, so the two commands also agree across
    # different ids (the name and the sources are masked).
    run_id = "20261015t120000z-view-two"
    ca = _created(V.natural_run(a, ALERT, run_id), a)
    cb = _created(V.natural_run(b, ALERT, run_id), b)

    assert ca.argv != cb.argv, "control: the two hosts' raw create commands must differ"
    assert V.scan(" ".join(ca.argv), [str(location_path(a.data_root))])
    assert V.scan(" ".join(cb.argv), [str(location_path(b.data_root))])
    ma, mb = V.masked_create(ca.argv), V.masked_create(cb.argv)
    assert ma == mb, (
        "the create command depends on the host layout:\n"
        + "\n".join(f"  A: {x}\n  B: {y}" for x, y in zip(ma, mb, strict=False) if x != y))
    assert ca.env == cb.env, {k: (ca.env.get(k), cb.env.get(k))
                              for k in set(ca.env) | set(cb.env)
                              if ca.env.get(k) != cb.env.get(k)}


def _arm_run(layout: V.Layout, tmp_path: Path, monkeypatch) -> object:
    """Create a materialized arm in the episode-owned runs container."""
    from defender.tests.support.storage import _alert_plant
    from defender import _yaml
    from defender.tests.support.learning.branch import _triplet_947 as T

    ep_dir = location_path(layout.data_root) / layout.tenant_id / "episodes" / EPISODE_ID
    ep_dir.parent.mkdir(parents=True, exist_ok=True)
    with Episode.create(ep_dir) as episode:
        episode.family.create(_yaml.safe_dump(T.family_doc(
            episode_id=EPISODE_ID, worlds=[T.world_doc("b", world_id=fixture_uuid("world:view-box:b"),
                                                       role="A", axis=None, facts=[])])))
        view = layout.tenant.runs_repository().episode(EPISODE_ID, held=episode)
        view.start_runs((fixture_uuid("world:view-box:b"),))
        arm = view.create(view.arm_id(fixture_uuid("world:view-box:b")))
    Path(arm.run_dir).mkdir()
    _alert_plant.plant_alert(Path(arm.run_dir), ALERT)
    return arm


def _lifecycle_create(run, layout: V.Layout) -> V.Create:
    """Record the create command emitted by the production run lifecycle."""
    from defender import run as run_mod

    docker = V.FakeDocker()

    def investigate(**_kw):
        raise AssertionError("the box was refused; the investigation must not run")

    with pytest.raises(BoxFault, match="refused by the #1255 static check"):
        run_mod._run_investigation_lifecycle(
            run=run, model="m", model_override=None, defender_dir=layout.checkout,
            tenant=dataclasses.replace(_tenants1106.run_tenant(layout.tenant),
                                       agent_root=layout.staged()[0],
                                       stage_token=layout.staged()[1]),
            investigate=investigate,
            start_box=functools.partial(box_mod.start_box, spec=SPEC, docker=docker),
            stop_box=lambda *a, **k: None, scrub=lambda *a, **k: None)
    return V.parse_create(docker.create)


def test_b1_o2_an_arm_and_a_natural_run_get_the_same_create_command(tmp_path, monkeypatch):
    from defender import run_common

    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    staged = tmp_path / "alert.json"
    staged.write_bytes(ALERT)
    natural = run_common.materialize_run(staged, tenant=layout.tenant)
    arm = _arm_run(layout, tmp_path, monkeypatch)

    cn = _lifecycle_create(natural, layout)
    ca = _lifecycle_create(arm, layout)

    assert V.scan(" ".join(ca.argv), [EPISODE_ID]), "control: the arm's sources name its episode"
    for tree, source in (("checkout", layout.checkout), ("tenant's agent half", layout.staged()[0])):
        target = cn.target_of(source)
        assert target is not None, (
            f"control: the natural run's box does not bind the {tree} {source}: {cn.mounts}")
        arm_sources = [s for s, t, _ in ca.mounts if t == target]
        assert arm_sources == [str(source)], (
            f"the arm's box binds {arm_sources} where the natural run's binds the {tree} "
            f"({source}) at {target}: an arm-specific tree")
    mn, ma = V.masked_create(cn.argv), V.masked_create(ca.argv)
    assert mn == ma, (
        "an arm's box differs from a natural run's:\n"
        + "\n".join(f"  natural: {x}\n  arm:     {y}" for x, y in zip(mn, ma, strict=False) if x != y))
    assert cn.target_of(Path(natural.run_dir)) is not None, cn.mounts
    assert ca.target_of(Path(arm.run_dir)) == cn.target_of(Path(natural.run_dir)), (
        "the arm's own run folder is not bound where the natural run's is", ca.mounts, cn.mounts)
    hits = V.scan(" ".join(ma), [EPISODE_ID])
    assert not hits, "arm identity reaches the box:\n" + "\n".join(hits)


def _env_of(box) -> dict[str, str]:
    """Observe the executor environment through its own env command."""
    res = box.run_parsed(bash_exec.parse("env"), command="env", cwd=Path("/"), timeout=30)
    assert res.rc == 0, res
    out: dict[str, str] = {}
    for line in res.out.decode("utf-8", "replace").splitlines():
        k, sep, v = line.partition("=")
        if sep:
            out[k] = v
    return out


def _run(box, command: str):
    """One command through the executor's own transport, from a neutral cwd."""
    return box.run_parsed(bash_exec.parse(command), command=command, cwd=Path("/"), timeout=60)


def test_b5_the_unboxed_fallback_never_hands_its_shims_the_real_runs_folder(tmp_path, monkeypatch):
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-unboxed")
    agent, token = layout.staged()
    box = box_mod.start_box(run_dir, layout.checkout, spec=SPEC, docker=V.FakeDocker(),
                            tenant_agent=agent, tenant_id=layout.tenant.id, staged_token=token)
    assert not box.sandboxed, "control: the fallback is the host executor"
    env = _env_of(box)

    assert "DEFENDER_RUNS_BASE" in env, f"control: the env was observed: {sorted(env)}"
    real_runs = str(run_dir.parent)
    leaked = {k: v for k, v in env.items() if k.startswith("DEFENDER_")
              and (real_runs in v or str(run_dir) in v)}
    assert not leaked, f"the unboxed shims are handed the real runs folder: {leaked}"
    run_view = Path(env["DEFENDER_RUN_DIR"])
    assert run_view.parts[-2:] == ("runs", "current"), env["DEFENDER_RUN_DIR"]
    assert env["DEFENDER_RUNS_BASE"] == str(run_view.parent), env["DEFENDER_RUNS_BASE"]
    stage = run_view.parent.parent
    assert env["DEFENDER_DIR"] == str(stage / "defender"), env["DEFENDER_DIR"]
    assert env["DEFENDER_AGENT_DIR"] == str(stage / "agent"), env["DEFENDER_AGENT_DIR"]
    assert (run_view / RUN_LAYOUT.alert_input_dir / "alert.json").is_file(), (
        "the staging tree's runs/current does not hold the run's alert")
    folders = {e.name for e in os.scandir(run_view.parent) if e.is_dir()}
    assert folders == {"current"}, f"the staging runs folder holds more than this run: {folders}"
    ident = _run(box, f"cat {env['DEFENDER_AGENT_DIR']}/.tenant-id")
    assert ident.rc == 0, ident
    assert ident.out.decode("utf-8").strip() == layout.tenant.id, ident.out
    staged_tags = _run(box, f"{env['DEFENDER_DIR']}/bin/defender-lessons --tags")
    assert staged_tags.rc == 0, staged_tags
    # #1108 P4 (O1, O4): the shim reads the lessons of the agent root `DEFENDER_AGENT_DIR`
    # names (the tenant's), never the checkout's, so the control names the same agent half the
    # box was handed (the staged view of it is what the box's own call reads).
    direct = subprocess.run(
        [str(layout.checkout / "bin" / "defender-lessons"), "--tags"], capture_output=True,
        timeout=60, env={**os.environ, "DEFENDER_DIR": str(layout.checkout),
                         "DEFENDER_AGENT_DIR": str(layout.agent)}, check=True)
    assert direct.stdout, "control: the checkout's own shim enumerates its tags"
    assert staged_tags.out == direct.stdout, (
        "the staged defender tree does not answer as the run's checkout does")


def test_b2_c9_mains_write_lane_lands_a_model_path_and_refuses_a_host_path(tmp_path):
    from pydantic_ai.exceptions import ModelRetry

    from defender.agents import MAIN_DEF
    from defender.runtime import tools as runtime_tools
    from defender.runtime.agent_definition import bind

    run, dfn = tmp_path / "run", tmp_path / "defender"
    run.mkdir()
    dfn.mkdir()
    deps = bind(MAIN_DEF, run, defender_dir=dfn)
    inv = run / RUN_LAYOUT.investigation
    host_inv = str(inv)
    model_inv = f"{V.MODEL_RUN}/{RUN_LAYOUT.investigation}"

    runtime_tools._tool_write_file(deps, RUN_LAYOUT.investigation.as_posix(), "+ a\n")
    assert inv.read_text(encoding="utf-8") == "+ a\n", "control: the write lane wrote nothing"

    with pytest.raises(ModelRetry):
        runtime_tools._tool_write_file(deps, host_inv, "+ a\n+ host\n")
    assert inv.read_text(encoding="utf-8") == "+ a\n", "a refused host-path write landed"
    with pytest.raises(ModelRetry):
        runtime_tools._tool_edit_file(deps, host_inv, "+ a\n", "+ a\n+ host\n")
    assert inv.read_text(encoding="utf-8") == "+ a\n", "a refused host-path edit landed"

    said = runtime_tools._tool_write_file(deps, model_inv, "+ a\n+ b\n")
    assert inv.read_text(encoding="utf-8") == "+ a\n+ b\n", "the model-path write did not land"
    assert str(tmp_path) not in said, f"the write's answer names a host path: {said}"
    runtime_tools._tool_edit_file(deps, model_inv, "+ b\n", "+ b\n+ c\n")
    assert inv.read_text(encoding="utf-8") == "+ a\n+ b\n+ c\n", "the model-path edit did not land"
