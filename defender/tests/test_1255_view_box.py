"""#1255 slice B — the box's half of the model view, checked statically (CI has no box).

Design rev 4, "Model view (P1)": the box "mounts each tree at its model path. Working directory and
environment become constants: DEFENDER_RUN_DIR, DEFENDER_RUNS_BASE=/runs, DEFENDER_DIR,
DEFENDER_AGENT_DIR, PATH, PYTHONPATH." Twin-check paragraph: "CI also checks the box statically:
the box create command and its environment are identical for an arm and a natural run and contain
only model paths." And "Every mode": unboxed mode runs shims with the model-view environment
pointing into a per-run staging tree, "so the shims' environment never names the real runs folder,
which for an arm holds its siblings."

Entry surface: the real `start_box` (and, for the arm/natural pair, the real run lifecycle that
calls it), over a recording daemon double (`_1255_view.FakeDocker`) that refuses the create — so
the argv asserted is exactly what production would hand docker, and nothing after it runs.

What is masked, and why (O4 / daemon-only): the container name (derived from the run id), the
per-start token label, each bind SOURCE and the seccomp profile's host path. A source is the one
place a host path must appear — the daemon needs it — and it is not inside the box's view (the
`/proc/self/mountinfo` residual, U1, is the live suite's). Everything else must be byte-identical.
"""
from __future__ import annotations

import functools
import os
import subprocess
from pathlib import Path

import pytest

from defender._episode_handle import Episode
from defender._episodes_root import episode_dir
from defender.run_repository import RUN_LAYOUT
from defender.runtime import bash_exec
from defender.runtime import box as box_mod
from defender.runtime.box import BoxFault, BoxSpec
from defender.tests import _1255_view as V
from defender.tests import _tenants1106

ALERT = (Path(__file__).resolve().parents[1] / "fixtures-e2e" / "golden-sshpivot-ab3"
         / "alert.json").read_bytes()
SPEC = BoxSpec(runtime="runc", rootfs=V.STATIC_ROOTFS)
EPISODE_ID = "20261015t120000z-view-case-n7"


def _start(run_dir: Path, layout: V.Layout, docker: V.FakeDocker) -> None:
    """The run box's real start over `run_dir`, the layout's checkout and its tenant's agent
    half, stopped by the double at the create."""
    with pytest.raises(BoxFault, match="refused by the #1255 static check"):
        box_mod.start_box(run_dir, layout.checkout, spec=SPEC, docker=docker,
                          tenant_agent=layout.agent, tenant_id=layout.tenant.id)


def _created(run_dir: Path, layout: V.Layout) -> V.Create:
    docker = V.FakeDocker()
    _start(run_dir, layout, docker)
    return V.parse_create(docker.create)


# ---------------------------------------------------------------------------------------------
# B1 — mounts, workdir and env are the model view's constants
# ---------------------------------------------------------------------------------------------
def test_b1_the_run_box_mounts_each_tree_at_its_model_path(tmp_path):
    """P1 (Box bullet): the run folder is mounted at `/runs/current` (writable), its input
    directory over it at `/runs/current/alert_input` (read-only), the checkout at `/defender`
    (read-only) and the tenant's agent half at `/agent` (read-only). Each mount is found by its
    HOST source — the positive control that the create still binds the real trees — and its
    target is the design's literal. Today every target is the source's own host path (G1)."""
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
    assert create.target_of(layout.agent) == V.MODEL_AGENT, create.mounts
    assert create.readonly_of(layout.agent)


def test_b1_the_run_box_workdir_and_env_are_the_model_view_constants(tmp_path):
    """P1: `--workdir /runs/current`; `DEFENDER_RUN_DIR=/runs/current`, `DEFENDER_RUNS_BASE=/runs`
    (so invlang's corpus is the folder holding only `current`, H2), `DEFENDER_DIR=/defender`,
    `DEFENDER_AGENT_DIR=/agent`; the shims' folder `/defender/bin` is on `PATH` (the checkout's
    `bin/` as the box sees it). Today each names the host tree, and `DEFENDER_RUNS_BASE` the run
    folder's real parent (G1)."""
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-env")
    create = _created(run_dir, layout)

    assert create.workdir == V.MODEL_RUN, create.workdir
    for key, value in V.MODEL_ENV.items():
        assert key in create.env, f"{key} is not set on the box: {sorted(create.env)}"
        assert create.env[key] == value, f"{key}={create.env[key]!r}, expected {value!r}"
    assert f"{V.MODEL_DEFENDER}/bin" in create.env["PATH"].split(":"), create.env["PATH"]


def test_b1_o3_the_create_command_carries_no_host_layout_outside_its_bind_sources(tmp_path):
    """O3 over the static surface: with the daemon-only tokens masked (bind sources, seccomp
    profile path, container name, start token), the create argv names no data root, no tenant
    name, no checkout path and no home. Positive control on the same argv: UNmasked, the scanner
    finds this layout's data root and checkout (in the sources) — so an empty scan of the masked
    argv is a finding about the argv, not a blind scanner."""
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-o3")
    create = _created(run_dir, layout)
    tokens = V.host_tokens(layout)

    unmasked = " ".join(create.argv)
    assert V.scan(unmasked, [str(layout.data_root)]), "control: the sources name the data root"
    assert V.scan(unmasked, [str(layout.checkout)]), "control: the sources name the checkout"
    hits = V.scan(" ".join(V.masked_create(create.argv)), tokens)
    assert not hits, "the box create command shows host layout:\n" + "\n".join(hits)


# ---------------------------------------------------------------------------------------------
# B1 — host independence: two layouts, one command
# ---------------------------------------------------------------------------------------------
def test_b1_two_host_layouts_render_the_same_create_command(tmp_path):
    """P1 / O3: two hosts that differ in data root (and its depth), tenant name and checkout path
    (layout B's checkout is a mirror of this one at another path) render the SAME create command
    once the daemon-only tokens are masked: same targets, same workdir, same env, same image.
    Positive control: the unmasked argvs differ, and each one's sources name its own data root —
    the two layouts really are different hosts to the builder."""
    a = V.make_layout(tmp_path / "a", V.TENANT_A)
    b = V.make_layout(tmp_path / "b" / "deeper" / "still",
                      V.TENANT_B, checkout=V.mirror_checkout(tmp_path / "b" / "elsewhere" / "src"))
    run_id = "20261015t120000z-view-two"
    ca = _created(V.natural_run(a, ALERT, run_id), a)
    cb = _created(V.natural_run(b, ALERT, run_id), b)

    assert ca.argv != cb.argv, "control: the two hosts' raw create commands must differ"
    assert V.scan(" ".join(ca.argv), [str(a.data_root)])
    assert V.scan(" ".join(cb.argv), [str(b.data_root)])
    ma, mb = V.masked_create(ca.argv), V.masked_create(cb.argv)
    assert ma == mb, (
        "the create command depends on the host layout:\n"
        + "\n".join(f"  A: {x}\n  B: {y}" for x, y in zip(ma, mb, strict=False) if x != y))
    assert ca.env == cb.env, {k: (ca.env.get(k), cb.env.get(k))
                              for k in set(ca.env) | set(cb.env)
                              if ca.env.get(k) != cb.env.get(k)}


# ---------------------------------------------------------------------------------------------
# B1 — an arm and a natural run: one command
# ---------------------------------------------------------------------------------------------
def _arm_run(layout: V.Layout, tmp_path: Path, monkeypatch) -> object:
    """An arm's run handle, made where the episode owner places arms: the episode created under
    the configured episodes root, its container made for the tenant (the launcher's step), the
    arm `b` created through the episode's runs view. The folder gets the source's alert, as an
    arm's materialisation leaves it (the alert input is what the box binds read-only)."""
    from defender.tests import _alert_plant

    monkeypatch.setenv("DEFENDER_EPISODES_BASE", str(tmp_path / "episodes-root"))
    ep_dir = episode_dir(layout.data_root, EPISODE_ID)
    ep_dir.parent.mkdir(parents=True, exist_ok=True)
    with Episode.create(ep_dir) as episode:
        view = layout.tenant.runs_repository().episode(EPISODE_ID, held=episode)
        view.create_container()
        arm = view.create(view.arm_id("b"))
    Path(arm.run_dir).mkdir()
    _alert_plant.plant_alert(Path(arm.run_dir), ALERT)
    return arm


def _lifecycle_create(run, layout: V.Layout) -> V.Create:
    """The create command the production run lifecycle hands docker for `run`: the lifecycle
    resolves what to bind (the run's folder, the checkout, the tenant's agent half) and calls
    `start_box`; the double refuses the create, so the investigation never runs."""
    from defender import run as run_mod

    docker = V.FakeDocker()

    def investigate(**_kw):
        raise AssertionError("the box was refused; the investigation must not run")

    with pytest.raises(BoxFault, match="refused by the #1255 static check"):
        run_mod._run_investigation_lifecycle(
            run=run, model="m", model_override=None, defender_dir=layout.checkout,
            tenant=_tenants1106.run_tenant(layout.tenant),
            investigate=investigate,
            start_box=functools.partial(box_mod.start_box, spec=SPEC, docker=docker),
            stop_box=lambda *a, **k: None, scrub=lambda *a, **k: None)
    return V.parse_create(docker.create)


def test_b1_o2_an_arm_and_a_natural_run_get_the_same_create_command(tmp_path, monkeypatch):
    """O1 / O2 / P1 (twin-check paragraph's static check): through the production lifecycle, an
    arm (its folder inside an episode's container) and a natural run (its folder in the tenant's
    runs folder) get the same create command once O4's fresh ids and the daemon-only tokens are
    masked — and no episode id or arm label appears in it. Positive control: the arm's unmasked
    argv does carry the episode id (its bind source sits under the episode), so the channel can
    show arm identity and the masked equality is a finding about what reaches the box.

    The masked sources are then held host-side (O1's "files in read scope"; F2-T2): the arm's
    box binds the same checkout and the same tenant agent half as the natural run's, and its
    own run folder where the natural run's is bound — so an arm-specific tree (a staged copy of
    the agent half carrying an arm notice) cannot hide behind the mask."""
    from defender import run_common

    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    staged = tmp_path / "alert.json"
    staged.write_bytes(ALERT)
    natural = run_common.materialize_run(staged, "20261015t120000z-view-nat", tenant=layout.tenant)
    arm = _arm_run(layout, tmp_path, monkeypatch)

    cn = _lifecycle_create(natural, layout)
    ca = _lifecycle_create(arm, layout)

    assert V.scan(" ".join(ca.argv), [EPISODE_ID]), "control: the arm's sources name its episode"
    # Host side (finding F2-T2): the masked comparison below hides every bind SOURCE, so alone it
    # cannot tell an arm handed its own copy of a tree from one handed the tree itself. Under
    # one layout, what the arm's box binds where the natural run's binds the checkout and the
    # tenant's agent half is that same checkout and agent half (P1's table: `/defender` is the
    # checkout, `/agent` the tenant's agent half) — and, once the masked commands agree, each
    # run's own folder is bound where the other's is.
    for tree, source in (("checkout", layout.checkout), ("tenant's agent half", layout.agent)):
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


# ---------------------------------------------------------------------------------------------
# B5 — the unboxed fallback's environment
# ---------------------------------------------------------------------------------------------
def _env_of(box) -> dict[str, str]:
    """The environment the executor runs a program under, observed by running `env` through it
    (the executor's own transport, not its fields)."""
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
    """P1 "Every mode" (and N5: the env rule holds even where O3 is not measured): when the box
    cannot start and the operator opted into `DEFENDER_ALLOW_UNSANDBOXED=1`, `start_box` returns
    the host executor — and the environment its programs run under is the model view over a
    per-run staging tree laid out as `runs/current`, `defender`, `agent`: `DEFENDER_RUN_DIR` ends
    `runs/current`, `DEFENDER_RUNS_BASE` is its parent, `DEFENDER_DIR` and `DEFENDER_AGENT_DIR` are
    the staging root's `defender` and `agent`. No DEFENDER_* value names the tenant's real runs
    folder (which, for an arm, holds its siblings) or the run's real folder. The staged
    `defender` and `agent` hold the run's checkout and the tenant's half: `agent/.tenant-id`
    reads the accepted tenant and the staged `defender-lessons --tags` answers as the checkout's
    does. Positive control: the env is observed (it carries `DEFENDER_RUNS_BASE` at all). Today it
    is `run_env`'s host env: `DEFENDER_RUNS_BASE` IS the real runs folder."""
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    layout = V.make_layout(tmp_path / "a", V.TENANT_A)
    run_dir = V.natural_run(layout, ALERT, "20261015t120000z-view-unboxed")
    box = box_mod.start_box(run_dir, layout.checkout, spec=SPEC, docker=V.FakeDocker(),
                            tenant_agent=layout.agent, tenant_id=layout.tenant.id)
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
    # The staging tree holds THIS run: its alert is where the model view says it is.
    assert (run_view / RUN_LAYOUT.alert_input_dir / "alert.json").is_file(), (
        "the staging tree's runs/current does not hold the run's alert")
    # No sibling run folder beside it (a runs-base record file would be harmless; a folder is
    # a case invlang's corpus walk would read).
    folders = {e.name for e in os.scandir(run_view.parent) if e.is_dir()}
    assert folders == {"current"}, f"the staging runs folder holds more than this run: {folders}"
    # The staged `defender` and `agent` hold the run's checkout and the tenant's half (R2-B3),
    # observed through the executor as a shim would: the tenant identity file reads the accepted
    # tenant, and `defender-lessons --tags`, run from the staged checkout, answers what the run's
    # checkout answers (computed here by running the checkout's own shim with the host env).
    ident = _run(box, f"cat {env['DEFENDER_AGENT_DIR']}/.tenant-id")
    assert ident.rc == 0, ident
    assert ident.out.decode("utf-8").strip() == layout.tenant.id, ident.out
    staged_tags = _run(box, f"{env['DEFENDER_DIR']}/bin/defender-lessons --tags")
    assert staged_tags.rc == 0, staged_tags
    direct = subprocess.run(
        [str(layout.checkout / "bin" / "defender-lessons"), "--tags"], capture_output=True,
        timeout=60, env={**os.environ, "DEFENDER_DIR": str(layout.checkout)}, check=True)
    assert direct.stdout, "control: the checkout's own shim enumerates its tags"
    assert staged_tags.out == direct.stdout, (
        "the staged defender tree does not answer as the run's checkout does")


# ---------------------------------------------------------------------------------------------
# C9/C11 — MAIN's write lane at the tool boundary
# ---------------------------------------------------------------------------------------------
def test_b2_c9_mains_write_lane_lands_a_model_path_and_refuses_a_host_path(tmp_path):
    """C9 (inbound mapping reachable from deps built by `bind`) + C11 (host paths are refused):
    MAIN's path-taking write handlers (`write_file`, `edit_file` — the lane `investigation.md`
    is written through when a path is named) land a MODEL path (`/runs/current/investigation.md`)
    on the host file, and refuse the same call spelled with the host path, writing nothing.
    Positive control on the same channel: the relative spelling, which holds before and after.
    Today the host spelling lands and the model spelling is refused as outside the read roots."""
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

    # Control (holds today): the relative spelling writes the run's investigation.md.
    runtime_tools._tool_write_file(deps, RUN_LAYOUT.investigation.as_posix(), "+ a\n")
    assert inv.read_text(encoding="utf-8") == "+ a\n", "control: the write lane wrote nothing"

    # The host spelling is refused, and nothing is written.
    with pytest.raises(ModelRetry):
        runtime_tools._tool_write_file(deps, host_inv, "+ a\n+ host\n")
    assert inv.read_text(encoding="utf-8") == "+ a\n", "a refused host-path write landed"
    with pytest.raises(ModelRetry):
        runtime_tools._tool_edit_file(deps, host_inv, "+ a\n", "+ a\n+ host\n")
    assert inv.read_text(encoding="utf-8") == "+ a\n", "a refused host-path edit landed"

    # The model spelling lands on the host file, and the answer names what the model typed.
    said = runtime_tools._tool_write_file(deps, model_inv, "+ a\n+ b\n")
    assert inv.read_text(encoding="utf-8") == "+ a\n+ b\n", "the model-path write did not land"
    assert str(tmp_path) not in said, f"the write's answer names a host path: {said}"
    runtime_tools._tool_edit_file(deps, model_inv, "+ b\n", "+ b\n+ c\n")
    assert inv.read_text(encoding="utf-8") == "+ a\n+ b\n+ c\n", "the model-path edit did not land"
