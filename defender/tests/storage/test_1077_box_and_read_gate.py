"""#1077 — O6's read gate and O7's box posture: what the name move must not weaken."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from defender.tests.support.shared.contracts import _spec1077 as S
from defender.tests.support.shared.contracts._by_path import DEFENDER
from defender.tests.support.storage._alert_plant import plant_alert


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    made = S.seed_run_tree(S.make_run_dir(S.make_runs_base(tmp_path)))
    plant_alert(made)
    return made


@pytest.fixture
def worktree(tmp_path: Path) -> Path:
    """A defender tree that is NOT this process's own checkout."""
    tree = tmp_path / "worktree" / "defender"
    (tree / "skills").mkdir(parents=True)
    from defender._paths import PATHS
    shutil.copytree(PATHS.defender_dir / "integrations", tree / "integrations")
    # The corpus-author role binds to a per-spawn corpus under the tree; give it one to name.
    (tree / "lessons").mkdir()
    return tree


def _policies(run_dir: Path, defender_dir: Path) -> dict[str, object]:
    """Every registered role's compiled policy — the enumeration picks the subjects."""
    from defender.agents import AGENTS
    from defender.investigation.agent_definition import RunScope, compile_policy_for
    from defender._agent_role import AgentRole
    from defender.tests.support.tenancy import _tenants1106
    # #1106 M4: gather binds with a RUN's grant (its definition carries none), as the driver does.
    defs = {role: (_tenants1106.fixture_gather_def() if role is AgentRole.GATHER else defn)
            for role, defn in AGENTS.items()}
    # A role that requires a per-spawn corpus (`requires_corpus`) refuses the default scope by
    # design; the enumeration hands it one so every role is reached.
    return {
        role.name: compile_policy_for(
            defn, run_dir=run_dir, defender_dir=defender_dir,
            scope=(RunScope(corpus_name="lessons", read_confine=(defender_dir / "lessons",))
                   if defn.requires_corpus else RunScope()))
        for role, defn in defs.items()}


def test_the_six_per_name_denies_hold_for_every_role(run_dir, worktree):
    from defender.records import CASE_ANSWER_KEY_NAMES, RUN_LAYOUT
    from defender.investigation import permission

    owner = S.RunPaths(run_dir)
    subjects = {
        "gather_raw by shape": owner.gather_raw / "not-a-lead-shape" / "x.json",
        "wire_logs/ outright": owner.wire_log,
        "provenance.json outright": owner.provenance,
        "case answer key": run_dir / sorted(CASE_ANSWER_KEY_NAMES)[0],
        "denylist": run_dir / ".env",
        "payload read cap": owner.ticket_read(0),
    }
    assert subjects["provenance.json outright"].name == RUN_LAYOUT.provenance.name
    assert str(RUN_LAYOUT.wire_log_dir) in subjects["wire_logs/ outright"].parts

    policies = _policies(run_dir, worktree)
    assert len(policies) >= 8, f"the roster is thin: {sorted(policies)}"
    allowed: list[str] = []
    for role, policy in policies.items():
        for why, path in subjects.items():
            if why == "payload read cap":
                # The cap is not a refusal but a bound: the payload is READ under a smaller cap.
                assert permission.is_captured_payload(path), (
                    f"{role}: the cap no longer recognises the captured payload by name")
                continue
            if why == "case answer key" and not getattr(policy, "read_confine", None):
                continue      # the answer-key deny is scoped to CONFINED roles
            decision = permission.decide_read(
                path, run_dir=run_dir, defender_dir=worktree, policy=policy)
            if decision.allow:
                allowed.append(f"{role} may read {why} ({path})")
    assert allowed == [], "\n".join(allowed)

    main = policies["MAIN"]
    assert permission.decide_read(
        run_dir / "alert.json", run_dir=run_dir, defender_dir=worktree, policy=main).allow, (
        "positive control: the alert is deliberately NOT in the answer key "
        "(`records/_layout.py`'s answer-key names) and stays readable")
    well_shaped = owner.payload("l-abc123", 0)
    well_shaped.parent.mkdir(parents=True, exist_ok=True)
    well_shaped.write_text("{}\n", encoding="utf-8")
    gather = policies["GATHER"]
    assert permission.decide_read(
        well_shaped, run_dir=run_dir, defender_dir=worktree, policy=gather).allow, (
        "positive control: the gather-raw deny is BY SHAPE — a well-shaped payload is admitted "
        "for the role that must `cat` it (O8), so the shape arm above is not a blanket refusal")


def test_the_box_keeps_network_none_and_one_rw_bind(run_dir):
    """The box still runs with `--network none` and the run dir as its one read-write bind."""
    from defender.box._lifecycle import _create_argv, _run_lane_mounts
    from defender.box._spec import BoxSpec

    argv = _create_argv("defender-run-1077", run_dir, DEFENDER, BoxSpec(), (), lane=_run_lane_mounts(run_dir, DEFENDER, None)).argv
    joined = " ".join(argv)
    assert argv[argv.index("--network") + 1] == "none", (
        "N7: the box's network stays `none`; a future store's client is the driver process")
    assert "--read-only" in argv

    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
    writable = [m for m in mounts if "readonly" not in m]
    assert len(writable) == 1, f"the box has more than one read-write bind: {writable}"
    # #1255 (design rev 4, P1) flipped the TARGETS to the model view: the run folder is bound at
    # `/runs/current`, the checkout at `/defender`; the SOURCES still name this host's trees.
    assert f"source={run_dir}," in writable[0], ("N1: the handle does not hide the filesystem from the box — the run-dir layout is a "
        "wire protocol with the model, and the run dir stays its one rw bind (at /runs/current)")
    assert "target=/runs/current" in writable[0], ("N1: the handle does not hide the filesystem from the box — the run-dir layout is a "
        "wire protocol with the model, and the run dir stays its one rw bind (at /runs/current)")
    readonly = [m for m in mounts if "readonly" in m]
    assert any(f"source={DEFENDER}," in m and "target=/defender," in m for m in readonly)
    assert any(f"source={run_dir / 'alert_input'}," in m
               and "target=/runs/current/alert_input," in m for m in readonly)
    from defender.tests.support.runtime.state._1255_view import MODEL_ROOTS

    extra = [m for m in readonly
             if not any(f"target={t}," in m or f"target={t}/" in m for t in MODEL_ROOTS)]
    named = [m for m in readonly if m not in extra]
    assert len(named) == 2, named
    assert len(extra) <= 1, f"more than the clock's one extra read-only bind: {extra}"
    for m in mounts:
        source = Path(m.split("source=")[1].split(",")[0])
        target = Path(m.split("target=")[1].split(",")[0])
        bound_the_base = (
            f"the RUNS BASE itself is bound ({m}); only the run dir is, which is what makes "
            "the tenant record beside it unreachable from inside a box (demand d49)")
        assert source != run_dir.parent, bound_the_base
        assert target != run_dir.parent, bound_the_base
        assert target != Path("/runs"), bound_the_base  # the model view's runs base (#1255)
    assert "--cap-add" not in joined
    assert "--privileged" not in joined


def test_the_box_entrypoint_closure_imports_the_owner_without_pydantic():
    from defender._paths import PATHS
    from defender.tests.support.shared.contracts._import_blocker import run_blocked

    done = run_blocked(
        "import sys\n"
        "import defender.records as rp\n"
        "assert rp.BOX_SENTINEL, 'the owner does not name the sentinel'\n"
        "import dataclasses\n"
        "assert dataclasses.is_dataclass(rp.RunPaths), 'RunPaths is not a stdlib dataclass'\n"
        "assert 'pydantic' not in sys.modules, sorted(m for m in sys.modules if 'pyd' in m)\n"
        "print('OK')\n",
        block=("pydantic", "pydantic_ai", "pydantic_core"), cwd=PATHS.repo_root)
    assert done.returncode == 0, (
        f"claim C4: `RunPaths` uses `@model` (pydantic) today while `_io.py` uses a stdlib "
        f"dataclass, so D1's conversion is a real constraint, not a formality:\n{done.stderr!r}")
    assert b"OK" in done.stdout
