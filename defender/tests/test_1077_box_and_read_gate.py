"""#1077 — O6's read gate and O7's box posture: what the name move must not weaken.

Carries 5 demands of `spec-flow/specs/spec_graph_1077.yaml`. The read gate's six per-name
denies key on exactly the names D1 moves onto the owner, so the move is the moment they could
silently stop holding; the box's posture is what the security dive's universal (4) rests on
when it says the tenant record cannot be planted from inside a box.

Cluster N was RESOLVED at §7 (decision 17) by keeping the six denials FILENAME-based, exactly
as today: this issue discharges the obligation it inherited as stated and grows no
content/inode-level checking machinery. The hard-link evasion is therefore out of scope BY
DECISION, not by omission — it is a follow-up GitHub issue, and this file deliberately pins no
content-based check.
"""
from __future__ import annotations

import subprocess
import sys
import shutil
from pathlib import Path

import pytest

from defender.tests import _spec1077 as S
from defender.tests._by_path import DEFENDER


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    return S.seed_run_tree(S.make_run_dir(S.make_runs_base(tmp_path)))


@pytest.fixture
def worktree(tmp_path: Path) -> Path:
    """A defender tree that is NOT this process's own checkout.

    `compile_policy_for(VERIFIER_DEF, …)` refuses a `PATHS` tree by design — a policy anchored
    on the main checkout would author it rather than the worktree — so the role enumeration
    cannot use the real one and still reach every role.
    """
    tree = tmp_path / "worktree" / "defender"
    (tree / "skills").mkdir(parents=True)
    # The verb registry reads the adapters directory of the tree it compiles for (a role's
    # declared systems); a tree with none is `RegistryError` before any policy exists. The
    # real adapters, under the fake tree.
    from defender._paths import PATHS
    shutil.copytree(PATHS.defender_dir / "scripts" / "adapters", tree / "scripts" / "adapters")
    # The corpus-author role binds to a per-spawn corpus under the tree; give it one to name.
    (tree / "lessons").mkdir()
    return tree


def _policies(run_dir: Path, defender_dir: Path) -> dict[str, object]:
    """Every registered role's compiled policy — the enumeration picks the subjects."""
    from defender.agents import AGENTS
    from defender.runtime.agent_definition import RunScope, compile_policy_for
    # A role that requires a per-spawn corpus (`requires_corpus`) refuses the default scope by
    # design; the enumeration hands it one so every role is reached.
    return {
        role.name: compile_policy_for(
            defn, run_dir=run_dir, defender_dir=defender_dir,
            scope=(RunScope(corpus_name="lessons", read_confine=(defender_dir / "lessons",))
                   if defn.requires_corpus else RunScope()))
        for role, defn in AGENTS.items()}


def test_the_six_per_name_denies_hold_for_every_role(run_dir, worktree):
    """Each of the six per-name denies — `gather_raw` by shape, `wire_logs/` outright,
    `provenance.json` outright, the case answer key for confined roles, the denylist and the
    payload read cap — refuses for every role."""
    from defender.runtime import permission
    from defender.runtime.permission.files import RAW_MARKER, TICKET_READS_MARKER
    from defender._run_paths import CASE_ANSWER_KEY_NAMES, PROVENANCE, WIRE_LOG_DIR

    owner = S.RunPaths(run_dir)
    subjects = {
        "gather_raw by shape": run_dir / RAW_MARKER / "not-a-lead-shape" / "x.json",
        "wire_logs/ outright": owner.wire_log,
        "provenance.json outright": owner.provenance,
        "case answer key": run_dir / sorted(CASE_ANSWER_KEY_NAMES)[0],
        "denylist": run_dir / ".env",
        "payload read cap": run_dir / TICKET_READS_MARKER / "0.json",
    }
    assert PROVENANCE in str(subjects["provenance.json outright"])
    assert WIRE_LOG_DIR in subjects["wire_logs/ outright"].parts

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

    # POSITIVE CONTROL: the denies are not a blanket refusal — an ordinary run-dir read that
    # names none of the six is allowed for the role that owns it. Without it every arm above
    # is green on a policy that refuses everything.
    main = policies["MAIN"]
    assert permission.decide_read(
        run_dir / "alert.json", run_dir=run_dir, defender_dir=worktree, policy=main).allow, (
        "positive control: the alert is deliberately NOT in the answer key "
        "(`_run_paths.py:197-198`) and stays readable")
    well_shaped = owner.payload("l-abc123", 0)
    well_shaped.parent.mkdir(parents=True, exist_ok=True)
    well_shaped.write_text("{}\n", encoding="utf-8")
    gather = policies["GATHER"]
    assert permission.decide_read(
        well_shaped, run_dir=run_dir, defender_dir=worktree, policy=gather).allow, (
        "positive control: the gather-raw deny is BY SHAPE — a well-shaped payload is admitted "
        "for the role that must `cat` it (O8), so the shape arm above is not a blanket refusal")


def test_every_deny_predicate_reads_its_name_from_the_owner(run_dir, worktree):
    """All six deny predicates read their names from the owner module, including `RAW_MARKER`
    and `TICKET_READS_MARKER`, which are no longer spelled in the gate."""
    import defender._run_paths as owner_mod
    from defender.runtime.permission import files

    for name in ("RAW_MARKER", "TICKET_READS_MARKER", "CASE_ANSWER_KEY_NAMES", "PROVENANCE",
                 "WIRE_LOG_DIR"):
        assert hasattr(owner_mod, name), (
            f"{name} must live on the owner; claim C20 says `files.py` spells RAW_MARKER and "
            "TICKET_READS_MARKER locally today and imports the other three")
        assert getattr(files, name, None) is getattr(owner_mod, name) or getattr(
            files, name, None) == getattr(owner_mod, name), (
            f"`files.py` holds its own {name} rather than the owner's — the security dive's "
            "universal (3) is TRUE ONLY AFTER D1 moves these two")

    src = (DEFENDER / "runtime" / "permission" / "files.py").read_text(encoding="utf-8")
    for spelled in ('RAW_MARKER = "gather_raw"', 'TICKET_READS_MARKER = "ticket_reads"'):
        assert spelled not in src, f"files.py still spells {spelled}"

    # Driven: the deny follows the OWNER's value, composed off the owner rather than a literal.
    from defender.runtime import permission
    policies = _policies(run_dir, worktree)
    raw_path = run_dir / owner_mod.RAW_MARKER / "wrong-shape" / "0.json"
    for role, policy in policies.items():
        assert not permission.decide_read(
            raw_path, run_dir=run_dir, defender_dir=worktree, policy=policy).allow, role
    assert permission.decide_read(
        run_dir / "alert.json", run_dir=run_dir, defender_dir=worktree,
        policy=policies["MAIN"]).allow, "positive control: the channel can say yes"


def test_the_box_keeps_network_none_and_one_rw_bind(run_dir):
    """The box still runs with `--network none` and the run dir as its one read-write bind.

    NEGATIVE (nothing new is mounted, nothing is opened up). Positive control: demand d49
    drives the same mount list and requires the run dir to still BE mounted.
    """
    from defender.runtime.box._lifecycle import _create_argv
    from defender.runtime.box._spec import BoxSpec

    argv = _create_argv("defender-run-1077", run_dir, DEFENDER, BoxSpec(), ()).argv
    joined = " ".join(argv)
    assert argv[argv.index("--network") + 1] == "none", (
        "N7: the box's network stays `none`; a future store's client is the driver process")
    assert "--read-only" in argv

    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
    writable = [m for m in mounts if "readonly" not in m]
    assert len(writable) == 1, f"the box has more than one read-write bind: {writable}"
    assert f"target={run_dir}" in writable[0], (
        "N1: the handle does not hide the filesystem from the box — the run-dir layout is a "
        "wire protocol with the model, and the run dir stays its one rw bind")
    readonly = [m for m in mounts if "readonly" in m]
    assert len(readonly) == 1
    assert f"target={DEFENDER}" in readonly[0]
    for m in mounts:
        source = Path(m.split("source=")[1].split(",")[0])
        target = Path(m.split("target=")[1].split(",")[0])
        bound_the_base = (
            f"the RUNS BASE itself is bound ({m}); only the run dir is, which is what makes "
            "the tenant record beside it unreachable from inside a box (demand d49)")
        assert source != run_dir.parent, bound_the_base
        assert target != run_dir.parent, bound_the_base
    assert "--cap-add" not in joined
    assert "--privileged" not in joined


def test_the_box_entrypoint_closure_imports_the_owner_without_pydantic():
    """The name owner the box entrypoint imports the sentinel from (`defender._run_paths`)
    imports with no third-party package installed, and `RunPaths` is a stdlib dataclass (D1).

    The `defender.runtime.box` package itself is NOT held to this any more: #1092 (O2/M7)
    retired the stdlib-only rule for the package door — `BoxSpec` is a `@model` dataclass and
    the owned box image carries pydantic. What the entrypoint's per-exec import then costs is
    #1096. This test pins the owner, which is #1077's."""
    from defender._paths import PATHS
    code = (
        "import sys\n"
        "class Blocker:\n"
        "    def find_module(self, name, path=None):\n"
        "        if name.split('.')[0] in ('pydantic', 'pydantic_ai', 'pydantic_core'):\n"
        "            raise ModuleNotFoundError(name)\n"
        "        return None\n"
        "sys.meta_path.insert(0, Blocker())\n"
        "import defender._run_paths as rp\n"
        "assert rp.BOX_SENTINEL, 'the owner does not name the sentinel'\n"
        "import dataclasses\n"
        "assert dataclasses.is_dataclass(rp.RunPaths), 'RunPaths is not a stdlib dataclass'\n"
        "assert 'pydantic' not in sys.modules, sorted(m for m in sys.modules if 'pyd' in m)\n"
        "print('OK')\n")
    done = subprocess.run([sys.executable, "-c", code], cwd=PATHS.repo_root,
                          capture_output=True, text=True, timeout=180)
    assert done.returncode == 0, (
        f"claim C4: `RunPaths` uses `@model` (pydantic) today while `_io.py` uses a stdlib "
        f"dataclass, so D1's conversion is a real constraint, not a formality:\n{done.stderr}")
    assert "OK" in done.stdout


def test_the_tenant_record_sits_outside_every_box_mount(run_dir):
    """The tenant record's directory is mounted into no box, while the run dir still is."""
    from defender.runtime.box._lifecycle import _create_argv
    from defender.runtime.box._spec import BoxSpec

    runs_base = run_dir.parent
    record = S.tenant().ensure_tenant(runs_base)
    record_path = S.tenant().record_path(runs_base)
    assert record.tenant_id
    assert record_path.parent == runs_base

    argv = _create_argv("defender-run-1077", run_dir, DEFENDER, BoxSpec(), ()).argv
    mounts = [argv[i + 1] for i, a in enumerate(argv) if a == "--mount"]
    for m in mounts:
        source = Path(m.split("source=")[1].split(",")[0])
        assert not record_path.is_relative_to(source), (
            f"the tenant record is inside the box mount {source} — the box mounts "
            "`<run_dir>` only (`runtime/box/_spec.py`), and the record sits one level up "
            "under `<runs_base>`, which no box mounts")
    # POSITIVE CONTROL, in the demand's own sentence: the run dir still IS mounted.
    assert any(f"target={run_dir}" in m for m in mounts), (
        "the run dir stopped being mounted, which would make the negative above pass "
        "vacuously — and would break N1")
    # N9 is the recorded scope: a hostile local user on a shared /tmp is outside the threat
    # model, exactly as it is for today's sidecars beside the same runs base.
    assert S.RunPaths(run_dir).run_end_sidecar(runs_base).parent == record_path.parent
