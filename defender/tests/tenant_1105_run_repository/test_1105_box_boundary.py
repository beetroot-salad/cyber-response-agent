"""#1105 PR 1 — S3's box boundary over the runs folder's host-only records (S3, N-l; the
owner's test shape, round 4).

S3: a box cannot hide or forge a sibling on the sandboxed lane. The episode record
(`tenant.runs/_episodes/<episode_id>.json`) and the tenant record (`tenant.runs/_tenant.json`)
sit beside the run folders, outside every box bind: the box binds its own run folder read-write
and the checkout read-only, nothing at or above `tenant.runs` (C8). The executed break attempt
(GR-A1 under runc, GR-A2 through the production bash lane) is the design's evidence; this file
pins it as a test, in the shape the owner named: from the sandboxed lane a write to the runs
folder, `_tenant.json` or `_episodes/` fails, while a control write inside the run folder lands.
The opt-out lane (`DEFENDER_ALLOW_UNSANDBOXED=1`) gives the boundary up and is not held to it
(N-l; GR-A3 is the probe's positive control, `w_opt_out_lane_outside_s1_s3`).

ONE BOX SESSION PER RUNTIME. The module-scoped `box_session` fixture plants a real tenant's
runs folder — the run `RUN_ID`, a sibling run `r0` holding a secret, the sidecar beside the run,
a host-written episode record claiming the arm `ep-a` (whose folder exists), and `_tenant.json`
— starts the box for `RUN_ID` under the real `start_box`, and runs one probe inside it that
makes every write attempt and then lists the run folder's parent. Both S3 tests read that one
session. `RUN_ID` is exactly 206 bytes, the longest id `RunId` admits (D12.3), so the container
is named `defender-run-<206-byte id>` (219 characters): CI starts that box under every runtime in
`RUNTIMES`, runsc included (RG-27-b; MF-10's probe-first, RG-27-a holds for runc), and a runtime
that refused the name fails the session's `start_box` here.
The host tree is observed twice after the box stops: entry for entry and byte for byte
(`H.tree_state`, the run's own folder excluded — the box writes there by design), and through
the repository's own readers (`runs.list()`, `sibling_run_ids`, `runs.exists`), which must
answer exactly what the planted tree says: the box neither hid a run nor forged a claim.

WHERE IT RUNS, AND WHY IT CANNOT SKIP IN CI. The file carries the `box` marker, so CI's main
`test` job (`-m "not live and not gate"`) collects it; that job installs gVisor and hard-fails
unless the daemon registers `runsc`, and it `--ignore`s only `tests/e2e/test_540_box_boundary.py`.
The session is parametrised over `RUNTIMES` (`runsc`, the production default, and `runc`, the
floor), so CI starts a gVisor box here (probing GR-A5, unprobed on this dev box). A parameter
skips for exactly two reasons — no daemon this process can start a box with (none answers, or
docker-outside-of-Docker with no shared path covering the repo tree, C46), or that runtime not
registered — and under CI (`CI` set) either reason FAILS instead (`_skip_or_fail`). The third
test pins all of this by reading the workflow and this file.

Red at base 80888efb, where a box can start: the two box tests import the repository's readers
from `defender.run_repository` (ModuleNotFoundError). On this dev box (docker-outside-of-Docker,
the worktree not on a shared mount, runc only) both box tests skip with the first reason. The
CI-wiring test reads files only and is green at base.
"""
from __future__ import annotations

import ast
import functools
import json
import os
import re
import shutil
import subprocess
import uuid
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, NoReturn

import pytest
import yaml

from defender.runtime import box as box_mod
from defender.runtime.bash_exec import parse
from defender.runtime.box import BoxSpec, start_box, stop_box
from defender.tests._docker import daemon_reachable, is_dood
from defender.tests.tenant_1105_run_repository import _spec1105 as H

pytestmark = pytest.mark.box

#: The runtimes every box test here runs under: the production default first (GR-A5), then the
#: floor. A superset of `BoxSpec.RUNTIMES`, so a runtime the lever admits is never left out.
RUNTIMES = ("runsc", "runc")

#: The two reasons a box parameter may skip for (off CI only).
NO_DAEMON = (
    "no Docker daemon this process can start a box with: none answers `docker version`, or "
    "this is docker-outside-of-Docker and no path shared with the daemon covers the repo tree, "
    "so no bind source can be resolved (C46)")
RUNTIME_ABSENT = (
    "the {runtime!r} runtime is not registered with this daemon (`docker info` Runtimes), so "
    "no box under it can start")

EXEC_TIMEOUT = 60.0
#: The box's own run: exactly `RUN_ID_BOUND` (206) bytes, so the container name is 219
#: characters (RG-27-a, RG-27-b). It starts with `r1`, so it sorts after the sibling `r0`.
RUN_ID = "r1-" + "a" * (H.RUN_ID_BOUND - 3)
SIBLING_ID = "r0"
ARM_ID = "ep-a"
SIBLING_SECRET = "SIBLING-RUN-SECRET-1105"
CONTROL = b"box-control-1105"

#: The writes the box attempts, keyed by what each tries to reach (GR-A1's shape, made
#: against a real tenant's runs folder). `control` is the one that must land.
_ATTEMPTS = ("tenant_record", "episode_record", "sibling_folder", "into_sibling", "dotdot")

_PROBE = r'''
import json, os, sys

run_dir, runs = sys.argv[1], sys.argv[2]


def attempt(label, fn):
    try:
        fn()
        return {"label": label, "ok": True, "exc": None, "errno": None}
    except OSError as e:
        return {"label": label, "ok": False, "exc": type(e).__name__, "errno": e.errno}


def write(path, data):
    def go():
        with open(path, "wb") as fh:
            fh.write(data)
    return go


writes = [
    attempt("tenant_record", write(os.path.join(runs, "_tenant.json"),
                                   b'{"tenant_id": "beta"}')),
    attempt("episode_record", write(os.path.join(runs, "_episodes", "x.json"), json.dumps(
        {"episode_id": "x", "tenant_id": "acme", "source_run_id": "r0",
         "runs": {"a": os.path.basename(run_dir.rstrip("/"))}}).encode())),
    attempt("sibling_folder", lambda: os.mkdir(os.path.join(runs, "r9"))),
    attempt("into_sibling", write(os.path.join(runs, "r0", "forged.txt"), b"forged")),
    attempt("dotdot", write("../x", b"escaped")),
    attempt("control", write(os.path.join(run_dir, "control.txt"), b"box-control-1105")),
]
try:
    listing = sorted(os.listdir(os.path.dirname(run_dir.rstrip("/"))))
except OSError as e:
    listing = {"exc": type(e).__name__, "errno": e.errno}
print(json.dumps({"writes": writes, "listing": listing}))
'''


# ==========================================================================================
# Whether a box can start here, and what a parameter does when it cannot.
# ==========================================================================================

def _docker_runtimes() -> frozenset[str]:
    probe = subprocess.run(
        ["docker", "info", "--format", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    return frozenset(probe.stdout.split()) if probe.returncode == 0 else frozenset()


@functools.cache
def _daemon() -> tuple[bool, Path | None, frozenset[str]]:
    """(a box can start from this process, where the data root must live, the runtimes the
    daemon registers). Asked once, lazily, so collecting this file runs no docker command.

    The anchor is the checkout's gitignored `.defender-runs/` natively too, never pytest's tmp
    dir: that sits under `/tmp`, and inside the box `/tmp` is the box's own writable tmpfs, so
    the run folder's parent there is box scratch, not the host's runs folder, and the write
    attempts would land in it (owner ruling, #1105 PR 1's first CI run)."""
    if not daemon_reachable():
        return False, None, frozenset()
    anchor = H.WORKTREE / ".defender-runs"
    if is_dood():
        mounts = box_mod._shared_mounts(box_mod._docker)
        if not mounts or not box_mod._covered(H.DEFENDER, mounts):
            return False, None, frozenset()
        # The repo tree is shared with the daemon (defender_dir is bound out of it), so a data
        # root under its gitignored `.defender-runs/` is too (test_540's placement).
    return True, anchor, _docker_runtimes()


def _skip_reason(runtime: str, *, usable: bool, registered: frozenset[str]) -> str | None:
    """Why a box parameter cannot run here, or `None`: exactly the two reasons."""
    if not usable:
        return NO_DAEMON
    if runtime not in registered:
        return RUNTIME_ABSENT.format(runtime=runtime)
    return None


def _skip_or_fail(reason: str, environ: Mapping[str, str]) -> NoReturn:
    """Off CI a box parameter that cannot run skips, naming why; in CI it fails — the box job
    installs the runtimes, so a skip there would pin the boundary with no box started."""
    if environ.get("CI"):
        pytest.fail(f"the S3 box boundary cannot skip in CI: {reason}")
    pytest.skip(reason)


# ==========================================================================================
# The session: one real tenant runs folder, one real box, one probe.
# ==========================================================================================

def _outside_run(state: dict[str, Any]) -> dict[str, Any]:
    """The runs folder's tree minus the run's own folder's contents (the box's rw bind, where
    start_box plants its sentinel and the control write lands)."""
    return {k: v for k, v in state.items() if not k.startswith(f"{RUN_ID}/")}


def _session(root: Path, runtime: str, *, defender_dir: Path = H.DEFENDER) -> dict[str, Any]:
    t = H.tenant(root, H.T_ID)
    runs = H.runs_folder(t)
    run_dir = H.make_run(runs, RUN_ID)
    sibling = H.make_run(runs, SIBLING_ID)
    (sibling / "secret.txt").write_text(SIBLING_SECRET, encoding="utf-8")
    (runs / f"{RUN_ID}{H.SIDECAR_SUFFIXES[0]}").write_text("{}\n", encoding="utf-8")
    H.plant_record(runs, "ep", t.id, SIBLING_ID, {"a": ARM_ID})
    H.make_run(runs, ARM_ID)
    before = _outside_run(H.tree_state(runs))

    script = run_dir / "_probe_s3_1105.py"
    script.write_text(_PROBE, encoding="utf-8")
    command = f"python3 {script} {run_dir} {runs}"
    box = start_box(run_dir, defender_dir, spec=BoxSpec(runtime=runtime))
    sandboxed, name = box.sandboxed, box.name
    try:
        result = box.run_parsed(parse(command), command=command, cwd=run_dir,
                                timeout=EXEC_TIMEOUT)
    finally:
        stop_box(box)
    probe = json.loads(result.out.decode("utf-8")) if result.rc == 0 else None
    control = run_dir / "control.txt"
    return {
        "tenant": t, "runs": runs, "run_dir": run_dir, "rc": result.rc,
        "sandboxed": sandboxed, "name": name,
        "err": result.err.decode("utf-8", "replace"), "probe": probe,
        "before": before, "after": _outside_run(H.tree_state(runs)),
        "control_on_host": control.read_bytes() if control.is_file() else None,
    }


@pytest.fixture(scope="module", params=RUNTIMES)
def box_session(request: pytest.FixtureRequest,
                tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Any]]:
    runtime = request.param
    usable, anchor, registered = _daemon()
    reason = _skip_reason(runtime, usable=usable, registered=registered)
    if reason is not None:
        _skip_or_fail(reason, os.environ)
    if anchor is None:
        yield _session(tmp_path_factory.mktemp(f"box-{runtime}") / "data", runtime)
        return
    base = anchor / uuid.uuid4().hex
    base.mkdir(parents=True)
    try:
        yield _session(base / "data", runtime)
    finally:
        # The box writes through the rw bind as root (C41); residue is gitignored.
        shutil.rmtree(base, ignore_errors=True)


def _writes(session: dict[str, Any]) -> dict[str, dict[str, Any]]:
    probe = session["probe"] or {}
    return {w["label"]: w for w in probe.get("writes", [])}


# ==========================================================================================
# The tests.
# ==========================================================================================

def test_1105_a_sandboxed_box_cannot_write_the_runs_folder_the_tenant_record_or_episodes(
        box_session):
    """From a sandboxed box started for a run under tenant.runs whose id is exactly 206 bytes
    (the container is named defender-run-<id>, 219 characters, under each runtime in RUNTIMES,
    runsc included: RG-27-b), the box starts sandboxed, and a write to the runs folder (a sibling
    folder, '../x'), to _tenant.json and to _episodes/x.json each fail and leave the host tree
    unchanged, while a control write inside the run folder lands (the shape of GR-A1 and GR-A2).
    The file skips with its reason where no daemon or no registered runtime can start a box. The
    host tree is observed entry for entry and through the repository's own readers."""
    from defender.run_repository import RunId, sibling_run_ids

    s = box_session
    assert s["sandboxed"] is True, (
        f"the box for a 206-byte run id did not start sandboxed (name {s['name']!r})")
    assert len(RUN_ID.encode()) == H.RUN_ID_BOUND, f"the box's run id is 206 bytes: {RUN_ID!r}"
    assert s["name"].endswith(RUN_ID), (
        f"the box must run under the 206-byte id's 219-character name: {s['name']!r}")
    assert s["probe"] is not None, f"the probe did not complete in the box: rc={s['rc']} {s['err']}"
    writes = _writes(s)
    assert writes["control"]["ok"] is True, (
        f"positive control: the in-run-folder write must succeed in the box: {writes['control']}")
    assert s["control_on_host"] == CONTROL, (
        f"positive control: the in-run-folder write must land on the host: {s['control_on_host']!r}")
    for label in _ATTEMPTS:
        assert writes[label]["ok"] is False, f"the sandboxed box wrote {label}: {writes[label]}"
    assert s["after"] == s["before"], (
        "the host's runs folder changed outside the run's own folder: "
        f"{sorted(set(s['after'].items()) ^ set(s['before'].items()))[:6]}")
    listed = list(s["tenant"].runs_repository().list())
    assert listed == [RunId.parse(SIBLING_ID), RunId.parse(RUN_ID)], (
        f"after the box ran, runs.list() must answer the planted runs, no more no fewer: {listed!r}")
    claimed = sibling_run_ids(s["tenant"])
    assert claimed == {RunId.parse(ARM_ID)}, (
        f"after the box ran, the claims must be the host-written record's alone: {claimed!r}")


def test_1105_a_sandboxed_box_sees_only_its_own_run_folder_not_the_tenant_record_episodes_or_a_sibling(
        box_session):
    """in the same sandboxed box session as the S3 writes, for a run whose id is exactly 206
    bytes (a 219-character container name under each runtime in RUNTIMES), listing
    run_dir.parent shows exactly the run's own folder; a planted sibling run folder,
    _tenant.json, _episodes/ and a sidecar file beside the run are not listed; positive control:
    the box started sandboxed, the run's own folder is listed and its control write lands. The
    host's own view of the same folder, through the repository, holds each planted run (the
    219-byte sidecar name, beyond RunId's bound, is checked on disk)."""
    from defender.run_repository import RunId

    s = box_session
    assert s["sandboxed"] is True, (
        f"the box for a 206-byte run id did not start sandboxed (name {s['name']!r})")
    assert s["probe"] is not None, f"the probe did not complete in the box: rc={s['rc']} {s['err']}"
    listing = s["probe"]["listing"]
    assert listing == [RUN_ID], (
        f"inside the box the run folder's parent must hold the run's own folder only: {listing!r}")
    assert _writes(s)["control"]["ok"] is True, (
        "positive control: the run's own folder is the box's writable bind")
    assert s["control_on_host"] == CONTROL, "positive control: the control write lands on the host"
    t = s["tenant"]
    for name in (SIBLING_ID, RUN_ID):
        assert t.runs_repository().exists(RunId.parse(name)) is True, (
            f"the host's runs folder holds {name!r}, which the box must not list")
    for name in ("_tenant.json", "_episodes", f"{RUN_ID}{H.SIDECAR_SUFFIXES[0]}"):
        assert (s["runs"] / name).exists(), f"the host's runs folder holds {name}"


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


_SKIP_SPELLINGS = {"pytest.skip", "pytest.importorskip", "pytest.mark.skip",
                   "pytest.mark.skipif", "pytest.xfail", "pytest.mark.xfail"}


def test_1105_the_box_boundary_file_is_collected_in_ci_on_every_registered_runtime_and_skips_only_for_no_daemon_or_runtime(
        request):
    """test_1105_box_boundary.py carries the box marker and neither the live nor the gate marker,
    so the test job's -m 'not live and not gate' collects it; no workflow --ignore names it; the
    job that collects it installs gVisor and hard-fails when runsc is not registered
    (ci.yml:138-142); the file skips only for 'no daemon' or 'runtime not registered' and is
    parametrised over the registered runtimes, runsc included (probing GR-A5 in CI); positive
    control: tests/e2e/test_540_box_boundary.py is the one file the main job ignores."""
    me = Path(__file__).resolve()
    rel = str(me.relative_to(H.DEFENDER))
    node = request.node
    assert node.get_closest_marker("box") is not None, "the file must carry the box marker"
    assert node.get_closest_marker("live") is None, "a live marker deselects the file from CI"
    assert node.get_closest_marker("gate") is None, (
        "a gate marker moves the file out of CI's main (box-capable) test job")

    workflows = H.WORKTREE / ".github" / "workflows"
    ci = yaml.safe_load((workflows / "ci.yml").read_text(encoding="utf-8"))
    collecting = [
        (job_id, job, i) for job_id, job in ci["jobs"].items()
        for i, step in enumerate(job.get("steps", []))
        if "pytest tests/" in (step.get("run") or "")
        and '-m "not live and not gate"' in (step.get("run") or "")]
    assert len(collecting) == 1, f"one job collects tests/ with the main selection: {collecting!r}"
    job_id, job, at = collecting[0]
    run_line = job["steps"][at]["run"]
    ignored = re.findall(r"--ignore[= ]\s*(\S+)", run_line)
    assert ignored == ["tests/e2e/test_540_box_boundary.py"], (
        f"positive control: the main job ignores exactly test_540's file: {ignored!r}")
    for wf in sorted(workflows.glob("*.y*ml")):
        text = wf.read_text(encoding="utf-8")
        for flag, target in re.findall(r"(--ignore(?:-glob)?|--deselect)[= ]\s*(\S+)", text):
            assert "test_1105_box_boundary" not in target, f"{wf.name}: {flag} {target} drops this file"
            assert "tenant_1105" not in target, f"{wf.name}: {flag} {target} drops this suite"
    earlier = "\n".join(s.get("run") or "" for s in job["steps"][:at])
    assert "runsc install" in earlier, f"job {job_id!r} installs gVisor before it runs the tests"
    assert "grep -qx runsc" in earlier, (
        f"job {job_id!r} hard-fails when the daemon does not register runsc")

    tree = ast.parse(me.read_text(encoding="utf-8"))
    skips = [_dotted(n.func) for n in ast.walk(tree)
             if isinstance(n, ast.Call) and _dotted(n.func) in _SKIP_SPELLINGS]
    skips += [_dotted(n) for n in ast.walk(tree)
              if isinstance(n, ast.Attribute) and _dotted(n) in {"pytest.mark.skip",
                                                                 "pytest.mark.skipif"}]
    assert skips == ["pytest.skip"], f"exactly one skip site, in _skip_or_fail: {skips!r}"
    assert _skip_reason("runsc", usable=False, registered=frozenset({"runsc"})) == NO_DAEMON
    assert _skip_reason("runsc", usable=True, registered=frozenset({"runc"})) == (
        RUNTIME_ABSENT.format(runtime="runsc"))
    assert _skip_reason("runc", usable=True, registered=frozenset({"runc"})) is None
    in_ci = H.raised(_skip_or_fail, NO_DAEMON, {"CI": "true"})
    off_ci = H.raised(_skip_or_fail, NO_DAEMON, {})
    assert isinstance(in_ci, pytest.fail.Exception), f"in CI a skip reason fails: {in_ci!r}"
    assert isinstance(off_ci, pytest.skip.Exception), f"off CI it skips: {off_ci!r}"
    assert "runsc" in RUNTIMES, f"the production runtime is parametrised: {RUNTIMES}"
    assert set(BoxSpec.RUNTIMES) <= set(RUNTIMES), f"every runtime the lever admits: {RUNTIMES}"
    fixture = next(n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == "box_session")
    params = [kw.value for d in fixture.decorator_list if isinstance(d, ast.Call)
              for kw in d.keywords if kw.arg == "params"]
    assert [_dotted(p) for p in params] == ["RUNTIMES"], "box_session is parametrised by RUNTIMES"
    users = sorted(n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
                   and n.name.startswith("test_") and "box_session" in
                   {a.arg for a in n.args.args})
    assert len(users) == 2, f"both S3 box tests run on the parametrised session: {users!r}"
    assert rel.startswith("tests/"), rel
