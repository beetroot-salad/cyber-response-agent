"""Box boundary: from a sandboxed box, writes to the runs folder, `_tenant.json` and `_episodes/` fail and sibling runs are invisible; one box session per runtime."""
from __future__ import annotations

import functools
import json
import os
import shutil
import subprocess
import uuid
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, NoReturn

import pytest

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
    command = f"python3 /runs/current/{script.name} /runs/current /runs"
    box = start_box(run_dir, defender_dir, spec=BoxSpec(runtime=runtime))
    sandboxed, name = box.sandboxed, box.name
    try:
        result = box.run_parsed(parse(command), command=command, cwd=Path("/runs/current"),
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


def test_1105_a_sandboxed_box_cannot_write_the_runs_folder_the_tenant_record_or_episodes(
        box_session):
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
    from defender.run_repository import RunId

    s = box_session
    assert s["sandboxed"] is True, (
        f"the box for a 206-byte run id did not start sandboxed (name {s['name']!r})")
    assert s["probe"] is not None, f"the probe did not complete in the box: rc={s['rc']} {s['err']}"
    listing = s["probe"]["listing"]
    assert listing == ["current"], (
        f"inside the box the run folder's parent must hold the run's own folder only: {listing!r}")
    assert _writes(s)["control"]["ok"] is True, (
        "positive control: the run's own folder is the box's writable bind")
    assert s["control_on_host"] == CONTROL, "positive control: the control write lands on the host"
    t = s["tenant"]
    for name in (SIBLING_ID, RUN_ID):
        assert t.runs_repository().open(RunId.parse(name)).run_dir.name == name, (
            f"the host's runs folder holds {name!r}, which the box must not list")
    for name in ("_tenant.json", "_episodes", f"{RUN_ID}{H.SIDECAR_SUFFIXES[0]}"):
        assert (s["runs"] / name).exists(), f"the host's runs folder holds {name}"
