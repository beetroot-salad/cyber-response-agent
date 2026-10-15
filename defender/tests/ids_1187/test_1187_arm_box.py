"""#1187 — the arm box cannot reach the episode's host-written files (R2-05, design "Contract:
write-tests adds a real arm-box test with a positive control").

#1187 puts an episode's arms at `<data root>/<T>/episodes/<ep>/runs/<arm uuid>/`, beside the
host-written arm roster `<ep>/arms.json` and the manifest `<ep>/family.yaml`. The roster is the
episode's single source of arm identity (a box that could rewrite it could forge or hide a
sibling), so the design rests on one property: a box started for an arm folder binds that folder
and nothing above it, so no write, append, create, replace, rename or unlink reaches `arms.json`,
the episode folder, the arm container `runs/` or a sibling arm. The executed probe (R2-05, runc)
saw every attempt fail (EROFS / EXDEV / EPERM / ENOENT) and the roster absent from the box's
view; gVisor was untested, which is why this is a test and not a claim.

This file turns that probe into a test, in the shape of `test_1105_box_boundary.py`. One
module-scoped session per runtime plants a real accepted tenant and a real episode in the NEW
layout (`_spec1187.make_episode`: manifest, roster, two arm folders, each with its alert input),
starts the PRODUCTION `start_box` for one arm's folder, and runs one probe inside it through the
production executor (`run_parsed`). The probe makes every attempt on `arms.json` (open for
write, append, exclusive create, unlink, replace, rename, `../` traversal, symlink and hard link
to it) and on the episode folder, `runs/` and the sibling arm. Every attempt must fail, and the
host's `<T>/episodes` tree, the arm's own run folder excluded (the box's one writable bind,
where `start_box` plants its sentinel), must be byte-identical before and after. The positive
control is the same box writing a file in the arm's own run folder: it succeeds, and the host
reads the bytes back.

This pins a property that holds TODAY and must keep holding. `start_box` takes a run folder and
does not care what it sits under, so the file is green at base (on a host that can start a box)
with the new layout planted through filesystem builders only.

WHERE IT RUNS. The file carries the `box` marker, so CI's main `test` job (`-m "not live and not
gate"`) collects it; that job builds the box image, installs gVisor and hard-fails unless the
daemon registers `runsc`. The session is parametrised over `RUNTIMES` (`runsc`, the production
default, then `runc`, the floor), so CI starts a gVisor box here, the runtime R2-05 did not probe.
A parameter skips off CI for exactly two reasons: no daemon this process can start a box with
(none answers, or docker-outside-of-Docker with no shared path covering the repo tree: C46), or
that runtime not registered. Under CI (`CI` set) either reason FAILS instead, so a silently
degraded runner cannot leave the boundary "pinned" by a run that started no box. A missing box
image is not a skip: `start_box` faults on it (#1092 O3), which is the signal.

The data root sits under the checkout's gitignored `.defender-runs/`, never pytest's tmp dir:
`/tmp` inside the box is the box's own tmpfs, so an episode under it would mask the very folders
the attempts aim at.
"""
from __future__ import annotations

import functools
import json
import os
import shutil
import uuid
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, NoReturn

import pytest

from defender.tests._docker import daemon_reachable, docker_runtimes, is_dood
from defender.tests.ids_1187 import _spec1187 as S
from defender.tests.tenant_1105_run_repository import _spec1105 as H

pytestmark = pytest.mark.box

#: The runtimes the session runs under: the production default first, then the floor. A
#: superset of `BoxSpec.RUNTIMES`; `DEFENDER_BOX_RUNTIME` is the production lever for the same
#: choice, and each parameter sets the runtime on the spec directly instead of reading it.
RUNTIMES = ("runsc", "runc")

NO_DAEMON = (
    "no Docker daemon this process can start a box with: none answers `docker version`, or "
    "this is docker-outside-of-Docker and no path shared with the daemon covers the repo tree, "
    "so no bind source can be resolved (C46)")
RUNTIME_ABSENT = (
    "the {runtime!r} runtime is not registered with this daemon (`docker info` Runtimes), so "
    "no box under it can start")

EXEC_TIMEOUT = 60.0
CONTROL = b"arm-box-control-1187"
SIBLING_SECRET = "SIBLING-ARM-SECRET-1187"
PROBE_NAME = "_probe_arm_box_1187.py"

#: Every attempt the probe makes on a file or folder the box must not change. `control` is the
#: one that must land.
ATTEMPTS = (
    "roster_open_write", "roster_append", "roster_create_excl", "roster_unlink",
    "roster_replace_from_run_folder", "roster_rename_into_run_folder", "roster_dotdot_write",
    "roster_symlink_from_run_folder", "roster_hardlink_into_run_folder",
    "episode_create_file", "episode_mkdir", "episode_symlink",
    "runs_create_file", "runs_mkdir", "sibling_write", "sibling_symlink",
)

# argv: run_dir, episode_dir, sibling_dir. Paths are the host's own: the box binds the arm's
# folder at the same path, so a path that names a host file names it (or nothing) in the box.
_PROBE = r'''
import json, os, sys

run_dir, episode, sibling = (p.rstrip("/") for p in sys.argv[1:4])
roster = os.path.join(episode, "arms.json")
container = os.path.dirname(run_dir)


def attempt(label, fn):
    try:
        fn()
        return {"label": label, "ok": True, "exc": None, "errno": None}
    except OSError as e:
        return {"label": label, "ok": False, "exc": type(e).__name__, "errno": e.errno}
    except Exception as e:
        return {"label": label, "ok": False, "exc": type(e).__name__, "errno": None}


def write(path, data, mode="wb"):
    def go():
        with open(path, mode) as fh:
            fh.write(data)
    return go


def excl():
    os.close(os.open(roster, os.O_CREAT | os.O_EXCL | os.O_WRONLY))


def replace_from_run_folder():
    tmp = os.path.join(run_dir, "roster.tmp")
    write(tmp, b'{"evil": 1}')()
    os.replace(tmp, roster)


def listing(path):
    try:
        return sorted(os.listdir(path))
    except OSError as e:
        return {"exc": type(e).__name__, "errno": e.errno}


def visible(path):
    try:
        os.stat(path)
        return True
    except OSError:
        return False


control = attempt("control", write(os.path.join(run_dir, "control.txt"), b"arm-box-control-1187"))
writes = [
    attempt("roster_open_write", write(roster, b'{"evil": 1}')),
    attempt("roster_append", write(roster, b"tamper", "ab")),
    attempt("roster_create_excl", excl),
    attempt("roster_unlink", lambda: os.unlink(roster)),
    attempt("roster_replace_from_run_folder", replace_from_run_folder),
    attempt("roster_rename_into_run_folder",
            lambda: os.rename(roster, os.path.join(run_dir, "stolen.json"))),
    attempt("roster_dotdot_write",
            write(os.path.join(run_dir, "..", "..", "arms.json"), b"traversal")),
    attempt("roster_symlink_from_run_folder",
            lambda: os.symlink(roster, os.path.join(run_dir, "roster-link"))),
    attempt("roster_hardlink_into_run_folder",
            lambda: os.link(roster, os.path.join(run_dir, "roster-hard"))),
    attempt("episode_create_file", write(os.path.join(episode, "new.txt"), b"x")),
    attempt("episode_mkdir", lambda: os.mkdir(os.path.join(episode, "newdir"))),
    attempt("episode_symlink", lambda: os.symlink(run_dir, os.path.join(episode, "elsewhere"))),
    attempt("runs_create_file", write(os.path.join(container, "planted.txt"), b"x")),
    attempt("runs_mkdir", lambda: os.mkdir(os.path.join(container, "forged-arm"))),
    attempt("sibling_write", write(os.path.join(sibling, "forged.txt"), b"forged")),
    attempt("sibling_symlink",
            lambda: os.symlink(run_dir, os.path.join(sibling, "elsewhere"))),
]
print(json.dumps({
    "control": control,
    "writes": writes,
    "episode_listing": listing(episode),
    "container_listing": listing(container),
    "roster_visible": visible(roster),
    "manifest_visible": visible(os.path.join(episode, "family.yaml")),
    "sibling_visible": visible(sibling),
}))
'''


# ==========================================================================================
# Whether a box can start here, and what a parameter does when it cannot.
# ==========================================================================================

@functools.cache
def _daemon() -> tuple[bool, Path | None, frozenset[str]]:
    """(a box can start from this process, where the data root must live, the runtimes the
    daemon registers). Asked once, lazily, so collecting this file runs no docker command.

    The anchor is the checkout's gitignored `.defender-runs/` natively too, never pytest's tmp
    dir: inside the box `/tmp` is the box's own writable tmpfs, so an episode under it would
    mask the folders the attempts aim at. Under docker-outside-of-Docker `dood_anchor()` is that
    same path when the repo tree is shared with the daemon (`defender_dir` is bound out of it, so
    it provably is), and `None` when even that is uncovered."""
    if not daemon_reachable():
        return False, None, frozenset()
    if is_dood():
        from defender.tests._docker import dood_anchor

        anchor = dood_anchor()
        if anchor is None:
            return False, None, frozenset()
    else:
        anchor = H.WORKTREE / ".defender-runs"
    return True, anchor, docker_runtimes()


def _skip_reason(runtime: str, *, usable: bool, registered: frozenset[str]) -> str | None:
    """Why a box parameter cannot run here, or `None`: exactly the two reasons."""
    if not usable:
        return NO_DAEMON
    if runtime not in registered:
        return RUNTIME_ABSENT.format(runtime=runtime)
    return None


def _skip_or_fail(reason: str, environ: Mapping[str, str]) -> NoReturn:
    """Off CI a box parameter that cannot run skips, naming why; in CI it fails: the test job
    installs the runtimes, so a skip there would pin the boundary with no box started."""
    if environ.get("CI"):
        pytest.fail(f"the arm-box boundary cannot skip in CI: {reason}")
    pytest.skip(reason)


# ==========================================================================================
# The session: one real episode in the new layout, one real box for one arm, one probe.
# ==========================================================================================

def _outside_arm(state: dict[str, Any], arm_id: str) -> dict[str, Any]:
    """The episodes tree minus the contents of the arm's own run folder (the box's rw bind,
    where `start_box` plants its sentinel and the control write lands). The folder's own entry
    stays, so the arm folder being removed or retyped still shows."""
    return {k: v for k, v in state.items() if f"/runs/{arm_id}/" not in f"/{k}"}


def _session(root: Path, runtime: str) -> dict[str, Any]:
    from defender.runtime.bash_exec import parse
    from defender.runtime.box import BoxSpec, start_box, stop_box

    t = S.tenant(root, H.T_ID)
    episode = S.make_episode(root, t.id, labels=("a", "b"), roster=True, arms=True)
    roster = S.read_roster(episode)
    arm_id, sibling_id = roster["a"], roster["b"]
    arm = episode / "runs" / arm_id
    sibling = episode / "runs" / sibling_id
    (sibling / "secret.txt").write_text(SIBLING_SECRET, encoding="utf-8")
    episodes = S.episodes_dir(root, t.id)
    before = _outside_arm(S.tree(episodes), arm_id)

    script = arm / PROBE_NAME
    script.write_text(_PROBE, encoding="utf-8")
    command = f"python3 {script} {arm} {episode} {sibling}"
    box = start_box(arm, H.DEFENDER, spec=BoxSpec(runtime=runtime),
                    tenant_agent=t.agent, tenant_id=t.id)
    sandboxed, name = box.sandboxed, box.name
    try:
        result = box.run_parsed(parse(command), command=command, cwd=arm, timeout=EXEC_TIMEOUT)
    finally:
        stop_box(box)
    probe = json.loads(result.out.decode("utf-8")) if result.rc == 0 else None
    control = arm / "control.txt"
    return {
        "runtime": runtime, "episode": episode, "arm": arm, "arm_id": arm_id,
        "sibling": sibling, "roster": roster, "rc": result.rc,
        "sandboxed": sandboxed, "name": name,
        "err": result.err.decode("utf-8", "replace"), "probe": probe,
        "before": before, "after": _outside_arm(S.tree(episodes), arm_id),
        "control_on_host": control.read_bytes() if control.is_file() else None,
    }


@pytest.fixture(scope="module", params=RUNTIMES)
def arm_box_session(request: pytest.FixtureRequest) -> Iterator[dict[str, Any]]:
    runtime = request.param
    usable, anchor, registered = _daemon()
    reason = _skip_reason(runtime, usable=usable, registered=registered)
    if reason is not None or anchor is None:
        _skip_or_fail(reason or NO_DAEMON, os.environ)
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

def test_1187_an_arm_box_cannot_change_the_roster_the_episode_folder_the_arm_container_or_a_sibling(
        arm_box_session):
    """From a sandboxed box started by the production start_box for an arm folder at
    <T>/episodes/<ep>/runs/<arm uuid>/, under each runtime in RUNTIMES (runsc, the production
    default, and runc), every one of these attempts fails: open for write, append, exclusive
    create, unlink, replace from the run folder, rename into the run folder, '../..' write, a
    symlink and a hard link to <ep>/arms.json; a new file, a new folder and a symlink in the
    episode folder; a new file and a new folder in <ep>/runs/; a write into, and a symlink in,
    the sibling arm. The host's <T>/episodes tree, the arm's own run folder excluded, is
    byte-identical before and after. Positive control, same box and same channel: a write to a
    file in the arm's own run folder succeeds and the host reads its bytes back."""
    s = arm_box_session
    assert s["sandboxed"] is True, (
        f"the box for an arm folder did not start sandboxed (name {s['name']!r})")
    assert s["probe"] is not None, f"the probe did not complete in the box: rc={s['rc']} {s['err']}"
    control = s["probe"]["control"]
    assert control["ok"] is True, (
        f"positive control: the write in the arm's own run folder must succeed in the box: {control}")
    assert s["control_on_host"] == CONTROL, (
        "positive control: the in-run-folder write must land on the host, byte for byte: "
        f"{s['control_on_host']!r}")
    writes = _writes(s)
    assert set(writes) == set(ATTEMPTS), (
        f"the probe made exactly the planned attempts, none silently dropped: {sorted(writes)}")
    for label in ATTEMPTS:
        assert writes[label]["ok"] is False, (
            f"under {s['runtime']} the arm's box succeeded at {label}: {writes[label]}")
    assert S.read_roster(s["episode"]) == s["roster"], (
        f"the roster on the host is not what was planted: {S.read_roster(s['episode'])!r}")
    assert s["after"] == s["before"], (
        "the host's episodes tree changed outside the arm's own run folder: "
        f"{sorted(set(s['after'].items()) ^ set(s['before'].items()))[:6]}")
    assert (s["sibling"] / "secret.txt").read_text(encoding="utf-8") == SIBLING_SECRET, (
        "the sibling arm's file changed")


def test_1187_an_arm_box_cannot_see_the_roster_the_manifest_or_a_sibling_arm(arm_box_session):
    """in the same sandboxed arm-box session, under each runtime in RUNTIMES, the roster
    <ep>/arms.json, the manifest <ep>/family.yaml and the sibling arm's folder are not visible
    from inside the box (not denied: absent), and neither the episode folder's listing nor the
    arm container's lists them; the arm container lists the arm's own folder. Positive control:
    the arm's own folder is listed and its control write lands on the host, while the host's own
    view of the same episode holds the roster, the manifest and the sibling."""
    s = arm_box_session
    assert s["sandboxed"] is True, (
        f"the box for an arm folder did not start sandboxed (name {s['name']!r})")
    assert s["probe"] is not None, f"the probe did not complete in the box: rc={s['rc']} {s['err']}"
    probe = s["probe"]
    assert probe["control"]["ok"] is True, "positive control: the control write succeeds in the box"
    assert s["control_on_host"] == CONTROL, "positive control: the control write lands on the host"
    container = probe["container_listing"]
    assert isinstance(container, list), f"the arm container is not listable: {container!r}"
    assert s["arm_id"] in container, (
        f"positive control: the arm container must list the arm's own folder: {container!r}")
    sibling_id = s["sibling"].name
    assert sibling_id not in container, (
        f"the sibling arm {sibling_id!r} is visible in the arm's container: {container!r}")
    episode = probe["episode_listing"]
    if isinstance(episode, list):
        assert S.ROSTER_NAME not in episode, f"the roster is listed in the episode folder: {episode!r}"
        assert S.MANIFEST_NAME not in episode, (
            f"the manifest is listed in the episode folder: {episode!r}")
    assert probe["roster_visible"] is False, "the roster is visible from inside the arm's box"
    assert probe["manifest_visible"] is False, "the manifest is visible from inside the arm's box"
    assert probe["sibling_visible"] is False, "the sibling arm is visible from inside the arm's box"
    host = sorted(p.name for p in s["episode"].iterdir())
    assert S.ROSTER_NAME in host, f"the host's episode folder holds the roster: {host!r}"
    assert S.MANIFEST_NAME in host, f"the host's episode folder holds the manifest: {host!r}"
    assert s["sibling"].is_dir(), "the host's episode holds the sibling arm the box must not see"
