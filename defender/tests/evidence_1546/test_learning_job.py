"""#1546 sketch (r6), flow "Learning job" from the job's side: the learning entry (`job_entry.main`, in process, on a
job socket the test owns: `SocketStandIn`, as `tests/learning/branch/test_1344_job_lane.py::run_entry` drives it) runs
with its source run's host folder and session database ABSENT; the source reaches it only as the bundle
`evidence.pull` serves. It unpacks the bundle into its root, sends its outcome (findings inside, D1), then its pages
(bytes from the renderer, A-O8) and its bundle. ("Done when": a learning job succeeds with its source's host folder
absent; A-O1, PR1.)

`run_entry` fixes its socket answers, so this case repeats its seams with three more answers. The arms are
`FakeSibling` (the launcher spawns `run.py` subprocesses), so no arm page is pushed here.
"""
from __future__ import annotations

import contextlib
import os
import shutil
import signal
from pathlib import Path

import pytest

from defender.tests.evidence_1546._support import EPISODE_PAGE, members, pack, sha

pytestmark = [pytest.mark.e2e]


def _source_files(tenant_dir: Path, src: Path) -> dict[str, bytes]:
    """The source's root as its bundle holds it: its run folder and session store, root-relative."""
    found = {str(p.relative_to(tenant_dir)): p.read_bytes() for p in sorted(src.rglob("*")) if p.is_file()}
    sessions = tenant_dir / "sessions"
    for db in sorted(sessions.glob("*.db")) if sessions.is_dir() else []:
        found[str(db.relative_to(tenant_dir))] = db.read_bytes()
    return found


def test_a_learning_job_with_its_source_folder_absent_pulls_unpacks_and_pushes(tmp_path, monkeypatch):  # noqa: PLR0915 — one flow, kept whole for the sketch
    """The job pulls `(source, bundle)`, unpacks it to `runs/<source>/`, sends one outcome with status `completed` and
    a `findings` field (D1: no findings object), then pushes `page/learning.html` and `bundle`, the outcome first; no
    learning-end or progress record is written to a folder. Its bundle holds its episode and not the pulled source's
    run folder or the launch facts the helper copied in.
    FORCED CHOICE: r6's bundle rule says "for a learning job also minus the pulled source's run folder, including the
    session database that holds the arms' forks". Read literally, the arms' forks (their transcripts) are in no
    bundle; read the other way, the session copy rides in the job's bundle. Not asserted here."""
    from defender import job_socket
    from defender.learning.branch import job_entry
    from defender.tests.learning.branch import test_1344_job_lane as L
    from defender.tests.learning.branch.test_triplet_launcher import _calls
    from defender.tests.learning.oracle.live_contracts import _spec1224 as S
    from defender.tests.support.jobs._socket_standin1170 import SocketStandIn, handed_records
    from defender.tests.support.jobs._socket_standin1170 import materialise as materialise_export
    from defender.tests.support.learning.branch import _triplet_947 as T
    from defender.tests.support.learning.judge import _judge_921 as J

    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    est = S.estate(tmp_path)
    _base, src = S.source_run(tmp_path, est, calls=_calls())
    tenant_dir = src.parent.parent
    tenant = tenant_dir.name
    source_files = _source_files(tenant_dir, src)
    assert any(name.startswith("sessions/") for name in source_files), "premise: the source has a session store"
    source_bundle = pack(source_files)
    shutil.rmtree(src)  # A-O1: the host keeps nothing of the finished run
    shutil.rmtree(tenant_dir / "sessions", ignore_errors=True)

    def pull(fields):
        if (fields.get("owner"), fields.get("object")) != (src.name, "bundle"):
            raise job_socket.Refused("not among the claim's inputs", "not-an-input")
        return {"data": source_bundle, "last": True}

    pushed: dict[str, bytes] = {}
    parts: dict[str, list[bytes]] = {}
    order: list[str] = []

    def put(fields):
        order.append(f"put:{fields['object']}")
        parts.setdefault(fields["object"], []).append(fields["data"])
        if not fields["last"]:
            return {}
        pushed[fields["object"]] = b"".join(parts.pop(fields["object"]))
        return {"size": len(pushed[fields["object"]]), "sha256": sha(pushed[fields["object"]])}

    ended: list[dict] = []

    def outcome(fields):
        order.append("outcome")
        ended.append(fields["record"])
        return {}

    asking = L.Watch(*S.questioner_for().replies)
    seams = dict(questioner=asking, preflight=S.no_preflight, live_tree=T.source_capture(), roster=est.roster(),
                 judge=L.WatchJudge(default=J.as_reply_text(J.reply_doc(bucket="none", systems=[]))),
                 oracle=S.oracle(then=S.submit()).model, verifier=S.passing_verifier().model,
                 directory=est.launch_directory(tenant), spawn=J.FakeSibling(), candidates=L.choose(T.BRANCH_MESSAGE_ID))
    answers = {"export.materialise": materialise_export(tenant), "evidence.pull": pull, "evidence.put": put,
               "outcome": outcome, "arms": lambda f: order.append("arms") or {}}
    launch = {"kind": "learning", "job": L.JOB, "records": handed_records(seams["directory"], tenant)}
    previous = signal.signal(signal.SIGTERM, L._unexpected_sigterm)
    try:
        with SocketStandIn(tenant, launch=launch, answers=answers) as helper:
            with contextlib.suppress(SystemExit):
                job_entry.main(["--job", L.JOB, "--tenant", tenant, "--source", src.name],
                               environ=helper.environ(), **seams)
            asked = [name for name, _ in helper.asked]
    finally:
        signal.signal(signal.SIGTERM, previous)

    assert "evidence.pull" in asked, "the job never pulled its source"
    assert src.is_dir(), "the source bundle was not unpacked into the job's root as runs/<source>/"
    assert len(ended) == 1, f"no outcome reached the socket: {asked}"
    assert ended[0]["status"] == "completed", ended[0]
    assert set(ended[0]["findings"]) == {"state", "text"}
    assert set(pushed) == {EPISODE_PAGE, "bundle"}, sorted(pushed)
    assert order.index("outcome") < min(order.index(f"put:{o}") for o in pushed), order
    assert pushed[EPISODE_PAGE].lstrip().lower().startswith(b"<!doctype html") or b"<html" in pushed[EPISODE_PAGE]
    runs = Path(os.environ["DEFENDER_DATA_ROOT"]) / tenant / "runs"
    assert not (runs / f"{L.JOB}.learning-end.json").exists(), "the end still went through the folder"
    inside = members(pushed["bundle"])
    assert not [n for n in inside if n.startswith(f"runs/{src.name}/")], "the job's bundle holds the pulled source"
    assert any(n.startswith(f"episodes/{L.JOB}/") for n in inside), sorted(inside)
    assert not [n for n in inside if n.startswith((f"runs/{L.JOB}.launch.json", "run-knowledge/", "exports/"))]
