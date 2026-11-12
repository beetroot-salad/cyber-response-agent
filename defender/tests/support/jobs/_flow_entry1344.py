"""#1344 e2e children, started by the real worker: `python _flow_entry1344.py <mode> <commit> <marks> <args...>`.

- `investigate`: the real per-job host helper (`job_host.main`, #1170) in front of the real job entry (`run.job_main`) over
  the replay driver, as `_helper_child1170.py` runs it: the helper's docker is the stand-in (`ContainerStandIn`) whose job
  container is this script again, in the same mode, as a real process given only the container's environment (the job
  socket set: the in-container branch). MAIN writes a document, dispatches one lead (`gather`) whose query reaches a
  stand-in elastic, writes the rest and closes: a completed run whose one `gather` response is a legal fork point.
- `investigate-no-gather`: the same run with no `gather`, so no fork point exists.
- `family`: the real learning job entry (`job_entry.main`) inside its job container (#1170 A6), every paid model a script
  and the siblings real `run.main` processes' in-process equivalent (`_1255_twin.run_main`), continuing MAIN's script
  after the fork. Args: `--job <id> --tenant <T> --source <investigation id> [--parent-pid <pid>]`.
- `post-step`: the real post-step inside its job container, with a recording drain gate (`<marks>/gate`, holding the
  queue's size when it ran).

The learning kinds' job socket is a stand-in (`_socket_standin1170.SocketStandIn`: the helper's `launch` facts, the
export it materialises and, for `family`, the passes it signs): the learning helper's own work is `tests/jobs/test_job_helper_learning.py`'s. The siblings run
in this process as the operator's (no job socket in this process's own environment), as they did before #1170."""
from __future__ import annotations

import functools
import json
import os
import subprocess
import sys
from pathlib import Path

# A bare script: the checkout root comes from this file's location, never from the parent's environment.
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from defender.tests.e2e import _replay_harness as RH
from defender.tests.e2e._lead_zero_808 import VerbRecorder, answer_hits, elastic_backend, hit
from defender.tests.support.runtime.state import _1255_snapshot as R

mode, commit, marks, argv = sys.argv[1], sys.argv[2], Path(sys.argv[3]), sys.argv[4:]
marks.mkdir(parents=True, exist_ok=True)

LEAD = "l-001"
QUERY = RH.Turn(tool_calls=[("query", {"system": "elastic", "verb": "query",
                                       "params": {"native_query": "user.name:dev.dana"}})])
DOCS = [hit(ts="2026-05-25T15:20:00.000Z")]
DISPOSITION = "malicious"
#: The credential proxy's address in these children: nothing answers there (the conftest's own).
PROXY_URL = "http://proxy.invalid"


def main_script(*, gathers: bool = True) -> list:
    """append, dispatch (the only `gather`; `gathers=False`: none), the rest of the document, close."""
    first, second, third = R.chunks(3)
    return [R.append(first), *([R.dispatch(LEAD)] if gathers else []), R.append(second), R.append(third),
            R.close(DISPOSITION), RH.Turn(text="Investigation complete.")]


def after_the_gather() -> list:
    """What a sibling's MAIN says once it has resumed at the `gather` response."""
    return main_script()[2:]


def _unboxed(*_a, start_token=None, **_k):
    from defender import box as box_mod

    return box_mod.unboxed_executor()


def investigate(*, gathers: bool = True) -> int:
    from defender import run as run_py

    gather = R.LeadRouter({R.CORRELATION_LEAD: R.CORRELATION_TURNS, LEAD: (QUERY, RH.Turn(text=f"summary of {LEAD}"))})
    inner = RH.investigate_as_handed(RH.ReplayFn(main_script(gathers=gathers)), gather)

    def investigate_with_a_system(**handed):
        return inner(**{**handed, "verbs": elastic_backend(VerbRecorder(), answer_hits(DOCS))})

    drive = functools.partial(run_py._drive_investigation, investigate=investigate_with_a_system)
    lifecycle = functools.partial(run_py._run_investigation_lifecycle, investigate=drive, start_box=_unboxed)
    return run_py.job_main(_in_container_argv(), lifecycle=lifecycle, preflight=lambda *a, **k: 0,
                           visualize=lambda *a, **k: None)


def _in_container_argv() -> list[str]:
    """This child's argv as the helper starts the entry in its container: no `--parent-pid` (A5, A6)."""
    if "--parent-pid" not in argv:
        return list(argv)
    at = argv.index("--parent-pid")
    return [*argv[:at], *argv[at + 2:]]


def helper_in_front() -> int:
    """The worker's child for an investigation: the real helper whose job container is this script, in this mode."""
    from defender import job_host
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
    from defender.tests.support.jobs._job_helper import ContainerStandIn
    from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

    root = Path(__file__).resolve().parents[4]
    job, tenant = argv[argv.index("--job") + 1], argv[argv.index("--tenant") + 1]

    def entry(container) -> int:
        env = {k: v for k, v in container.env.items() if v is not None}
        env.update(PATH=os.environ["PATH"], PYTHONPATH=f"{root}{os.pathsep}{os.environ.get('PYTHONPATH', '')}")
        return subprocess.run([sys.executable, str(Path(__file__).resolve()), mode, commit, str(marks),  # noqa: S603
                               "--job", job, "--tenant", tenant],
                              env=env, cwd=str(root), stdin=subprocess.DEVNULL, check=False).returncode

    return job_host.main(["--kind", "investigation", "--job", job, "--tenant", tenant,
                          "--parent-pid", argv[argv.index("--parent-pid") + 1]],
                         docker=ContainerStandIn(entry), signer=A.MarkedSigner(),
                         publish=lambda *a, **k: B.fresh(commit))


def in_container(entry):
    """`entry` inside its job container; the worker's child (no job socket yet) runs the helper in front first."""
    from defender import job_socket

    return entry if os.environ.get(job_socket.SOCKET_ENV) else helper_in_front


def _socket(tenant: str, *, signing: dict | None = None, **launch):
    """The learning kinds' job socket stand-in (module doc); with `signing` (`passes`' keywords), it signs the job's
    passes as the helper does."""
    from defender.tests.support.jobs._socket_standin1170 import SocketStandIn, materialise, passes

    answers = {"export.materialise": materialise(tenant)}
    if signing is not None:
        launch["proxy_url"], answers["pass"] = passes(tenant, **signing)
    return SocketStandIn(tenant, launch=launch, answers=answers)


def family() -> int:
    from defender import box as box_mod
    from defender.learning.branch import job_entry
    from defender.tests.e2e import _1255_twin as TWIN
    from defender.tests.integrations.credential_proxy_1163 import _stream1412 as W
    from defender.tests.integrations.credential_proxy_1163._harness import FakeSigner
    from defender.tests.support.jobs._socket_standin1170 import handed_records
    from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv
    from defender.tests.learning.oracle.live_contracts import _spec1224 as S
    from defender.tests.support.learning.branch import _triplet_947 as T
    from defender.tests.support.learning.judge import _judge_921 as J

    from defender.integrations.elastic_adapter import search_envelope
    from defender.tests.e2e._lead_zero_808 import EVENTS_INDEX

    PROXY_REPLY = W.fmt().encode_body(json.dumps(search_envelope(EVENTS_INDEX, [], 0, False, "desc")).encode()) \
        + W.fmt().encode_final(W.final_record())
    tenant, source = argv[argv.index("--tenant") + 1], argv[argv.index("--source") + 1]
    runs = Path(os.environ["DEFENDER_DATA_ROOT"]) / tenant / "runs"

    def sibling(sibling_argv, *, env=None, **_kw) -> int:
        """A real sibling's `run.py --tenant T --episode E --world W`, in this process, MAIN continuing the script."""
        recording = TWIN.Recording(sibling_argv[sibling_argv.index("--world") + 1])
        # No Docker daemon here: the sibling's box start fails and the operator's opt-out, set for this sibling
        # alone, turns it into production's unboxed mode (as `_replay_harness.production_unboxed_box` does).
        # Its tree is walked by the real reap scan, so the family's verification can archive it.
        # Its elastic is on the credential proxy, and a sibling that cannot sign or reach the proxy loses its access and
        # ends `proxy-access` (#1363 O1, O5): it gets the stand-in's signer and a stand-in proxy answering every read
        # with an empty result, as the reads these replays never judged did before (a failed call the run went on from).
        with RH._unsandboxed_allowed(), W.fake_proxy(PROXY_REPLY, ended=True) as proxy_url:
            TWIN.run_main(sibling_argv[2:], recording, main_turns=after_the_gather(),
                          clock=TWIN.SteppingClock(TWIN.ARM_CLOCK_START), scrub=box_mod.scrub,
                          signer=FakeSigner("flow1344"), proxy_url=proxy_url)
        (marks / f"sibling-{recording.label}").write_text(str(recording.exit_code), encoding="utf-8")
        return recording.exit_code if isinstance(recording.exit_code, int) else 1

    episode = Path(os.environ["DEFENDER_DATA_ROOT"]) / tenant / "episodes" / argv[argv.index("--job") + 1]

    def judge(*a, **kw) -> str:
        """The scripted judge. Its finding contrasts the worlds' reports by the world ids this launch minted, so the
        reply is written when the judge is first asked (a pointer naming no archived world is dropped unresolved)."""
        if not scripted:
            evidence = [f"worlds/{T.world_id(episode, label)}/report.md" for label in ("a", "b", "c")]
            finding = J.finding_doc(bucket="lead-quality", subject="defender", topic="the lead was never revisited",
                                    evidence=evidence)
            world = J.reply_doc(findings=[finding])
            world.update(bucket="lead-quality", systems=["idp"])
            scripted.append(J.scripted_judge(default=S.as_reply_text(world),
                                             family_default=S.as_reply_text(J.family_reply())))
        return scripted[0](*a, **kw)

    scripted: list = []
    # The run tenant's own systems: its gather grant names the product adapters' verbs, so the launcher reads its own
    # roster (no `roster=`). Its elastic is reached through the credential proxy (#1391), so pre-flight signs a read
    # token: the tenant's records hold a live generation with a sign login, as the siblings' and the investigation's
    # do (`directory_for_argv`), the signature is a stand-in's, and the proxy's address is one nothing answers at
    # (`PROXY_URL`). Every call the source made is in its capture, so pre-flight reads nothing live through it.
    seams = dict(questioner=S.questioner_for(), preflight=S.no_preflight, live_tree=T.source_capture(),
                 judge=judge, oracle=S.oracle(then=S.submit(_captured(runs, source), S.EMPTY_CLAIM)).model,
                 verifier=S.passing_verifier().model, directory=directory_for_argv(argv), spawn=sibling,
                 signer=FakeSigner("flow1344"), proxy_url=PROXY_URL)
    (marks / "runs").write_text(str(runs), encoding="utf-8")
    if os.environ.get("FLOW_DAMAGE") == "store-version":
        _store_from_a_newer_format(runs, source)
    try:
        # Pre-flight signs its pass up front (#1363): the helper signs it, over the tenant's one proxied system.
        signing = dict(reads=("elastic",), directory=seams["directory"], proxy_url=PROXY_URL, signer=seams["signer"])
        with _socket(tenant, kind="learning", job=argv[argv.index("--job") + 1], signing=signing,
                     records=handed_records(seams["directory"], tenant)) as helper:
            job_entry.main(_in_container_argv(), environ=helper.environ(), **seams)
    except SystemExit as stop:
        return stop.code if isinstance(stop.code, int) else 1
    return 0


def _captured(runs: Path, source: str) -> object:
    """What the source's elastic answered its lead (every call it made answered these rows), as the oracle's base
    submission: each world's served answer keeps the shape the source was answered in. `None` when the source has no
    such capture (a run the family step refuses before pre-flight)."""
    import json

    raw = runs / source / "gather_raw" / LEAD / "0.json"
    return json.loads(raw.read_text(encoding="utf-8")) if raw.is_file() else None


def _store_from_a_newer_format(runs: Path, investigation: str) -> None:
    """The source's session database as a store of another format version would leave it (L5)."""
    import json
    import sqlite3

    from defender.tests.support.jobs._jobs1342 import session_db

    case = json.loads((runs / f"{investigation}.session-pointer.json").read_text(encoding="utf-8"))["case_id"]
    path = session_db(runs, case)
    assert path.is_file(), f"premise: the run's session database is at {path}"
    with sqlite3.connect(path) as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.execute("PRAGMA user_version = 99")


def post_step() -> int:
    from defender.learning.branch import post_step as step
    from defender.tests.support.learning.core._store1278 import call

    tenant = argv[argv.index("--tenant") + 1]

    def gate(*_a, **_k) -> int:
        # #1278: the findings the learning store holds for the tenant (both channels), not a queue file's rows.
        held = [i for i in call(os.environ["DEFENDER_DATABASE_DSN"], "work", tenant)
                if i.kind in ("finding", "questioner_finding")]
        (marks / "gate").write_text(str(len(held)), encoding="utf-8")
        return 0

    try:
        job = argv[argv.index("--job") + 1] if "--job" in argv else None
        with _socket(tenant, kind="post-step", job=job) as helper:
            step.main(_in_container_argv(), environ=helper.environ(), author_tick=gate)
    except SystemExit as stop:
        return stop.code if isinstance(stop.code, int) else 1
    return 0


sys.exit({"investigate": in_container(investigate),
          "investigate-no-gather": in_container(functools.partial(investigate, gathers=False)),
          "family": family, "post-step": post_step}[mode]())
