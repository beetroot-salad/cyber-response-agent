"""#1344 e2e children, started by the real worker: `python _flow_entry1344.py <mode> <commit> <marks> <remote> <args...>`
(`<remote>`: the tenant's bare Forgejo repository, which the knowledge fetch reads: #1618, `_fetch_standin_1618`).

- `investigate`: the real per-job host helper (`job_host.main`, #1170) in front of the real job entry (`run.job_main`) over
  the replay driver, as `_helper_child1170.py` runs it: the helper's docker is the stand-in (`ContainerStandIn`) whose job
  container is this script again, in the same mode, as a real process given only the container's environment (the job
  socket set: the in-container branch). MAIN writes a document, dispatches one lead (`gather`) whose query reaches a
  stand-in elastic, writes the rest and closes: a completed run whose one `gather` response is a legal fork point.
- `investigate-no-gather`: the same run with no `gather`, so no fork point exists.
- `family`: the real per-job host helper (kind `learning`) in front of the real learning job entry (`job_entry.main`) in
  its job container (#1170 A6), as for `investigate`: the helper's docker is the stand-in whose job container is this
  script, in this mode. Every paid model is a script and the siblings are real `run.main` processes' in-process
  equivalent (`_1255_twin.run_main`) in the container's process (its job socket set: the in-container sibling, whose run
  copy the helper makes, `copy.make(world=)`), continuing MAIN's script after the fork. Args: `--job <id> --tenant <T>
  --source <investigation id> [--parent-pid <pid>]`.
- `post-step`: the real post-step inside its job container, with a recording drain gate (`<marks>/gate`, holding the
  queue's size when it ran).

#1546: every helper in front of a job that pushes evidence (`investigate*`, `family`) is configured with the real store
(`DEFENDER_EVIDENCE_*` in the worker's environment, the tenant's key login in `LOGIN_ENV`), and the learning job reads its
source only as the investigation's accepted bundle (r10: nothing of the source stays on the host). The post-step's job
socket is a stand-in (`_socket_standin1170.SocketStandIn`: the helper's `launch` facts): its gate is the subject here,
and the post-step helper's own work is `tests/jobs/test_job_helper_learning.py`'s."""
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

mode, commit, marks, remote, argv = sys.argv[1], sys.argv[2], Path(sys.argv[3]), sys.argv[4], sys.argv[5:]
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
    out = list(argv)
    for flag in ("--parent-pid", "--alert-digest"):  # the worker's start hands both to the helper, never to the container's entry (C-1)
        if flag in out:
            at = out.index(flag)
            del out[at:at + 2]
    return out


#: Where the worker's child finds the tenant's evidence-key login (`{addr, role_id, secret_id, mount}`), as
#: `_helper_child1546_replay.py` takes it; popped here, so no job container is handed it.
LOGIN_ENV = "DEFENDER_TEST_EVIDENCE_LOGIN"


def helper_in_front() -> int:
    """The worker's child for a job: the real helper (kind `investigation`, or `learning` for `family`) over the real evidence
    store (`DEFENDER_EVIDENCE_*` from the worker's environment, the key login from `LOGIN_ENV`; #1546 r8: a helper without
    either is refused at setup), whose job container is this script, in this mode, given only the container's environment."""
    from defender import evidence, job_host
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
    from defender.tests.support.jobs._job_helper import ContainerStandIn
    from defender.tests.support.tenancy._fetch_standin_1618 import in_process_fetch

    root = Path(__file__).resolve().parents[4]
    login = json.loads(os.environ.pop(LOGIN_ENV))
    job, tenant = argv[argv.index("--job") + 1], argv[argv.index("--tenant") + 1]
    kind = "learning" if mode == "family" else "investigation"
    # The worker's command line, as it hands it to the helper (`job_entry_argv`): a learning job names its source before
    # the parent pid, an investigation its alert digest after it (C-1).
    helper_argv = ["--kind", kind, "--job", job, "--tenant", tenant]
    if kind == "learning":
        helper_argv += ["--source", argv[argv.index("--source") + 1]]
    helper_argv += ["--parent-pid", argv[argv.index("--parent-pid") + 1]]
    if kind == "investigation":
        helper_argv += ["--alert-digest", argv[argv.index("--alert-digest") + 1]]

    def entry(container) -> int:
        env = {k: v for k, v in container.env.items() if v is not None}
        env.update(PATH=os.environ["PATH"], PYTHONPATH=f"{root}{os.pathsep}{os.environ.get('PYTHONPATH', '')}")
        return subprocess.run([sys.executable, str(Path(__file__).resolve()), mode, commit, str(marks), remote,  # noqa: S603
                               *_in_container_argv()],
                              env=env, cwd=str(root), stdin=subprocess.DEVNULL, check=False).returncode

    return job_host.main(helper_argv, docker=ContainerStandIn(entry), signer=A.MarkedSigner(), fetch=in_process_fetch(remote),
                         evidence_keys=evidence.EvidenceKeys(addr=login["addr"], role_id=login["role_id"],
                                                             secret_id=login["secret_id"], mount=login["mount"]))


def in_container(entry):
    """`entry` inside its job container; the worker's child (no job socket yet) runs the helper in front first."""
    from defender import job_socket

    return entry if os.environ.get(job_socket.SOCKET_ENV) else helper_in_front


def _socket(tenant: str, *, signing: dict | None = None, answers: dict | None = None, **launch):
    """The post-step's job socket stand-in (module doc); with `signing` (`passes`' keywords), it signs the job's
    passes as the helper does; `answers` adds to (or replaces) its own."""
    from defender.tests.support.jobs._socket_standin1170 import SocketStandIn, copy_make, passes

    answers = {"copy.make": copy_make(tenant, remote), **(answers or {})}
    if signing is not None:
        launch["proxy_url"], answers["pass"] = passes(tenant, **signing)
    return SocketStandIn(tenant, launch=launch, answers=answers)


def family() -> int:
    from defender import box as box_mod
    from defender.learning.branch import job_entry
    from defender.tests.e2e import _1255_twin as TWIN
    from defender.tests.integrations.credential_proxy_1163 import _stream1412 as W
    from defender.tests.integrations.credential_proxy_1163._harness import FakeSigner
    from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv
    from defender.tests.learning.oracle.live_contracts import _spec1224 as S
    from defender.tests.support.learning.branch import _triplet_947 as T
    from defender.tests.support.learning.judge import _judge_921 as J

    from defender.integrations.elastic_adapter import search_envelope
    from defender.tests.e2e._lead_zero_808 import EVENTS_INDEX

    PROXY_REPLY = W.fmt().encode_body(json.dumps(search_envelope(EVENTS_INDEX, [], 0, False, "desc")).encode()) \
        + W.fmt().encode_final(W.final_record())
    tenant = argv[argv.index("--tenant") + 1]
    # The container's own data root (#1546 A-O9: the claim's root, never the host's tenant folder).
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
            evidence = [f"worlds/{T.world_id(episode, label)}/closing" for label in ("a", "b", "c")]
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
                 judge=judge, oracle=S.oracle(then=S.submit()).model,
                 verifier=S.passing_verifier().model, directory=directory_for_argv(argv), spawn=sibling,
                 signer=FakeSigner("flow1344"), proxy_url=PROXY_URL)
    (marks / "runs").write_text(str(runs), encoding="utf-8")  # the family step started, in its container's own root
    try:
        # #1546: the real learning helper is in front (`helper_in_front`): it pins the claim's commit, serves the source as
        # its accepted bundle (`evidence.pull`, the claim's one input; r10: nothing of the source is on the host), signs
        # the passes, makes each sibling's copy and stages the outcome and pushes the worker decides the end from.
        return job_entry.main(_in_container_argv(), environ=os.environ, **seams)
    except SystemExit as stop:
        return stop.code if isinstance(stop.code, int) else 1


def _captured(runs: Path, source: str) -> object:
    """What the source's elastic answered its lead (every call it made answered these rows), as the oracle's base
    submission: each world's served answer keeps the shape the source was answered in. `None` when the source has no
    such capture (a run the family step refuses before pre-flight)."""
    import json

    raw = runs / source / "gather_raw" / LEAD / "0.json"
    return json.loads(raw.read_text(encoding="utf-8")) if raw.is_file() else None


def post_step() -> int:
    from defender.learning.branch import post_step as step
    from defender.tests.support.jobs._socket_standin1170 import stubbed_port
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
        with _socket(tenant, kind="post-step", job=job) as helper, stubbed_port():  # #1487: the gate stands for the tick; its store is not looked at
            step.main(_in_container_argv(), environ=helper.environ(), author_tick=gate)
    except SystemExit as stop:
        return stop.code if isinstance(stop.code, int) else 1
    return 0


sys.exit({"investigate": in_container(investigate),
          "investigate-no-gather": in_container(functools.partial(investigate, gathers=False)),
          "family": in_container(family), "post-step": post_step}[mode]())
