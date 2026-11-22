"""#1170 review of PR #1467: the cases the review found unguarded, each at the seam that now owns it.

- Two concurrent `box.start` of one run's shell box: only one starts (the id is reserved before the start).
- A read pass from the helper is the asking call's `AdapterFault` on every in-container path (`credential_proxy.helper_access`),
  so the verb layer records a refusal as the proxy's own fault instead of crashing.
- A learning job's sibling pages are the renderer's bytes it pushes over the socket (#1546 A-O8), stored as pushed."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest
from defender.tests.support.evidence._evidence1546 import evidence_keys, garage  # noqa: F401 — fixtures
from defender.tests.support.jobs import _helper_evidence1546 as H
from defender.tests.support.jobs import _job_helper as J
from defender.tests.support.shared._openbao1163 import openbao  # noqa: F401 — fixture

from defender import job_socket
from defender.credential_proxy import helper_access
from defender.job_host import _common
from defender.job_host._session import Registry, Session
from defender.job_socket import Refused
from defender.kit.faults import AdapterFault

evidence_store = H.evidence_store
process_state = J.process_state
scene = H.fresh_scene

RUN = "af3ba774-355d-4dbc-b8b6-3becc9d3e7a1"


def _session(**kw: Any) -> Session:
    return Session(kind="investigation", job_id=RUN, tenant_id="acme", source=None, root=None,
                   root_folder=Path("/nonexistent"), claim="claim", docker=None, defender_dir=Path("/nonexistent"), **kw)


# --- one run box per id, under concurrent starts -----------------------------------------------------------------------

def test_two_concurrent_starts_of_one_runs_shell_box_start_it_once_and_refuse_the_other():
    """The second `box.start(shell, id)` arriving while the first is still starting is refused as already running; the starter
    runs once. Control: once the first start failed, the id is free again and a start goes through."""
    session = _session()
    session.minted.add(RUN)
    registry = Registry()
    entered, release = threading.Event(), threading.Event()
    starts: list[str] = []
    fail_next = [False]

    def starter(_session: Session, ident: str) -> Any:
        from defender.box import BoxFault

        starts.append(ident)
        if fail_next[0]:
            fail_next[0] = False
            raise BoxFault("the daemon refused")
        entered.set()
        release.wait(10)
        return object()

    registry.box_kinds[("investigation", "shell")] = starter
    answers: list[Any] = []
    first = threading.Thread(target=lambda: answers.append(
        _common._box_start(session, {"kind": "shell", "id": RUN}, registry=registry)))
    first.start()
    assert entered.wait(10), "premise: the first start is under way"
    with pytest.raises(Refused, match="already running") as second:
        _common._box_start(session, {"kind": "shell", "id": RUN}, registry=registry)
    assert second.value.code == "box-start"
    release.set()
    first.join(10)
    assert len(answers) == 1
    assert answers[0]["handle"]
    assert starts == [RUN], "the second start reached the starter"

    other = _session()
    other.minted.add(RUN)
    fail_next[0] = True
    with pytest.raises(Refused, match="did not start"):
        _common._box_start(other, {"kind": "shell", "id": RUN}, registry=registry)
    release.set()
    assert _common._box_start(other, {"kind": "shell", "id": RUN}, registry=registry)["handle"], \
        "a failed start left its id reserved"


# --- a pass from the helper is the call's AdapterFault -----------------------------------------------------------------

@pytest.mark.parametrize("failure", [Refused("the helper is stopping", "signalled"), ConnectionResetError("gone"),
                                     KeyError("token")], ids=["refused", "socket-gone", "no-token"])
def test_every_in_container_pass_maps_a_helper_failure_to_the_calls_adapter_fault(failure):
    """`helper_access` (the investigation entry's pass and pre-flight's `JobContainer.access`) turns the helper's refusal, a socket
    fault or an answer without a token into `AdapterFault`. Control: a good answer is the token, asked once."""
    from defender.learning.branch.container import JobContainer

    def failing(_name: str, **_fields: Any) -> dict[str, Any]:
        raise failure

    for access in (helper_access(failing, RUN, "http://proxy"),
                   JobContainer(ask=failing, launch={"proxy_url": "http://proxy"}).access(RUN)):
        assert access is not None
        with pytest.raises(AdapterFault):
            access.token()

    asked: list[tuple[str, dict[str, Any]]] = []

    def good(name: str, **fields: Any) -> dict[str, Any]:
        asked.append((name, fields))
        return {"token": "t0k", "expires_at": 4e9}

    access = JobContainer(ask=good, launch={"proxy_url": "http://proxy"}).access(RUN)
    assert access is not None
    assert access.proxy_url == "http://proxy"
    assert access.token() == access.token() == "t0k"
    assert asked == [("pass", {"id": RUN})]


def test_the_forge_cap_is_one_value_for_the_container_and_the_helper():
    """The container clamps its forge ask to the cap the helper refuses past: one constant, `job_socket.FORGE_TOKEN_CAP`."""
    from defender.learning.branch import container

    asked: list[float] = []
    credential = container.JobContainer(ask=lambda _n, **f: asked.append(f["min_validity"]) or {"token": "f"},
                                        launch={"tenant": "acme"}).forge_credential()
    credential.token(min_validity=10_000)
    assert asked == [job_socket.FORGE_TOKEN_CAP]


# --- the siblings' run pages ---------------------------------------------------------------------------------------------

@pytest.mark.postgres
@pytest.mark.openbao
@pytest.mark.garage
def test_a_learning_jobs_sibling_pages_stored_are_the_bytes_it_pushed_per_arm_and_nothing_is_copied_out(
        scene, evidence_store, tmp_path):
    """#1546 A-O8 (conflict updated: the page mirror is gone): each rendered arm's page and the episode page are stored as the
    bytes the learning job pushed over its socket, though every arm's folder holds another `runtime.html` (which nothing
    reads back), and the publish folder stays empty. (A-O8, D3)"""
    import uuid

    from defender.tests.support.evidence._facts1546 import sent_arm, sent_arms
    from defender.tests.support.jobs import _helper_evidence1546 as H
    from defender.tests.support.jobs._job_helper import host_path

    planted = H.plant(scene, "learning")
    arms = {str(uuid.uuid4()): str(uuid.uuid4()) for _ in range(2)}
    pages = {run: f"<html>the renderer's page for {run}</html>".encode() for run in arms}
    episode_page = b"<html>the episode page</html>"
    publish_dir = tmp_path / "published"
    publish_dir.mkdir()

    def job(c: Any) -> int:
        root = host_path(c.mounts, str(H.job_root(scene) / scene.tenant))
        for run in arms:
            folder = root / "episodes" / planted.owner / "runs" / run
            folder.mkdir(parents=True, exist_ok=True)
            (folder / "runtime.html").write_bytes(b"<html>written in the arm's folder</html>")  # never read back
        H.send(c, "arms", record=sent_arms(*arms.items()))
        for run in arms:
            H.send(c, "arm", run_id=run, record=sent_arm())
            H.put_object(c, H.arm_page(run), pages[run])
        H.send(c, "outcome", record=H.learning_outcome())
        H.put_object(c, H.EPISODE_PAGE, episode_page)
        return 0

    with pytest.MonkeyPatch.context() as patch:
        patch.setenv("DEFENDER_DEPLOYMENT", "dev")
        patch.setenv("DEFENDER_RUN_VISUALIZATIONS_DIR", str(publish_dir))
        H.drive(scene, planted, job, **evidence_store.seams)
    rows = H.uploads(scene.dsn, scene.claim)
    for obj, data in [(H.arm_page(run), pages[run]) for run in arms] + [(H.EPISODE_PAGE, episode_page)]:
        assert rows[obj]["status"] == "uploaded", obj
        assert evidence_store.read(scene.tenant, "learning", planted.owner, scene.claim, obj,
                                   rows[obj]["wrapped_key"]) == data, obj
    assert [p for p in publish_dir.rglob("*") if p.is_file()] == [], "a page was copied to the publish folder"
