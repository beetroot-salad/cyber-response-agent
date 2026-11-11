"""#1170 review of PR #1467: the cases the review found unguarded, each at the seam that now owns it.

- Two concurrent `box.start` of one run's shell box: only one starts (the id is reserved before the start).
- A read pass from the helper is the asking call's `AdapterFault` on every in-container path (`credential_proxy.helper_access`),
  so the verb layer records a refusal as the proxy's own fault instead of crashing.
- A learning job's siblings' run pages are copied to the publish area after the container, as an investigation's is."""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

import pytest

from defender import job_socket
from defender.credential_proxy import helper_access
from defender.job_host import _common, _learning
from defender.job_host._session import Prepared, Registry, Session
from defender.job_socket import Refused
from defender.kit.faults import AdapterFault

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

class _Page:
    def __init__(self, text: str | None) -> None:
        self._text = text

    def read(self) -> str | None:
        if self._text is None:
            raise FileNotFoundError("no page")
        return self._text


class _Handle:
    def __init__(self, run_id: str, page: str | None) -> None:
        self.run_dir = Path("/episodes/e/runs") / run_id
        self.observability = type("O", (), {"runtime_html": _Page(page)})()


class _Episode:
    def __init__(self, pages: dict[str, str | None]) -> None:
        self._pages = pages

    def __enter__(self) -> _Episode:
        return self

    def __exit__(self, *_exc: object) -> None:
        return None

    def open(self, run_id: Any) -> _Handle:
        return _Handle(str(run_id), self._pages[str(run_id)])


class _Tenant:
    def __init__(self, pages: dict[str, str | None]) -> None:
        self._pages = pages

    def runs_repository(self) -> Any:
        pages = self._pages
        return type("R", (), {"episode": lambda _self, _job: _Episode(pages)})()


def test_a_learning_jobs_sibling_pages_are_each_copied_after_its_container_and_a_missing_one_is_skipped(monkeypatch):
    """`_learning_exited` on a container that ran: every sibling's saved page goes to `mirror_page` under its run id; a sibling
    with no page copies nothing."""
    from defender.presentation import visualize_run

    other = "b04cb885-466e-4ecd-89c7-4cfdd0e4f8b2"
    copied: list[tuple[str, str]] = []
    monkeypatch.setattr(visualize_run, "mirror_page",  # lint-monkeypatch: ok — the dev copy's own write is publish_page's tests'
                        lambda page, run_id, _tenant: copied.append((run_id, page)) or "copied")
    tenant = _Tenant({RUN: "<html>one</html>", other: None})
    state = _learning._Learning(tenant, "c" * 40, Path("/scratch"))
    state.siblings = dict.fromkeys((RUN, other))  # only the ids are read
    session = _session()
    session.kind = "learning"
    session.job_id = "00000000-0000-4000-8000-000000000000"
    session.prepared = Prepared(launch={}, command=[], state=state)

    _learning._learning_exited(session, 0)
    assert copied == [(RUN, "<html>one</html>")]
