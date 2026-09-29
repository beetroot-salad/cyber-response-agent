"""#1131 — the platform API's HTTP layer: the route set, the login seam, and how each port's
answer maps onto a response.

WHAT IS DRIVEN. The real app (`api.app.create_app`) through starlette's `TestClient`, over a
SCRIPTED fake: every port method answers what the test says, and a call the test did not script
fails it. So each test pins what the API does with an answer, never what a store would answer.
The data rules behind the answers (request-id replay, one live investigation per alert, what may
be cancelled, deleted or learned from) are the store's (`api/ports.py`, #1082) and are tested
there, against the real implementation — not here against a re-derivation of them.
"""
from __future__ import annotations

import datetime as _dt
import json
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("fastapi")

from fastapi.testclient import TestClient  # noqa: E402

from defender.api.app import MAX_PAGE, create_app  # noqa: E402
from defender.api.demo import demo_deps, demo_tokens  # noqa: E402
from defender.api.fakes import (  # noqa: E402
    InMemoryAudit,
    InMemorySecrets,
    InMemoryStore,
    StubArtifactLinks,
    StubSystemChecker,
    TokenAuthenticator,
)
from defender.api.models import (  # noqa: E402
    Alert,
    AlertSummary,
    Investigation,
    LearningJob,
    Lesson,
    System,
    SystemCheck,
    SystemSettings,
)
from defender.api.ports import (  # noqa: E402
    ApiDeps,
    Conflict,
    NotFound,
    Principal,
    UnknownReference,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
NOW = _dt.datetime(2026, 9, 28, 12, 0, tzinfo=_dt.UTC)

A = "tenant-a"
USER = "ann@a.example"
AUTH = {"Authorization": "Bearer tok-a"}
AUTH_B = {"Authorization": "Bearer tok-b"}
BASE = "http://testserver"

ALERT = Alert(
    alert_id="al-1", vendor="tickets", vendor_ticket_id="T-1", title="t", severity="high",
    rule="r", fired_at=NOW, changed_at=NOW, received_at=NOW, raw={"id": "al-1"},
)
SUMMARY = AlertSummary.model_validate(ALERT.model_dump(exclude={"raw"}))
INV = Investigation(
    investigation_id="inv-1", alert_id="al-1", status="completed", disposition="benign",
    cost_usd=1.5, created_at=NOW, artifacts=["report.md", "gather_raw/L1/0.json"],
)
JOB = LearningJob(
    learning_job_id="lj-1", investigation_id="inv-1", alert_id="al-1", status="queued",
    trigger="explicit", created_at=NOW,
)
LESSON = Lesson(lesson_id="le-1", title="t", description="d", status="live")
SETTINGS = SystemSettings(system_id="tix", kind="ticketing", display_name="T", enabled=True,
                          settings={"queue": "sec"})
SIGNED = "https://blobs.invalid/signed?sig=1"

#: #1131's "API" section, verbatim as (method, path). The contract this stub exists to pin.
PUBLIC_ROUTES = {
    ("GET", "/alerts"),
    ("GET", "/alerts/{alert_id}"),
    ("POST", "/investigations"),
    ("GET", "/investigations"),
    ("GET", "/investigations/{investigation_id}"),
    ("POST", "/investigations/{investigation_id}/cancel"),
    ("DELETE", "/investigations/{investigation_id}"),
    ("GET", "/investigations/{investigation_id}/artifacts/{key}"),
    ("POST", "/learning-jobs"),
    ("GET", "/learning-jobs"),
    ("GET", "/learning-jobs/{learning_job_id}"),
    ("GET", "/lessons"),
    ("GET", "/systems"),
    ("PUT", "/systems/{system_id}"),
    ("PUT", "/systems/{system_id}/credentials"),
    ("POST", "/systems/{system_id}/check"),
}

#: One successful call per route: (route, concrete path, body, the port answers it needs).
HAPPY: list[tuple[tuple[str, str], str, dict[str, Any] | None, dict[str, Any]]] = [
    (("GET", "/alerts"), "/alerts", None, {"list_alerts": [SUMMARY]}),
    (("GET", "/alerts/{alert_id}"), "/alerts/al-1", None, {"get_alert": ALERT}),
    (("POST", "/investigations"), "/investigations",
     {"alert_id": "al-1", "client_request_id": "r1"}, {"create_investigation": (INV, True)}),
    (("GET", "/investigations"), "/investigations", None, {"list_investigations": [INV]}),
    (("GET", "/investigations/{investigation_id}"), "/investigations/inv-1", None,
     {"get_investigation": INV}),
    (("POST", "/investigations/{investigation_id}/cancel"), "/investigations/inv-1/cancel", None,
     {"cancel_investigation": INV}),
    (("DELETE", "/investigations/{investigation_id}"), "/investigations/inv-1", None,
     {"delete_investigation": None}),
    (("GET", "/investigations/{investigation_id}/artifacts/{key}"),
     "/investigations/inv-1/artifacts/report.md", None,
     {"get_investigation": INV, "signed_url": SIGNED}),
    (("POST", "/learning-jobs"), "/learning-jobs",
     {"investigation_id": "inv-1", "client_request_id": "r1"}, {"create_learning_job": (JOB, True)}),
    (("GET", "/learning-jobs"), "/learning-jobs", None, {"list_learning_jobs": [JOB]}),
    (("GET", "/learning-jobs/{learning_job_id}"), "/learning-jobs/lj-1", None,
     {"get_learning_job": JOB}),
    (("GET", "/lessons"), "/lessons", None, {"list_lessons": [LESSON]}),
    (("GET", "/systems"), "/systems", None,
     {"list_systems": [SETTINGS], "has_credentials": False}),
    (("PUT", "/systems/{system_id}"), "/systems/tix", {"kind": "ticketing", "display_name": "T"},
     {"put_system": (SETTINGS, True), "has_credentials": False}),
    (("PUT", "/systems/{system_id}/credentials"), "/systems/tix/credentials",
     {"credentials": {"api_token": "x"}},
     {"get_system": SETTINGS, "has_credentials": False, "put_credentials": None}),
    (("POST", "/systems/{system_id}/check"), "/systems/tix/check", None,
     {"get_system": SETTINGS, "has_credentials": True,
      "check": SystemCheck(ok=True, detail="fine")}),
]


class Scripted:
    """Every port the routes call. `answers` maps a port method's name to what it returns, an
    exception it raises, or a function of its arguments. Each call is recorded; an unscripted
    one fails the test, so a test states exactly what the API may ask of the platform."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name.startswith("_"):
            raise AttributeError(name)

        def call(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((name, args, kwargs))
            if name not in self.answers:
                raise AssertionError(f"unscripted port call: {name}{args}")
            answer = self.answers[name]
            if isinstance(answer, BaseException):
                raise answer
            return answer(*args, **kwargs) if callable(answer) else answer

        return call

    def called(self, name: str) -> list[tuple[tuple[Any, ...], dict[str, Any]]]:
        return [(args, kwargs) for n, args, kwargs in self.calls if n == name]


class Api:
    def __init__(self, **answers: Any) -> None:
        self.ports = Scripted(answers)
        self.audit = InMemoryAudit()
        ports: Any = self.ports
        self.client = TestClient(create_app(ApiDeps(
            authenticator=TokenAuthenticator({
                "tok-a": Principal(tenant_id=A, user_id=USER),
                "tok-b": Principal(tenant_id="tenant-b", user_id="bob@b.example"),
            }),
            alerts=ports, investigations=ports, learning_jobs=ports, lessons=ports,
            systems=ports, secrets=ports, checker=ports, artifact_links=ports,
            audit=self.audit, clock=lambda: NOW,
        )))

    def actions(self) -> list[str]:
        return [e.action for e in self.audit.events]


# --- the contract --------------------------------------------------------------------------


def test_the_published_routes_are_exactly_1131s_list() -> None:
    doc = Api().client.get("/openapi.json").json()
    documented = {(method.upper(), path) for path, ops in doc["paths"].items() for method in ops}
    assert documented == PUBLIC_ROUTES
    assert doc["components"]["securitySchemes"]["HTTPBearer"]["scheme"] == "bearer"


def test_the_happy_path_table_covers_every_route() -> None:
    assert {route for route, *_ in HAPPY} == PUBLIC_ROUTES


def test_the_api_never_loads_the_runtime_or_the_learning_loop() -> None:
    probe = (
        "import json, sys; import defender.api.app, defender.api.demo, defender.api.serve; "
        "print(json.dumps(sorted(m for m in sys.modules "
        "if m.startswith(('defender.runtime', 'defender.learning')))))"
    )
    out = subprocess.run(
        [sys.executable, "-c", probe], cwd=REPO_ROOT, capture_output=True, text=True,
        encoding="utf-8", check=True,
    )
    assert json.loads(out.stdout) == []


# --- login and tenant ----------------------------------------------------------------------


@pytest.mark.parametrize(("route", "path", "body", "answers"), HAPPY, ids=lambda v: str(v))
def test_every_route_asks_the_ports_as_the_logged_in_tenant(
    route: tuple[str, str], path: str, body: dict[str, Any] | None, answers: dict[str, Any]
) -> None:
    api = Api(**answers)
    response = api.client.request(route[0], path, headers=AUTH, json=body, follow_redirects=False)
    assert response.status_code < 400, response.text
    assert api.ports.calls, "the route asked no port"
    assert {args[0] for _, args, _ in api.ports.calls} == {A}
    assert all(e.tenant_id == A and e.user_id == USER for e in api.audit.events)


@pytest.mark.parametrize(("route", "path", "body", "answers"), HAPPY, ids=lambda v: str(v))
@pytest.mark.parametrize("headers", [{}, {"Authorization": "Bearer nope"}, {"Authorization": "Basic tok-a"}])
def test_every_route_refuses_a_caller_without_a_known_bearer_token(
    route: tuple[str, str], path: str, body: dict[str, Any] | None, answers: dict[str, Any],
    headers: dict[str, str],
) -> None:
    api = Api(**answers)
    response = api.client.request(route[0], path, headers=headers, json=body)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert api.ports.calls == []
    assert api.audit.events == []


@pytest.mark.parametrize(("path", "body"), [
    ("/investigations", {"alert_id": "al-1", "client_request_id": "r", "tenant_id": A}),
    ("/learning-jobs", {"investigation_id": "inv-1", "client_request_id": "r", "tenant_id": A}),
])
def test_a_body_cannot_name_a_tenant(path: str, body: dict[str, str]) -> None:
    api = Api()
    assert api.client.post(path, headers=AUTH, json=body).status_code == 422
    assert api.ports.calls == []


# --- creates: 201 or replay ----------------------------------------------------------------


@pytest.mark.parametrize(("path", "body", "port", "record", "location", "action"), [
    ("/investigations", {"alert_id": "al-1", "client_request_id": "r1"}, "create_investigation",
     INV, "/investigations/inv-1", "investigation.start"),
    ("/learning-jobs", {"investigation_id": "inv-1", "client_request_id": "r1"},
     "create_learning_job", JOB, "/learning-jobs/lj-1", "learning_job.start"),
])
def test_a_create_is_a_201_with_location_only_when_the_store_created(
    path: str, body: dict[str, str], port: str, record: Any, location: str, action: str,
) -> None:
    created = Api(**{port: (record, True)})
    response = created.client.post(path, headers=AUTH, json=body)
    assert response.status_code == 201
    assert response.headers["Location"] == BASE + location
    assert response.json() == record.model_dump(mode="json")
    assert created.actions() == [action]
    assert created.ports.called(port) == [((A, *body.values()), {})]

    replayed = Api(**{port: (record, False)})
    response = replayed.client.post(path, headers=AUTH, json=body)
    assert response.status_code == 200
    assert "Location" not in response.headers
    assert response.json() == record.model_dump(mode="json")
    assert replayed.actions() == [], "a replay is not a second start"


def test_put_system_is_a_201_at_its_own_url_when_created_and_200_when_replaced() -> None:
    body = {"kind": "ticketing", "display_name": "T"}
    created = Api(put_system=(SETTINGS, True), has_credentials=False)
    response = created.client.put("/systems/tix", headers=AUTH, json=body)
    assert (response.status_code, response.headers["Location"]) == (201, BASE + "/systems/tix")
    replaced = Api(put_system=(SETTINGS, False), has_credentials=False)
    response = replaced.client.put("/systems/tix", headers=AUTH, json=body)
    assert response.status_code == 200
    assert "Location" not in response.headers
    assert created.actions() == replaced.actions() == ["system.update"]


# --- refusals ------------------------------------------------------------------------------


@pytest.mark.parametrize(("path", "port"), [
    ("/alerts/al-1", "get_alert"),
    ("/investigations/inv-1", "get_investigation"),
    ("/investigations/inv-1/artifacts/report.md", "get_investigation"),
    ("/learning-jobs/lj-1", "get_learning_job"),
])
def test_a_read_the_store_answers_none_is_a_404(path: str, port: str) -> None:
    api = Api(**{port: None})
    assert api.client.get(path, headers=AUTH, follow_redirects=False).status_code == 404
    assert api.audit.events == []


@pytest.mark.parametrize(("method", "path", "body", "port", "error", "code"), [
    ("POST", "/investigations/inv-1/cancel", None, "cancel_investigation", NotFound("x"), 404),
    ("POST", "/investigations/inv-1/cancel", None, "cancel_investigation", Conflict("x"), 409),
    ("DELETE", "/investigations/inv-1", None, "delete_investigation", NotFound("x"), 404),
    ("DELETE", "/investigations/inv-1", None, "delete_investigation", Conflict("x"), 409),
    ("POST", "/investigations", {"alert_id": "al-1", "client_request_id": "r"},
     "create_investigation", UnknownReference("x"), 422),
    ("POST", "/learning-jobs", {"investigation_id": "inv-1", "client_request_id": "r"},
     "create_learning_job", UnknownReference("x"), 422),
    ("POST", "/learning-jobs", {"investigation_id": "inv-1", "client_request_id": "r"},
     "create_learning_job", Conflict("x"), 409),
])
def test_a_store_refusal_maps_to_its_status_and_audits_nothing(
    method: str, path: str, body: dict[str, str] | None, port: str, error: Exception, code: int,
) -> None:
    api = Api(**{port: error})
    response = api.client.request(method, path, headers=AUTH, json=body)
    assert response.status_code == code
    assert response.json() == {"detail": "x"}
    assert api.audit.events == []


# --- artifacts -----------------------------------------------------------------------------


@pytest.mark.parametrize("key", ["report.md", "gather_raw/L1/0.json"])
def test_an_artifact_read_redirects_to_the_signed_link_and_is_audited(key: str) -> None:
    api = Api(get_investigation=INV, signed_url=SIGNED)
    response = api.client.get(f"/investigations/inv-1/artifacts/{key}", headers=AUTH,
                              follow_redirects=False)
    assert response.status_code == 307
    assert response.headers["Location"] == SIGNED
    assert response.headers["Cache-Control"] == "no-store"
    assert api.ports.called("signed_url") == [((A, "inv-1", key), {})]
    assert [(e.action, e.target, e.detail) for e in api.audit.events] == [("artifact.read", "inv-1", key)]


@pytest.mark.parametrize("key", ["runtime.html", "../other/report.md", "report.md/x"])
def test_only_keys_the_investigation_lists_are_answered(key: str) -> None:
    api = Api(get_investigation=INV)
    response = api.client.get(f"/investigations/inv-1/artifacts/{key}", headers=AUTH,
                              follow_redirects=False)
    assert response.status_code == 404
    assert api.ports.called("signed_url") == []
    assert api.audit.events == []


# --- systems and credentials ---------------------------------------------------------------


@pytest.mark.parametrize("has", [True, False])
def test_has_credentials_is_the_secret_stores_answer(has: bool) -> None:
    api = Api(list_systems=[SETTINGS], has_credentials=has,
              get_system=SETTINGS, check=lambda tenant, system: SystemCheck(ok=True, detail="x"))
    listed = api.client.get("/systems", headers=AUTH).json()["items"]
    assert listed == [System(**SETTINGS.model_dump(), has_credentials=has).model_dump(mode="json")]
    api.client.post("/systems/tix/check", headers=AUTH)
    ((_, checked), _), = api.ports.called("check")
    assert checked.has_credentials is has
    assert api.ports.called("has_credentials")[0] == ((A, "tix"), {})


def test_credentials_are_written_through_and_never_echoed_or_audited() -> None:
    secret = "s3cr3t-value-never-echoed"
    api = Api(get_system=SETTINGS, has_credentials=False, put_credentials=None)
    response = api.client.put("/systems/tix/credentials", headers=AUTH,
                              json={"credentials": {"api_token": secret}})
    assert (response.status_code, response.content) == (204, b"")
    assert api.ports.called("put_credentials") == [((A, "tix", {"api_token": secret}), {})]
    assert [(e.action, e.detail) for e in api.audit.events] == [("system.credentials", "fields: api_token")]
    assert secret not in repr(api.audit.events)


def test_credentials_for_an_unknown_system_are_refused_before_the_secret_store() -> None:
    api = Api(get_system=None)
    response = api.client.put("/systems/nope/credentials", headers=AUTH, json={"credentials": {"k": "v"}})
    assert response.status_code == 404
    assert api.ports.called("put_credentials") == []
    assert Api().client.put("/systems/tix/credentials", headers=AUTH,
                            json={"credentials": {}}).status_code == 422


# --- the boundary: malformed input never reaches a port ------------------------------------


@pytest.mark.parametrize("param", ["fired_after", "fired_before"])
def test_a_time_without_an_offset_is_refused_at_the_boundary(param: str) -> None:
    api = Api()
    response = api.client.get("/alerts", headers=AUTH, params={param: "2026-09-28T06:00:00"})
    assert response.status_code == 422
    assert api.ports.calls == []


def test_an_aware_time_and_the_filters_reach_the_store_as_given() -> None:
    api = Api(list_alerts=[SUMMARY])
    after = _dt.datetime(2026, 9, 28, 8, 0, tzinfo=_dt.timezone(_dt.timedelta(hours=2)))
    response = api.client.get("/alerts", headers=AUTH, params={
        "fired_after": after.isoformat(), "severity": "high", "limit": 7,
    })
    assert response.json() == {"items": [SUMMARY.model_dump(mode="json")], "next_cursor": None}
    ((tenant,), kwargs), = api.ports.called("list_alerts")
    assert tenant == A
    assert kwargs == {"fired_after": after, "fired_before": None, "severity": "high",
                      "after": None, "limit": 8}
    assert kwargs["fired_after"].utcoffset() == _dt.timedelta(hours=2)


@pytest.mark.parametrize(("method", "path", "body"), [
    ("GET", "/alerts/%E2%9C%93", None),
    ("GET", "/investigations/a%20b", None),
    ("GET", "/learning-jobs/-leading-dash", None),
    ("PUT", "/systems/%E2%9C%93", {"kind": "k", "display_name": "d"}),
    ("POST", "/systems/a%20b/check", None),
    ("POST", "/investigations", {"alert_id": "✓", "client_request_id": "r"}),
    ("POST", "/learning-jobs", {"investigation_id": "a b", "client_request_id": "r"}),
    ("GET", "/investigations?alert_id=%E2%9C%93", None),
])
def test_an_id_outside_the_grammar_is_refused_at_the_boundary(
    method: str, path: str, body: dict[str, str] | None
) -> None:
    api = Api()
    assert api.client.request(method, path, headers=AUTH, json=body).status_code == 422
    assert api.ports.calls == []
    assert api.audit.events == []


@pytest.mark.parametrize("limit", [0, MAX_PAGE + 1])
@pytest.mark.parametrize("path", ["/alerts", "/investigations", "/learning-jobs"])
def test_a_page_size_out_of_range_is_refused(path: str, limit: int) -> None:
    api = Api()
    assert api.client.get(path, headers=AUTH, params={"limit": limit}).status_code == 422
    assert api.ports.calls == []


def test_a_blank_client_request_id_is_refused() -> None:
    api = Api()
    assert api.client.post("/investigations", headers=AUTH,
                           json={"alert_id": "al-1", "client_request_id": ""}).status_code == 422
    assert api.ports.calls == []


def test_a_disposition_outside_the_vocabulary_cannot_be_served() -> None:
    with pytest.raises(ValueError, match="not a disposition"):
        Investigation(investigation_id="i", alert_id="a", status="completed", disposition="fine",
                      cost_usd=0.0, created_at=NOW)


def test_a_naive_time_cannot_be_served() -> None:
    with pytest.raises(ValueError, match="timezone"):
        Investigation(investigation_id="i", alert_id="a", status="queued", cost_usd=0.0,
                      created_at=NOW.replace(tzinfo=None))


# --- pagination ----------------------------------------------------------------------------

LATER = NOW + _dt.timedelta(hours=1)
INV_2 = INV.model_copy(update={"investigation_id": "inv-2", "created_at": LATER})
JOB_2 = JOB.model_copy(update={"learning_job_id": "lj-2", "created_at": LATER})
SUMMARY_2 = SUMMARY.model_copy(update={"alert_id": "al-2", "fired_at": LATER})
LESSON_2 = LESSON.model_copy(update={"lesson_id": "le-2"})
SETTINGS_2 = SETTINGS.model_copy(update={"system_id": "tiy"})

#: (path, port, the store's first two rows in the list's order, the position the second page
#: must start after — the first row's, as the port's order names it).
LISTS = [
    ("/alerts", "list_alerts", [SUMMARY_2, SUMMARY], (LATER, "al-2")),
    ("/investigations", "list_investigations", [INV_2, INV], (LATER, "inv-2")),
    ("/learning-jobs", "list_learning_jobs", [JOB_2, JOB], (LATER, "lj-2")),
    ("/lessons", "list_lessons", [LESSON, LESSON_2], "le-1"),
    ("/systems", "list_systems", [SETTINGS, SETTINGS_2], "tix"),
]


def _rows_after(rows: list[Any]) -> Callable[..., list[Any]]:
    """The store as a function of `after`: both rows from the start, the second after the first."""
    return lambda tenant, *, after, limit, **_filters: (rows if after is None else rows[1:])[:limit]


@pytest.mark.parametrize(("path", "port", "rows", "first_after"), LISTS, ids=[x[0] for x in LISTS])
def test_every_list_pages_by_cursor_from_the_last_row_served(
    path: str, port: str, rows: list[Any], first_after: Any,
) -> None:
    api = Api(**{port: _rows_after(rows), "has_credentials": False})
    first = api.client.get(path, headers=AUTH, params={"limit": 1}).json()
    assert len(first["items"]) == 1
    assert first["next_cursor"]
    second = api.client.get(path, headers=AUTH,
                            params={"limit": 1, "cursor": first["next_cursor"]}).json()
    assert len(second["items"]) == 1
    assert second["items"] != first["items"]
    assert second["next_cursor"] is None
    (_, first_kwargs), (_, second_kwargs) = api.ports.called(port)
    assert (first_kwargs["after"], first_kwargs["limit"]) == (None, 2)
    assert (second_kwargs["after"], second_kwargs["limit"]) == (first_after, 2)


def test_a_short_page_is_the_last_page() -> None:
    api = Api(list_investigations=[INV_2, INV])
    page = api.client.get("/investigations", headers=AUTH, params={"limit": 2}).json()
    assert (len(page["items"]), page["next_cursor"]) == (2, None)


def _cursor(api: Api, path: str, params: dict[str, str] | None = None) -> str:
    page = api.client.get(path, headers=AUTH, params={"limit": 1, **(params or {})}).json()
    cursor: str = page["next_cursor"]
    assert cursor
    return cursor


@pytest.mark.parametrize("cursor", [
    "!!not-base64!!",
    "bm90IGpzb24",                               # base64 of "not json"
    "eyJ2IjogMn0",                               # base64 of {"v": 2}
    "e30",                                       # base64 of {}
])
def test_a_cursor_this_api_did_not_issue_is_refused_before_the_store(cursor: str) -> None:
    api = Api()
    response = api.client.get("/investigations", headers=AUTH, params={"cursor": cursor})
    assert response.status_code == 422
    assert api.ports.calls == []


def test_a_cursor_is_bound_to_its_list_its_tenant_and_its_filters() -> None:
    issuer = Api(list_investigations=[INV_2, INV], list_lessons=[LESSON, LESSON_2])
    by_alert = _cursor(issuer, "/investigations", {"alert_id": "al-1"})
    lessons = _cursor(issuer, "/lessons")

    api = Api()
    refusals = [
        api.client.get("/investigations", headers=AUTH, params={"cursor": by_alert, "alert_id": "al-2"}),
        api.client.get("/investigations", headers=AUTH, params={"cursor": by_alert}),
        api.client.get("/systems", headers=AUTH, params={"cursor": lessons}),
        api.client.get("/lessons", headers=AUTH_B, params={"cursor": lessons}),
    ]
    assert [r.status_code for r in refusals] == [422, 422, 422, 422]
    assert api.ports.calls == []


def test_paging_the_demo_store_serves_every_row_once_across_tied_timestamps() -> None:
    store = InMemoryStore(lambda: NOW)
    fired = [NOW, NOW, NOW, LATER, NOW - _dt.timedelta(hours=1)]
    for n, at in enumerate(fired):
        store.add_alert(A, ALERT.model_copy(update={"alert_id": f"al-{n}", "fired_at": at}))
    client = TestClient(create_app(ApiDeps(
        authenticator=TokenAuthenticator({"tok-a": Principal(tenant_id=A, user_id=USER)}),
        alerts=store, investigations=store, learning_jobs=store, lessons=store, systems=store,
        secrets=InMemorySecrets(), checker=StubSystemChecker(), artifact_links=StubArtifactLinks(),
        audit=InMemoryAudit(), clock=lambda: NOW,
    )))
    seen: list[str] = []
    params: dict[str, Any] = {"limit": 2}
    while True:
        page = client.get("/alerts", headers=AUTH, params=params).json()
        seen += [a["alert_id"] for a in page["items"]]
        if page["next_cursor"] is None:
            break
        params = {"limit": 2, "cursor": page["next_cursor"]}
    assert seen == ["al-3", "al-2", "al-1", "al-0", "al-4"]


# --- the demo server -----------------------------------------------------------------------


def test_the_demo_seed_serves_each_named_tenant_only_its_own_records() -> None:
    tenants = ("t-one", "t-two")
    client = TestClient(create_app(demo_deps(tenants, lambda: NOW)))
    seen: dict[str, set[str]] = {}
    for token, principal in demo_tokens(tenants).items():
        auth = {"Authorization": f"Bearer {token}"}
        alerts = client.get("/alerts", headers=auth).json()["items"]
        assert alerts, token
        for alert in alerts:
            assert client.get(f"/alerts/{alert['alert_id']}", headers=auth).status_code == 200
        seen.setdefault(principal.tenant_id, set()).update(a["alert_id"] for a in alerts)
    assert set(seen) == set(tenants)
    assert not seen["t-one"] & seen["t-two"]
    systems = client.get("/systems", headers={"Authorization": "Bearer t-one-analyst"}).json()["items"]
    assert {s["system_id"]: s["has_credentials"] for s in systems} == {"siem": False, "tickets": True}


def test_the_demo_store_keys_records_by_tenant() -> None:
    store = InMemoryStore(lambda: NOW)
    store.add_alert("t-one", ALERT)
    store.add_alert("t-two", ALERT.model_copy(update={"title": "two's"}))
    one, two = store.get_alert("t-one", "al-1"), store.get_alert("t-two", "al-1")
    assert one is not None
    assert two is not None
    assert (one.title, two.title) == ("t", "two's")


@pytest.mark.parametrize(("tenants", "reason"), [
    ((), "at least one tenant"),
    (("t-one", "t-one"), "tenants repeat"),
    (("Not_A_Tenant",), "not a tenant id"),
])
def test_the_demo_seed_refuses_a_bad_tenant_list(tenants: tuple[str, ...], reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        demo_deps(tenants)
