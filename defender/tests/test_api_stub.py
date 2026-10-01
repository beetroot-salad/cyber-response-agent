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

import base64
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
    CredentialsPut,
    SystemCheck,
    SystemPut,
    SystemSettings,
)
from defender._tenant import TenantRefused  # noqa: E402
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
    (("PUT", "/systems/{system_id}"), "/systems/tix",
     {"kind": "ticketing", "display_name": "T", "enabled": True, "settings": {}},
     {"put_system": (SETTINGS, True), "has_credentials": False}),
    (("PUT", "/systems/{system_id}/credentials"), "/systems/tix/credentials",
     {"credentials": {"api_token": "x"}},
     {"get_system": SETTINGS, "has_credentials": False, "put_credentials": None}),
    (("POST", "/systems/{system_id}/check"), "/systems/tix/check", None,
     {"get_system": SETTINGS, "has_credentials": True,
      "check": SystemCheck(ok=True, detail="fine")}),
]


#: The writes a route makes through a transaction; they carry no tenant — the transaction does.
TX_WRITES = {"create_investigation", "cancel_investigation", "delete_investigation",
             "create_learning_job", "put_system"}


class Scripted:
    """Every port the routes call. `answers` maps a port method's name to what it returns, an
    exception it raises, or a function of its arguments. Each call is recorded; an unscripted
    one fails the test, so a test states exactly what the API may ask of the platform.

    `transaction` is built in: it records `(tenant, actor)` as it opens, sends writes to the
    answers like any call, and keeps the audit events written through it in `audits` only when
    its block exits normally — what a store commits. `answers["audit"]`, an exception, fails the
    audit write."""

    def __init__(self, answers: dict[str, Any]) -> None:
        self.answers = answers
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        self.transactions: list[tuple[str, str]] = []
        self.audits: list[tuple[str, str, str, str, str]] = []

    def transaction(self, tenant_id: str, actor: str) -> _ScriptedTransaction:
        return _ScriptedTransaction(self, tenant_id, actor)

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


class _ScriptedTransaction:
    def __init__(self, ports: Scripted, tenant_id: str, actor: str) -> None:
        self.ports = ports
        self.tenant_id = tenant_id
        self.actor = actor
        self.pending: list[tuple[str, str, str, str, str]] = []

    def __enter__(self) -> _ScriptedTransaction:
        self.ports.transactions.append((self.tenant_id, self.actor))
        return self

    def __exit__(self, exc_type: type[BaseException] | None, *_: object) -> None:
        if exc_type is None:
            self.ports.audits.extend(self.pending)

    def __getattr__(self, name: str) -> Callable[..., Any]:
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.ports, name)

    def audit(self, action: str, target: str, detail: str = "") -> None:
        failure = self.ports.answers.get("audit")
        if isinstance(failure, BaseException):
            raise failure
        self.pending.append((self.tenant_id, self.actor, action, target, detail))


def _deps(ports: Any, authenticator: Any = None) -> ApiDeps:
    return ApiDeps(
        authenticator=authenticator or TokenAuthenticator({
            "tok-a": Principal(tenant_id=A, user_id=USER),
            "tok-b": Principal(tenant_id="tenant-b", user_id="bob@b.example"),
        }),
        alerts=ports, investigations=ports, learning_jobs=ports, lessons=ports,
        systems=ports, writes=ports, secrets=ports, checker=ports, artifact_links=ports,
    )


class Api:
    def __init__(self, **answers: Any) -> None:
        self.ports = Scripted(answers)
        self.client = TestClient(create_app(_deps(self.ports)))

    def actions(self) -> list[str]:
        return [action for _, _, action, _, _ in self.ports.audits]

    def audited(self) -> list[tuple[str, str, str]]:
        """The committed audit events, as (action, target, detail)."""
        return [(action, target, detail) for _, _, action, target, detail in self.ports.audits]

    def lenient(self) -> TestClient:
        """A client that answers a server error as a 500 instead of raising it."""
        return TestClient(self.client.app, raise_server_exceptions=False)


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
    assert {args[0] for name, args, _ in api.ports.calls if name not in TX_WRITES} <= {A}
    assert set(api.ports.transactions) <= {(A, USER)}
    assert {(tenant, user) for tenant, user, *_ in api.ports.audits} <= {(A, USER)}
    if any(name in TX_WRITES for name, _, _ in api.ports.calls):
        assert api.ports.transactions == [(A, USER)], "a write runs in one transaction"


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
    assert api.ports.transactions == []


class _ProviderClaims:
    """A login adapter that builds its caller from the provider's claims at request time."""

    def __init__(self, tenant_claim: str) -> None:
        self.tenant_claim = tenant_claim

    def authenticate(self, bearer_token: str | None) -> Principal:
        return Principal(tenant_id=self.tenant_claim, user_id=USER)  # type: ignore[arg-type]


@pytest.mark.parametrize("claim", ["Acme_Corp", "org_2NxAbCdEf", ""])
def test_a_login_whose_tenant_fails_the_grammar_is_a_401_not_a_500(claim: str) -> None:
    ports = Scripted({})
    client = TestClient(create_app(_deps(ports, _ProviderClaims(claim))),
                        raise_server_exceptions=False)
    response = client.get("/alerts", headers=AUTH)
    assert response.status_code == 401
    assert response.headers["WWW-Authenticate"] == "Bearer"
    assert ports.calls == []


@pytest.mark.parametrize(("path", "body"), [
    ("/investigations", {"alert_id": "al-1", "client_request_id": "r", "tenant_id": A}),
    ("/learning-jobs", {"investigation_id": "inv-1", "client_request_id": "r", "tenant_id": A}),
])
def test_a_body_cannot_name_a_tenant(path: str, body: dict[str, str]) -> None:
    api = Api()
    assert api.client.post(path, headers=AUTH, json=body).status_code == 422
    assert api.ports.calls == []


# --- creates: 201 or replay ----------------------------------------------------------------


@pytest.mark.parametrize(("path", "body", "port", "record", "location", "audit"), [
    ("/investigations", {"alert_id": "al-1", "client_request_id": "r1"}, "create_investigation",
     INV, "/investigations/inv-1", ("investigation.start", "inv-1", "alert al-1")),
    ("/learning-jobs", {"investigation_id": "inv-1", "client_request_id": "r1"},
     "create_learning_job", JOB, "/learning-jobs/lj-1", ("learning_job.start", "lj-1", "investigation inv-1")),
])
def test_a_create_is_a_201_with_location_only_when_the_store_created(
    path: str, body: dict[str, str], port: str, record: Any, location: str,
    audit: tuple[str, str, str],
) -> None:
    created = Api(**{port: (record, True)})
    response = created.client.post(path, headers=AUTH, json=body)
    assert response.status_code == 201
    assert response.headers["Location"] == BASE + location
    assert response.json() == record.model_dump(mode="json")
    assert created.ports.called(port) == [((*body.values(),), {})]
    assert created.ports.transactions == [(A, USER)]
    assert created.audited() == [audit]

    replayed = Api(**{port: (record, False)})
    response = replayed.client.post(path, headers=AUTH, json=body)
    assert response.status_code == 200
    assert "Location" not in response.headers
    assert response.json() == record.model_dump(mode="json")
    assert replayed.ports.transactions == [(A, USER)]
    assert replayed.audited() == [], "a replay is not a second start"


@pytest.mark.parametrize(("path", "body", "port", "record"), [
    ("/investigations", {"alert_id": "al-OTHER", "client_request_id": "r1"}, "create_investigation", INV),
    ("/learning-jobs", {"investigation_id": "inv-OTHER", "client_request_id": "r1"},
     "create_learning_job", JOB),
])
@pytest.mark.parametrize("created", [True, False])
def test_a_create_answered_for_another_target_is_a_500_and_commits_nothing(
    path: str, body: dict[str, str], port: str, record: Any, created: bool,
) -> None:
    api = Api(**{port: (record, created)})
    response = api.lenient().post(path, headers=AUTH, json=body)
    assert response.status_code == 500
    assert "Location" not in response.headers
    assert api.audited() == []


def test_a_create_whose_audit_write_fails_commits_nothing() -> None:
    api = Api(create_investigation=(INV, True), audit=RuntimeError("audit down"))
    response = api.lenient().post("/investigations", headers=AUTH,
                                  json={"alert_id": "al-1", "client_request_id": "r1"})
    assert response.status_code == 500
    assert api.audited() == []


def test_put_system_is_a_201_at_its_own_url_when_created_and_200_when_replaced() -> None:
    body = {"kind": "ticketing", "display_name": "T", "enabled": False, "settings": {"q": "s"}}
    created = Api(put_system=(SETTINGS, True), has_credentials=False)
    response = created.client.put("/systems/tix", headers=AUTH, params={"x": "1"}, json=body)
    assert (response.status_code, response.headers["Location"]) == (201, BASE + "/systems/tix")
    ((system_id, sent), kwargs), = created.ports.called("put_system")
    assert (system_id, sent.model_dump(), kwargs) == ("tix", body, {})
    replaced = Api(put_system=(SETTINGS, False), has_credentials=False)
    response = replaced.client.put("/systems/tix", headers=AUTH, json=body)
    assert response.status_code == 200
    assert "Location" not in response.headers
    assert created.audited() == replaced.audited() == [("system.update", "tix", "")]


@pytest.mark.parametrize("model", [SystemPut, CredentialsPut])
def test_a_whole_record_put_body_has_no_defaults(model: type[Any]) -> None:
    """A PUT replaces the record, so a default would silently reset whatever a caller left out."""
    assert [name for name, field in model.model_fields.items() if not field.is_required()] == []


@pytest.mark.parametrize("missing", ["enabled", "settings"])
def test_put_system_without_a_field_is_refused(missing: str) -> None:
    api = Api()
    body = {"kind": "ticketing", "display_name": "T", "enabled": True, "settings": {}}
    del body[missing]
    assert api.client.put("/systems/tix", headers=AUTH, json=body).status_code == 422
    assert api.ports.calls == []


@pytest.mark.parametrize(("method", "path", "port", "answer", "action"), [
    ("POST", "/investigations/inv-1/cancel", "cancel_investigation", INV, "investigation.cancel"),
    ("DELETE", "/investigations/inv-1", "delete_investigation", None, "investigation.delete"),
])
def test_a_write_is_audited_in_its_own_transaction(
    method: str, path: str, port: str, answer: Any, action: str,
) -> None:
    api = Api(**{port: answer})
    assert api.client.request(method, path, headers=AUTH).status_code < 400
    assert api.ports.called(port) == [(("inv-1",), {})]
    assert api.ports.transactions == [(A, USER)]
    assert api.audited() == [(action, "inv-1", "")]


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
    assert api.ports.audits == []


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
    assert api.ports.audits == [], "the refused write's transaction committed nothing"


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
    assert api.audited() == [("artifact.read", "inv-1", key)]


def test_an_artifact_read_whose_link_fails_is_not_audited() -> None:
    api = Api(get_investigation=INV, signed_url=RuntimeError("signer down"))
    response = api.lenient().get("/investigations/inv-1/artifacts/report.md", headers=AUTH,
                                 follow_redirects=False)
    assert response.status_code == 500
    assert api.ports.transactions == []
    assert api.ports.audits == []


def test_an_artifact_link_is_not_handed_out_unless_its_read_is_audited() -> None:
    api = Api(get_investigation=INV, signed_url=SIGNED, audit=RuntimeError("audit down"))
    response = api.lenient().get("/investigations/inv-1/artifacts/report.md", headers=AUTH,
                                 follow_redirects=False)
    assert response.status_code == 500
    assert SIGNED not in response.text
    assert "Location" not in response.headers


@pytest.mark.parametrize("key", ["runtime.html", "%2E%2E/other/report.md", "report.md/x",
                                 "other/report.md"])
def test_only_keys_the_investigation_lists_are_answered(key: str) -> None:
    api = Api(get_investigation=INV)
    response = api.client.get(f"/investigations/inv-1/artifacts/{key}", headers=AUTH,
                              follow_redirects=False)
    assert response.status_code == 404
    assert response.json()["detail"].startswith("no artifact"), "refused by the route's own list"
    assert api.ports.called("signed_url") == []
    assert api.ports.audits == []


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
    assert api.ports.called("has_credentials") == [], "an existence check, not a read"
    assert api.audited() == [("system.credentials", "tix", "fields: api_token")]
    assert secret not in repr(api.ports.audits)


def test_credentials_are_not_written_when_their_audit_write_fails() -> None:
    api = Api(get_system=SETTINGS, put_credentials=None, audit=RuntimeError("audit down"))
    response = api.lenient().put("/systems/tix/credentials", headers=AUTH,
                                 json={"credentials": {"api_token": "x"}})
    assert response.status_code == 500
    assert api.ports.called("put_credentials") == []


def test_a_failed_credentials_write_commits_no_audit() -> None:
    api = Api(get_system=SETTINGS, put_credentials=RuntimeError("vault down"))
    response = api.lenient().put("/systems/tix/credentials", headers=AUTH,
                                 json={"credentials": {"api_token": "x"}})
    assert response.status_code == 500
    assert api.ports.audits == []


#: Each as it is spelled inside a JSON string, so the body is valid JSON that decodes to it.
@pytest.mark.parametrize("key", [r"a\u0000b", r"\ud800", "", "has space", "x" * 65, "9lead"])
def test_a_credential_field_name_outside_the_grammar_is_refused(key: str) -> None:
    """A field name reaches the audit detail, so one the audit store would refuse never gets in."""
    api = Api()
    response = api.client.put("/systems/tix/credentials", headers={**AUTH, "Content-Type": "application/json"},
                              content=('{"credentials": {"' + key + '": "v"}}').encode())
    assert response.status_code == 422
    assert api.ports.calls == []


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


@pytest.mark.parametrize("value", ["20260928", "2026", "1727500000.5", "-1"])
@pytest.mark.parametrize("param", ["fired_after", "fired_before"])
def test_a_bare_number_is_not_read_as_a_time(param: str, value: str) -> None:
    api = Api()
    response = api.client.get("/alerts", headers=AUTH, params={param: value})
    assert response.status_code == 422
    assert api.ports.calls == []


def test_an_aware_time_reaches_the_store_as_the_same_instant_in_utc() -> None:
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
    assert kwargs["fired_after"].utcoffset() == _dt.timedelta(0)


def test_a_record_time_is_served_in_utc() -> None:
    odd = _dt.timezone(_dt.timedelta(minutes=19, seconds=32))
    inv = INV.model_validate({**INV.model_dump(), "created_at": NOW.astimezone(odd)})
    assert inv.created_at == NOW
    assert inv.created_at.utcoffset() == _dt.timedelta(0)
    assert inv.model_dump(mode="json")["created_at"] == "2026-09-28T12:00:00Z"


@pytest.mark.parametrize(("method", "path", "body"), [
    ("GET", "/alerts/%E2%9C%93", None),
    ("GET", "/investigations/a%20b", None),
    ("GET", "/learning-jobs/-leading-dash", None),
    ("PUT", "/systems/%E2%9C%93", {"kind": "k", "display_name": "d", "enabled": True, "settings": {}}),
    ("PUT", "/systems/a%20b/credentials", {"credentials": {"k": "v"}}),
    ("POST", "/systems/a%20b/check", None),
    ("POST", "/investigations/a%20b/cancel", None),
    ("DELETE", "/investigations/a%20b", None),
    ("GET", "/investigations/a%20b/artifacts/report.md", None),
    ("GET", "/learning-jobs?investigation_id=a%20b", None),
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
    assert api.ports.transactions == []


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


@pytest.mark.parametrize("bad", ["a/b", "a b", "a?b#c", "é", ""])
def test_an_id_outside_the_grammar_cannot_be_served(bad: str) -> None:
    with pytest.raises(ValueError, match="pattern"):
        INV.model_validate({**INV.model_dump(), "investigation_id": bad})
    with pytest.raises(ValueError, match="pattern"):
        SETTINGS.model_validate({**SETTINGS.model_dump(), "system_id": bad})


def test_a_caller_from_the_login_provider_carries_a_checked_tenant() -> None:
    with pytest.raises(TenantRefused):
        Principal(tenant_id="Not_A_Tenant", user_id=USER)


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


def test_a_cursor_stays_short_whatever_the_filters_and_is_accepted_back() -> None:
    severity = "x" * 1600
    api = Api(list_alerts=_rows_after([SUMMARY_2, SUMMARY]))
    cursor = _cursor(api, "/alerts", {"severity": severity})
    assert len(cursor) < 400
    page = api.client.get("/alerts", headers=AUTH,
                          params={"limit": 1, "severity": severity, "cursor": cursor})
    assert page.status_code == 200, page.text
    assert [a["alert_id"] for a in page.json()["items"]] == ["al-1"]


def _edited(cursor: str, **changes: Any) -> str:
    """`cursor` with fields of its JSON changed, re-encoded as the API encodes one."""
    body = json.loads(base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)))
    return base64.urlsafe_b64encode(json.dumps({**body, **changes}).encode()).decode().rstrip("=")


@pytest.mark.parametrize("bad_id", ["a b/é", "' OR 1=1 --", "", "\u0000", "x" * 1363])
@pytest.mark.parametrize(("path", "port", "rows"), [x[:3] for x in LISTS], ids=[x[0] for x in LISTS])
def test_an_edited_cursor_cannot_hand_a_port_an_id_outside_the_grammar(
    path: str, port: str, rows: list[Any], bad_id: str,
) -> None:
    api = Api(**{port: _rows_after(rows), "has_credentials": False})
    cursor = _edited(_cursor(api, path), id=bad_id)
    calls = len(api.ports.calls)
    response = api.client.get(path, headers=AUTH, params={"limit": 1, "cursor": cursor})
    assert response.status_code == 422
    assert len(api.ports.calls) == calls, "the edited cursor reached a port"


@pytest.mark.parametrize(("path", "port", "rows", "at"), [
    ("/investigations", "list_investigations", [INV_2, INV], None),
    ("/lessons", "list_lessons", [LESSON, LESSON_2], NOW.isoformat()),
])
def test_a_cursor_of_the_wrong_shape_for_its_list_is_refused(
    path: str, port: str, rows: list[Any], at: str | None,
) -> None:
    api = Api(**{port: _rows_after(rows)})
    cursor = _edited(_cursor(api, path), at=at)
    calls = len(api.ports.calls)
    response = api.client.get(path, headers=AUTH, params={"limit": 1, "cursor": cursor})
    assert response.status_code == 422
    assert "not a position in this list" in response.text
    assert len(api.ports.calls) == calls


@pytest.mark.parametrize("answer", [
    lambda tenant, *, after, limit, **_: [INV_2, INV][:limit],      # ignores `after`
    lambda tenant, *, after, limit, **_: [INV, INV_2][:limit],      # out of order
    lambda tenant, *, after, limit, **_: [INV_2, INV, INV, INV],    # more than asked
], ids=["repeats", "unordered", "oversized"])
def test_a_page_that_does_not_advance_is_a_500_not_an_endless_walk(answer: Any) -> None:
    client = Api(list_investigations=answer).lenient()
    params: dict[str, Any] = {"limit": 1}
    statuses = []
    for _ in range(3):
        response = client.get("/investigations", headers=AUTH, params=params)
        statuses.append(response.status_code)
        if response.status_code != 200:
            break
        params = {"limit": 1, "cursor": response.json()["next_cursor"]}
    assert statuses[-1] == 500, statuses


def test_one_filter_instant_written_with_another_offset_keeps_its_cursor() -> None:
    api = Api(list_alerts=_rows_after([SUMMARY_2, SUMMARY]))
    cursor = _cursor(api, "/alerts", {"fired_after": "2026-09-20T08:00:00+02:00"})
    page = api.client.get("/alerts", headers=AUTH, params={
        "limit": 1, "fired_after": "2026-09-20T06:00:00Z", "cursor": cursor})
    assert page.status_code == 200, page.text


def test_a_store_answering_full_system_records_is_still_served_from_its_settings() -> None:
    stored = System(**SETTINGS.model_dump(), has_credentials=False)
    api = Api(list_systems=[stored], get_system=stored, has_credentials=True,
              check=lambda tenant, system: SystemCheck(ok=True, detail=str(system.has_credentials)))
    assert api.client.get("/systems", headers=AUTH).json()["items"][0]["has_credentials"] is True
    assert api.client.post("/systems/tix/check", headers=AUTH).json()["detail"] == "True"


def test_systems_are_served_only_for_the_rows_on_the_page() -> None:
    api = Api(list_systems=[SETTINGS, SETTINGS_2], has_credentials=False)
    page = api.client.get("/systems", headers=AUTH, params={"limit": 1}).json()
    assert [s["system_id"] for s in page["items"]] == ["tix"]
    assert api.ports.called("has_credentials") == [((A, "tix"), {})]


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
        writes=store, secrets=InMemorySecrets(), checker=StubSystemChecker(),
        artifact_links=StubArtifactLinks(),
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


def test_the_demo_store_keeps_the_audit_events_a_transaction_commits() -> None:
    deps = demo_deps(("t-one",), lambda: NOW)
    client = TestClient(create_app(deps))
    auth = {"Authorization": "Bearer t-one-analyst"}
    created = client.post("/investigations", headers=auth,
                          json={"alert_id": "t-one-alert-0003", "client_request_id": "r1"})
    assert created.status_code == 201, created.text
    events = deps.writes.audit_events  # type: ignore[attr-defined]
    assert [(e.tenant_id, e.user_id, e.action, e.target) for e in events] == [
        ("t-one", "analyst@t-one.example", "investigation.start", created.json()["investigation_id"])]


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
