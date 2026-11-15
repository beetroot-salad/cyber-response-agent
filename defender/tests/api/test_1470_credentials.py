"""#1470: a tenant admin sets a system's credentials through the API, and every stored write is announced (O7, O9).

Real server over a migrated database; the secret store is the real `OpenBaoSecrets` over `ScriptedOpenBao` (faults a real
server cannot be made to give, the post-write race) and, in the `real` runs of `configured`, a real OpenBao holding the
writer policy. Postgres-gated; the `openbao`-marked tests need the test OpenBao."""
from __future__ import annotations

import logging
from typing import Any

import anyio
import httpx
import pytest
from defender.tests.support.api._config1470 import (
    remove_tenant,
    BASE_MOVED,
    BODY,
    ELASTIC,
    ELASTIC_ACCESS,
    ELASTIC_SETTINGS,
    PASSWORD,
    TICKET,
    TICKET_ACCESS,
    TICKET_SETTINGS,
    TOKEN,
    Configured,
    audit_events,
    holds_no_value,
    problem_text,
    told,
)
from defender.tests.support.api._openbao1470 import (
    KV_MOUNT,
    WRITER_TOKEN,
    ScriptedOpenBao,
)
from defender.tests.support.api._server1083 import ANN, A
from defender.tests.support.tenancy._mapping1345 import FIXTURE_ALERT_MAPPING

ELASTIC_SET = {"username": "defender-reader", "password": PASSWORD}
MARKER_UNUSED = "stored for an unused generation"
MARKER_POSSIBLY = "possibly stored"

postgres = pytest.mark.postgres
anyio_mark = pytest.mark.anyio


async def _ticket(configured: Configured, *, with_set: bool = False) -> None:
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    if with_set:
        assert (await configured.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 204


def _faults(response: httpx.Response) -> list[str]:
    body = response.json()
    assert response.status_code == 422, response.text
    assert "errors" not in body, body
    assert body["faults"]
    assert all(isinstance(f, str) for f in body["faults"]), body
    return body["faults"]


# --- O7 / P3: the generation, not the version ------------------------------------------------------------------------

@anyio_mark
@postgres
async def test_o7_p3_credentials_follow_the_generation_not_the_version(configured):
    """Set for v1 → 204 at g1; v2 changes a setting (same generation): for v1 still 204; v3 moves the base: for v2 is
    409 naming 3 and `has_credentials` is false until a set for v3 (at g2). (O7, P3, D-D)"""
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    first = await configured.put_credentials(TICKET, 1, {"api_key": TOKEN})
    assert first.status_code == 204, first.text
    assert (first.status_code, first.content) == (204, b"")  # nothing echoed
    assert configured.stored_set(TICKET, 1) == {"kind": "static", "fields": {"api_key": TOKEN}}

    timeout = TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"}
    assert (await configured.put_system(TICKET, 1, settings=timeout)).status_code == 200
    assert (await configured.put_credentials(TICKET, 1, {"api_key": TOKEN + "-2"})).status_code == 204
    assert configured.stored_set(TICKET, 1)["fields"] == {"api_key": TOKEN + "-2"}  # a set is replaced whole

    moved = TICKET_ACCESS.replace(*BASE_MOVED)
    assert moved != TICKET_ACCESS, "premise: the base is in the fixture's access text"
    assert (await configured.put_system(TICKET, 2, settings=timeout, access=moved)).status_code == 200
    refused = await configured.put_credentials(TICKET, 2, {"api_key": TOKEN})
    assert refused.status_code == 409, refused.text
    assert refused.json()["current_version"] == 3
    assert "faults" not in refused.json()
    assert configured.stored_generations(TICKET) == [1]
    assert (await configured.put_credentials(TICKET, 3, {"api_key": TOKEN})).status_code == 204
    assert configured.stored_generations(TICKET) == [1, 2]
    assert (await configured.get_system(TICKET)).json()["has_credentials"] is True


@anyio_mark
@postgres
async def test_o7_a_disabled_current_version_counts_and_an_unknown_or_future_version_is_409(configured):
    """v2 disables the system (same generation): for v1 and for v2 are 204; for 0, 3, 99: 409 naming 2. (O7, P3)"""
    await _ticket(configured)
    assert (await configured.put_system(TICKET, 1, enabled=False)).status_code == 200
    assert (await configured.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 204
    assert (await configured.put_credentials(TICKET, 2, {"api_key": TOKEN})).status_code == 204
    for for_version in (0, 3, 99):
        refused = await configured.put_credentials(TICKET, for_version, {"api_key": TOKEN + "-x"})
        assert refused.status_code == 409
        assert refused.json()["current_version"] == 2, (for_version, refused.text)
    assert configured.stored_set(TICKET, 1)["fields"] == {"api_key": TOKEN}


@anyio_mark
@postgres
async def test_o7_a_deleted_system_has_no_current_record_and_its_version_is_not_a_generation_to_write_to(configured):
    """No record (never written, or deleted): 404 for any set, however wrong, and nothing stored. (O7)"""
    bad = {"nonsense": "x"}
    assert (await configured.put_credentials(TICKET, 1, bad)).status_code == 404
    await _ticket(configured)
    assert (await configured.delete_system(TICKET, 1)).status_code == 204
    assert (await configured.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 404
    assert (await configured.put_credentials(TICKET, 7, bad)).status_code == 404
    assert configured.stored_generations(TICKET) == []


@anyio_mark
@postgres
async def test_o7_the_version_check_comes_before_the_schema_check(configured):
    """A stale `for_version` with an invalid set is 409 (not 422), and nothing is stored. (O7)"""
    await _ticket(configured)
    stale = await configured.put_credentials(TICKET, 5, {"nonsense": "x"})
    assert stale.status_code == 409
    assert stale.json()["current_version"] == 1, stale.text
    assert configured.stored_generations(TICKET) == []


# --- O7: the credential schema ---------------------------------------------------------------------------------------

#: Values one character short of the minimum that are told apart from any word an answer could hold (N1: the refusal must
#: not print a value, and a value like "short" would be in a sentence by chance).
SHORT_KEY = "shrt-key-1470-x"
SHORT_PASS = "shrt-pass-1470x"
assert len(SHORT_KEY) == len(SHORT_PASS) == 15  # noqa: PLR2004 — one below the minimum

_BAD_SETS = [
    (TICKET, "a missing field", {}, ("api_key",)),
    (TICKET, "a field the scheme does not have", {"api_key": TOKEN, "password": TOKEN}, ("password",)),
    (TICKET, "the wrong field", {"api_token": TOKEN}, ("api_key", "api_token")),
    (TICKET, "a secret shorter than the minimum", {"api_key": SHORT_KEY}, ("api_key",)),
    (TICKET, "an empty value", {"api_key": ""}, ("api_key",)),
    (TICKET, "a non-ASCII character in a bearer token", {"api_key": "tøken-of-sixteen-or-more"}, ("api_key",)),
    (TICKET, "a line break in a token", {"api_key": TOKEN + "\nX-Evil: 1"}, ("api_key",)),
    (ELASTIC, "a username holding a colon", {**ELASTIC_SET, "username": "defender:reader"}, ("username",)),
    (ELASTIC, "a short password", {**ELASTIC_SET, "password": SHORT_PASS}, ("password",)),
    (ELASTIC, "a missing username", {"password": PASSWORD}, ("username",)),
    (ELASTIC, "an empty username", {**ELASTIC_SET, "username": ""}, ("username",)),
]


@anyio_mark
@postgres
@pytest.mark.parametrize(("system", "label", "bad", "names"), _BAD_SETS, ids=[f"{s}-{label}" for s, label, _, _ in _BAD_SETS])
async def test_o7_a_set_that_breaks_the_schemes_credential_schema_is_422_naming_the_fields(configured, system, label, bad, names):
    """A set not exactly the scheme's fields, or with a value the proxy would refuse at use: 422 `faults` naming the
    field, at the write; a good set on the same system is taken (control) and the bad one never replaces it. (O7)"""
    if system == TICKET:
        await _ticket(configured)
        good = {"api_key": TOKEN}
    else:
        assert (await configured.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)).status_code == 201
        good = ELASTIC_SET
    assert (await configured.put_credentials(system, 1, good)).status_code == 204
    refused = await configured.put_credentials(system, 1, bad)
    faults = _faults(refused)
    for name in names:
        assert any(name in f for f in faults), (name, faults)
    assert holds_no_value(refused, bad), (label, "a credential value was printed", refused.text)  # N1; "" is the defect
    assert configured.stored_set(system, 1) == {"kind": "static", "fields": good}


@anyio_mark
@postgres
async def test_o7_every_fault_of_one_set_is_listed_in_one_answer(configured):
    """A basic set with a colon username and a short password: both named in one 422. (O7)"""
    assert (await configured.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)).status_code == 201
    sent = {"username": "svc:1470-n1", "password": SHORT_PASS}
    refused = await configured.put_credentials(ELASTIC, 1, sent)
    faults = _faults(refused)
    assert any("username" in f for f in faults)
    assert any("password" in f for f in faults), faults
    assert holds_no_value(refused, sent), ("a credential value was printed", refused.text)  # N1
    assert configured.stored_generations(ELASTIC) == []


@anyio_mark
@postgres
async def test_o7_a_stored_access_that_no_longer_parses_is_422_naming_its_fault_and_stores_nothing(scripted):
    """A current record whose access an earlier release stored and today's parser refuses: 422, nothing stored. (O7)"""
    scripted.plant_version(TICKET, 1, access="base: [unclosed")
    refused = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})
    faults = _faults(refused)
    assert faults
    assert holds_no_value(refused, {"api_key": TOKEN}), ("a credential value was printed", refused.text)  # N1
    assert scripted.stored_generations(TICKET) == []
    assert scripted.scripted.calls == []


#: (body, the credential values it sends that no answer may print). A number is not a credential value; `for_version` is not.
_MALFORMED_BODIES = [
    ({"credentials": {"api_key": TOKEN}}, {"api_key": TOKEN}),
    ({"for_version": 1}, {}),
    ({"for_version": 1, "credentials": {"api_key": 12345678901234567890}}, {}),
    ({"for_version": 1, "credentials": {"api_key": TOKEN}, "kind": "static"}, {"api_key": TOKEN}),
    ({"for_version": 1, "credentials": {"api_key": TOKEN}, "kind": ""}, {"api_key": TOKEN}),
    ({"for_version": 1, "credentials": {"api_key": TOKEN}, "kind": "oauth"}, {"api_key": TOKEN}),
    ({"for_version": 1, "credentials": {"api_key": TOKEN}, "kind": "other"}, {"api_key": TOKEN}),
    ({"for_version": "one", "credentials": {"api_key": TOKEN}}, {"api_key": TOKEN}),
]


@anyio_mark
@postgres
@pytest.mark.parametrize(("body", "sent"), _MALFORMED_BODIES, ids=[
    "no for_version", "no credentials", "a number for a value", "a kind (P4)", "a kind of ''", "a kind of 'oauth'",
    "a kind of 'other'", "version not a number"])
async def test_o7_a_malformed_credential_body_is_a_validation_422_with_errors(configured, body, sent):
    """Wire shape: `for_version` and `credentials` (field → text), nothing else; a body that carries a `kind` of any value
    is refused (the kind is the scheme's, never a write field). No credential value it carries is printed back. (O7, P4, N1)"""
    await _ticket(configured)
    refused = await configured.put_raw(f"/tenants/{A}/systems/{TICKET}/credentials", body)
    assert refused.status_code == 422, refused.text
    assert refused.json()["errors"]
    assert "faults" not in refused.json()
    assert holds_no_value(refused, sent), ("a credential value was printed", refused.text)
    assert configured.stored_generations(TICKET) == []


#: Each as it is spelled inside a JSON string, so the body is valid JSON that decodes to it (base: a name the audit store
#: would refuse never gets in, and the route must answer 422, not fail serialising it).
_NAMES_OUTSIDE_THE_GRAMMAR = [r"a\u0000b", r"\ud800", "", "has space", "x" * 65, "9lead"]


@anyio_mark
@postgres
@pytest.mark.parametrize("key", _NAMES_OUTSIDE_THE_GRAMMAR, ids=["nul", "lone-surrogate", "empty", "space", "65-chars", "digit-first"])
async def test_a_credential_field_name_outside_the_grammar_is_refused_and_nothing_is_stored(configured, key):
    """A field name no scheme has, however unprintable, is a 422 (never a 500) at the write and nothing is stored; the
    value it carries is not printed back. (F5, G2; base `test_a_credential_field_name_outside_the_grammar_is_refused`)"""
    await _ticket(configured)
    refused = await configured.client.put(
        f"/tenants/{A}/systems/{TICKET}/credentials", headers={**configured.ann(), "Content-Type": "application/json"},
        content=('{"for_version": 1, "credentials": {"' + key + '": "' + TOKEN + '"}}').encode())
    assert refused.status_code == 422, refused.text
    assert holds_no_value(refused, {"v": TOKEN}), ("a credential value was printed", refused.text)
    assert configured.stored_generations(TICKET) == []


@anyio_mark
@postgres
async def test_o7_no_route_returns_a_value_and_no_answer_or_log_line_holds_one(configured, caplog):
    """After setting credentials and reading everything back: no answer or log line holds the token or password, the
    credentials path answers only the write, and the writer never read a value. (O7, C10)"""
    caplog.set_level(logging.DEBUG)
    await _ticket(configured, with_set=True)
    assert (await configured.put_system(ELASTIC, 0, settings=ELASTIC_SETTINGS, access=ELASTIC_ACCESS)).status_code == 201
    seen = [await configured.put_credentials(ELASTIC, 1, ELASTIC_SET), await configured.get_system(TICKET),
            await configured.list_systems(), await configured.put_credentials(TICKET, 1, {"api_key": TOKEN + "!"}),
            await configured.put_credentials(TICKET, 1, {"api_key": "short"}),
            await configured.put_credentials(TICKET, 9, {"api_key": TOKEN})]
    for method in ("get", "post", "delete", "patch"):
        seen.append(await configured.client.request(method.upper(), f"/tenants/{A}/systems/{TICKET}/credentials",
                                                    headers=configured.ann()))
    assert [r.status_code for r in seen[-4:]] == [405] * 4
    everything = " ".join([r.text for r in seen] + [r.getMessage() + str(getattr(r, "detail", "")) for r in caplog.records])
    assert TOKEN not in everything
    assert PASSWORD not in everything
    if configured.scripted is not None:
        assert configured.scripted.value_reads == []


# --- O7: the secret store failing ------------------------------------------------------------------------------------

_FAILS = [
    ("sealed", None, 503, "not stored", False),
    ("a refused connection", httpx.ConnectError("refused"), 503, "not stored", False),
    ("a timeout", httpx.ReadTimeout("slow"), 503, MARKER_POSSIBLY, True),
    ("a 500", httpx.Response(500, json={"errors": ["internal error"]}), 503, MARKER_POSSIBLY, True),
    ("a refused login", httpx.Response(403, json={"errors": ["permission denied"]}), 500, "refus", False),
    ("a refused request", httpx.Response(400, json={"errors": ["check-and-set parameter required"]}), 500, "not stored",
     False),
    ("a rate limit", httpx.Response(429, json={"errors": ["request path kv/data: rate limit quota exceeded"]}), 500,
     "not stored", False),
]


@anyio_mark
@postgres
@pytest.mark.parametrize(("label", "fault", "status", "says", "announced"), _FAILS, ids=[f[0] for f in _FAILS])
async def test_o7_o9_a_secret_store_fault_on_the_write_is_503_not_stored_or_possibly_stored_or_500_for_a_refused_login(
        scripted, caplog, label, fault, status, says, announced):
    """Sealed or a refused connection: 503 'not stored', nothing announced. A timeout or a 5xx: 503 'possibly stored',
    announced with that marker. A login refused after start: 500 naming the refusal, nothing announced. Any other
    refusal (a 4xx: OpenBao refuses before it writes): 500 'not stored', nothing announced. (O7, O9; r8 Am-1)"""
    caplog.set_level(logging.DEBUG)
    await _ticket(scripted)
    caplog.clear()
    bao = scripted.scripted
    if fault is None:
        bao.sealed = True
    else:
        bao.answer("POST", "/data/", fault, times=1)
    refused = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})
    assert refused.status_code == status, refused.text
    said = problem_text(refused).lower()
    assert says in said, said
    if says == "not stored":
        assert "possibly" not in said, said
    events = audit_events(caplog, "system.credentials")
    if announced:
        [event] = events
        assert MARKER_POSSIBLY in told(event)
        assert event.target == TICKET
        assert TOKEN not in told(event)
    else:
        assert events == []
    bao.sealed = False
    control = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})
    assert control.status_code == 204, control.text  # the same request succeeds once the fault is gone


# --- O7 / O9: the whole outcome table of a credential write ---------------------------------------------------------

def _scheme_systems() -> dict[str, tuple[str, dict[str, str], str, tuple[str, ...]]]:
    """scheme -> (a catalog system that declares it, its settings, its access, its set's fields): every scheme the
    credential schema knows, each on a system of its own."""
    from defender.kit.access import SCHEMES as DECLARED
    from defender.tests.support.tenancy import _systems1366 as R

    table = {
        "bearer": ("ticket", ("api_key",), {}),
        "header": ("identity", ("api_key",), {}),
        "basic": ("elastic", ("username", "password"), {}),
        R.OAUTH: ("cmdb", ("client_id", "client_secret"), {"token_url": "https://cmdb.test/token"}),
    }
    assert set(table) == set(DECLARED), "premise: every scheme the kit declares"
    return {scheme: (system, dict(R.FIXTURE_FOLDERS[system][0]),
                     R.declaration(f"http://{system}.test", scheme=scheme, **extra), fields)
            for scheme, (system, fields, extra) in table.items()}


def _a_set(fields: tuple[str, ...], n: int) -> dict[str, str]:
    """A set of `fields` with values found nowhere else (each long enough to be a secret, none holding `:`)."""
    return {field: f"value-1470-{n:05d}-{field}" for field in fields}


def _http_error_classes() -> list[type[Exception]]:
    """Every concrete `httpx.HTTPError` class (the leaves of its subclass tree)."""
    def leaves(cls: type[Exception]) -> list[type[Exception]]:
        subs = cls.__subclasses__()
        return [cls] if not subs else [leaf for sub in subs for leaf in leaves(sub)]

    found = leaves(httpx.HTTPError)
    assert httpx.ConnectError in found, "premise: the tree is walked"
    assert httpx.HTTPStatusError in found, "premise: the tree is walked"
    return found


def _raised(cls: type[Exception]) -> Exception:
    request = httpx.Request("POST", "http://openbao.test/v1/secret/data/x")
    if cls is httpx.HTTPStatusError:
        return cls("status", request=request, response=httpx.Response(500, request=request))
    try:
        return cls("the transport failed", request=request)
    except TypeError:
        return cls("the transport failed")


#: Faults that come before the request is sent: the connection was never made (design: "a connection error").
_NEVER_SENT = (httpx.ConnectError, httpx.ConnectTimeout)


def _write_outcomes() -> list[tuple[str, object, str]]:
    """(label, the secret store's answer to the write or None for success, the expected outcome): success; every concrete
    `httpx.HTTPError`; every 4xx and 5xx status, with a sealed and with another body. The outcome is `stored`, `not
    stored` (sealed: the observed 503 sealed answer, C20; or never sent), `refused login` (403), `refused` (any other
    4xx: OpenBao refuses before it writes, r8 Am-1) or `possibly stored` (a 5xx not sealed, or a fault once sent)."""
    sealed = {"errors": ["Vault is sealed"]}
    rows: list[tuple[str, object, str]] = [("success", None, "stored")]
    for cls in _http_error_classes():
        rows.append((cls.__name__, cls, "not stored" if issubclass(cls, _NEVER_SENT) else "possibly stored"))
    for status in range(400, 600):
        for label, body in (("sealed", sealed), ("other", {"errors": ["internal error"]})):
            outcome = ("refused login" if status == 403 else  # noqa: PLR2004
                       "refused" if status < 500 else  # noqa: PLR2004
                       "not stored" if status == 503 and body is sealed else "possibly stored")  # noqa: PLR2004
            rows.append((f"{status}-{label}", (status, body), outcome))
    return rows


def _kind(scheme: str) -> str:
    return "oauth-client-credentials" if scheme == "oauth-client-credentials" else "static"


async def _write_answered(client: httpx.AsyncClient, served: Configured, system: str, sent: dict[str, str],
                          answer: object, failing: logging.Handler | None) -> httpx.Response:
    """The credential write of `sent`, the secret store answering its write with `answer` (None: as it would)."""
    bao = served.scripted
    assert bao is not None
    bao._rules.clear()
    if isinstance(answer, type):
        bao.answer("POST", "/data/", _raised(answer), times=1)
    elif isinstance(answer, tuple):
        bao.answer("POST", "/data/", httpx.Response(answer[0], json=answer[1]), times=1)
    if failing is not None:
        logging.getLogger().addHandler(failing)
    try:
        return await client.put(f"/tenants/{A}/systems/{system}/credentials", headers=served.ann(),
                                json={"for_version": 1, "credentials": sent})
    finally:
        if failing is not None:
            logging.getLogger().removeHandler(failing)


def _event_faults(events: list[Any], *, system: str, marker: str | None, fields: tuple[str, ...],
                  sent: dict[str, str]) -> list[str]:
    """What is wrong with one announced write's events: not exactly one, another target or marker, a field name left
    out, or any value of the set (public or secret) named."""
    if len(events) != 1:
        return [f"{len(events)} events"]
    words = told(events[0])
    wrong = [] if events[0].target == system else [f"target {events[0].target}"]
    for other in (MARKER_POSSIBLY, MARKER_UNUSED):
        if (other in words) != (other == marker):
            wrong.append(f"marker {other!r}: {words}")
    wrong += [f"field {f} not named" for f in fields if f not in words]
    wrong += [f"value of {f} named" for f, v in sent.items() if v in words]
    return wrong


@anyio_mark
@postgres
async def test_o7_o9_every_outcome_of_the_secret_stores_write_is_answered_and_announced_as_the_design_says(scripted, caplog):
    """Over every write outcome (success; every concrete httpx error; every 4xx/5xx with a sealed or another body), each
    with the announcement working and failing, on every scheme: not stored and nothing announced exactly when OpenBao
    answered sealed or the request was never sent; a refused login or any other 4xx is 500 'not stored' with nothing
    announced; a 5xx not sealed, or a fault once sent, is 503 possibly stored with one event so marked; success 204 with one plain event. Every event names the set's field names
    and no value, public or secret; a failed announcement is 500 and the write stands. (O7, O9)"""
    caplog.set_level(logging.DEBUG)
    systems = _scheme_systems()
    for system, settings, access, _ in systems.values():
        assert (await scripted.put_system(system, 0, settings=settings, access=access)).status_code == 201
    import random

    statuses = {"stored": 204, "not stored": 503, "possibly stored": 503, "refused login": 500, "refused": 500}
    wrong: list[tuple[object, ...]] = []
    rng = random.Random(1470)
    # Success and each httpx class meet every scheme; each status row meets a scheme drawn at random (seeded).
    cases = [(row, announcing, scheme) for row in _write_outcomes() for announcing in ("works", "fails")
             for scheme in (sorted(systems) if not isinstance(row[1], tuple) else [rng.choice(sorted(systems))])]
    assert len(cases) > 800, "premise: the table is walked"  # noqa: PLR2004
    inspected: set[tuple[str, str, str]] = set()
    async with scripted.lenient() as client:
        for n, ((label, answer, outcome), announcing, scheme) in enumerate(cases):
            system, _, _, fields = systems[scheme]
            sent, kept, case = _a_set(fields, n), scripted.stored_set(system, 1), (label, announcing, scheme)
            failing = _AnnouncementFails("system.credentials") if announcing == "fails" else None
            caplog.clear()
            got = await _write_answered(client, scripted, system, sent, answer, failing)
            assert answer is None or [r.fired for r in scripted.scripted._rules] == [1], ("premise: answered", case)
            announced = outcome in ("stored", "possibly stored")
            status = 500 if announced and failing else statuses[outcome]
            said = problem_text(got).lower() if got.status_code in (500, 503) else ""  # noqa: PLR2004
            found = [] if got.status_code == status else [f"status {got.status_code}: {got.text[:160]}"]
            if outcome in ("refused login", "refused") and ("not stored" not in said or "possibly" in said):
                found.append(f"said {said[:160]}")
            if status == 503 and (outcome == "possibly stored") != (MARKER_POSSIBLY in said):  # noqa: PLR2004
                found.append(f"said {said[:160]}")
            if status == 503 and (outcome == "not stored") != ("not stored" in said):  # noqa: PLR2004
                found.append(f"said {said[:160]}")
            if announced:
                inspected.add((scheme, outcome, announcing))
            if failing is not None:
                found += [] if failing.refused == int(announced) else [f"{failing.refused} announcements"]
            elif announced:
                found += _event_faults(audit_events(caplog, "system.credentials"), system=system, fields=fields,
                                       sent=sent, marker=MARKER_POSSIBLY if outcome == "possibly stored" else None)
            else:
                found += [f"announced: {told(e)}" for e in audit_events(caplog, "system.credentials")]
            if scripted.stored_set(system, 1) != ({"kind": _kind(scheme), "fields": sent} if outcome == "stored" else kept):
                found.append("stored set")
            wrong += [(case, f) for f in found]
    assert {(s, o, a) for s in systems for o in ("stored", "possibly stored") for a in ("works", "fails")} <= inspected, \
        "premise: every scheme's stored and possibly-stored events were inspected and failed to be announced"
    assert wrong == [], wrong[:8]


def _slot_refusals() -> set[str]:
    """Every concrete `RecordRefused` type: what the slot can raise."""
    from defender.system_records import RecordRefused

    def leaves(cls: type) -> set[type]:
        subs = cls.__subclasses__()
        return {cls} if not subs else {leaf for sub in subs for leaf in leaves(sub)}

    return {cls.__name__ for cls in leaves(RecordRefused)}


#: The record changed while the set is written (re-read): its refusal type, or None (unchanged) or "exception".
#: Only `Stale` (the generation moved) and `NoCurrentRecord` (deleted) show the set at a generation no current version
#: uses (r8 Am-3); any other refusal is answered as itself, the set announced as stored.
_UNUSED = {"Stale", "NoCurrentRecord"}
#: Each other refusal's own status, as the first call's would be.
_OWN_STATUS = {"TenantNotActive": 409, "NoSuchTenant": 404, "Judged": 422}
_REREADS = {"unchanged": None, "generation raised": "Stale", "deleted": "NoCurrentRecord",
            "tenant not active": "TenantNotActive", "tenant row gone": "NoSuchTenant", "access unparseable": "Judged",
            "the re-read fails": "exception"}


def test_o7_the_re_read_table_covers_every_refusal_the_slot_can_raise():
    """The re-read rows below hold one state change per type the slot can refuse with: none is left out. (O7)"""
    assert {kind for kind in _REREADS.values() if kind not in (None, "exception")} == _slot_refusals()


async def _change(served: Configured, change: str, system: str, settings: dict[str, str], access: str) -> None:
    """`change` made to the record (the tenant's or the system's), as another writer or a fault would."""
    from defender.tests.support.jobs._jobs1342 import move_tenant
    from defender.tests.support.shared._postgres1339 import execute

    if change == "generation raised":
        moved = await served.put_system(system, 1, settings=settings, access=access.replace(".test", ".moved.test"))
        assert moved.status_code == 200, moved.text
    elif change == "deleted":
        assert (await served.delete_system(system, 1)).status_code == 204
    elif change == "tenant not active":
        await anyio.to_thread.run_sync(lambda: move_tenant(served.dsn, A, state="offboarding"))
    elif change == "tenant row gone":
        await remove_tenant(served.dsn, A)
    elif change == "access unparseable":
        served.plant_version(system, 2, settings=settings, access="not: [a declaration")
    elif change == "the re-read fails":
        await anyio.to_thread.run_sync(execute, served.dsn, "SET lock_timeout = '5s'; "
                                       "ALTER TABLE tenancy.system_versions RENAME TO sv_away")


def _changing(served: Configured, change: str, system: str, settings: dict[str, str], access: str,
              seen: list[str | None]) -> Any:
    """An `on_write` hook that makes `change` once, then notes in `seen` what the slot now answers (its refusal type's
    name, None, or "exception")."""
    from defender.system_records import RecordRefused, RecordStore
    from defender.tests.support.jobs._jobs1342 import fixed_clock

    async def meanwhile(path: str) -> None:
        assert served.scripted is not None
        served.scripted.on_write = None
        with anyio.fail_after(30):
            await _change(served, change, system, settings, access)
        store = RecordStore(served.dsn, clock=fixed_clock, judge=lambda after, before: [])
        try:
            await store.credential_slot(A, system, 1)
            seen.append(None)
        except RecordRefused as refusal:
            seen.append(type(refusal).__name__)
        except Exception:  # noqa: BLE001 — the re-read that fails
            seen.append("exception")
        finally:
            await store.close()

    return meanwhile


_REREAD_CASES = [(change, announcing) for change in _REREADS for announcing in ("works", "fails")]


@anyio_mark
@postgres
@pytest.mark.parametrize(("change", "announcing"), _REREAD_CASES, ids=[f"{c}-{a}" for c, a in _REREAD_CASES])
async def test_o7_o9_the_re_read_tells_an_unused_generation_from_a_refusal_of_the_current_one(
        scripted, caplog, change, announcing):
    """The set is stored, then the record changes before the re-read, one change per slot refusal type. The generation
    moved or the system deleted: 409 announced `stored for an unused generation` (`current_version` the new version, or
    0 when deleted). Any other refusal (the tenant left `active` or is gone, the access no longer parses) does not show
    the set unused, so it is announced as stored, with no marker, and the answer is that refusal's own status, saying
    the set was stored. A re-read that fails is 503 possibly stored; unchanged is 204. With the
    announcement failing each is 500 and the set stands. The one event names the fields and no value. (O7, O9; r8 Am-3)"""
    from defender.tests.support.shared._postgres1339 import execute

    caplog.set_level(logging.DEBUG)
    scheme = sorted(_scheme_systems())[list(_REREADS).index(change) % len(_scheme_systems())]
    system, settings, access, fields = _scheme_systems()[scheme]
    assert (await scripted.put_system(system, 0, settings=settings, access=access)).status_code == 201
    sent, seen = _a_set(fields, 1), []
    scripted.scripted.on_write = _changing(scripted, change, system, settings, access, seen)
    failing = _AnnouncementFails("system.credentials") if announcing == "fails" else None
    if failing:
        logging.getLogger().addHandler(failing)
    caplog.clear()
    try:
        async with scripted.lenient() as client:
            got = await client.put(f"/tenants/{A}/systems/{system}/credentials", headers=scripted.ann(),
                                   json={"for_version": 1, "credentials": sent})
    finally:
        if failing:
            logging.getLogger().removeHandler(failing)
        if change == "the re-read fails":
            execute(scripted.dsn, "ALTER TABLE tenancy.sv_away RENAME TO system_versions")
    assert seen == [_REREADS[change]], ("premise: the change makes the slot refuse so", seen)
    expected = _REREADS[change]
    status = (204 if expected is None else 503 if expected == "exception" else 409 if expected in _UNUSED
              else _OWN_STATUS[expected])
    assert got.status_code == (500 if failing else status), got.text
    marker = MARKER_POSSIBLY if expected == "exception" else MARKER_UNUSED if expected in _UNUSED else None
    if not failing and expected in _UNUSED:
        assert got.json()["current_version"] == {"Stale": 2, "NoCurrentRecord": 0}[expected], got.text
        assert MARKER_UNUSED in problem_text(got).lower(), got.text
    if not failing and expected in _OWN_STATUS:
        said = problem_text(got).lower()
        assert "were stored" in said, got.text
        assert MARKER_UNUSED not in said, got.text
        assert "possibly" not in said, got.text
    if not failing and status == 503:  # noqa: PLR2004
        assert MARKER_POSSIBLY in problem_text(got).lower(), got.text
    if failing:
        assert failing.refused == 1, "premise: the event was announced, and that failed"
    else:
        events = audit_events(caplog, "system.credentials")
        assert _event_faults(events, system=system, marker=marker, fields=fields, sent=sent) == [], [told(e) for e in events]
    assert scripted.scripted.stored(f"{A}/{system}/g1") == {"kind": _kind(scheme), "fields": sent}, "the write stands"


@anyio_mark
@postgres
async def test_o7_o9_a_re_read_that_cannot_answer_is_503_possibly_stored_and_announced_so(scripted, caplog):
    """The record store fails between the write and its re-read (the table is gone): 503 'possibly stored', announced
    `possibly stored`. (O7, O9)"""
    from defender.tests.support.shared._postgres1339 import execute

    caplog.set_level(logging.DEBUG)
    await _ticket(scripted)
    caplog.clear()

    async def break_the_records(path: str) -> None:
        with anyio.fail_after(30):  # off the loop, and failing rather than hanging on a lock the app holds
            await anyio.to_thread.run_sync(
                execute, scripted.dsn, "SET lock_timeout = '5s'; ALTER TABLE tenancy.system_versions RENAME TO sv_away")

    scripted.scripted.on_write = break_the_records
    try:
        refused = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})
    finally:
        execute(scripted.dsn, "ALTER TABLE tenancy.sv_away RENAME TO system_versions")
    assert refused.status_code == 503, refused.text
    assert MARKER_POSSIBLY in problem_text(refused).lower()
    [event] = audit_events(caplog, "system.credentials")
    assert MARKER_POSSIBLY in told(event)
    assert scripted.stored_set(TICKET, 1) == {"kind": "static", "fields": {"api_key": TOKEN}}


@anyio_mark
@postgres
async def test_o7_the_kind_stored_is_the_schemes_not_a_constant(scripted):
    """An oauth-scheme system stores its set as kind `oauth-client-credentials` with `client_id`/`client_secret`; a bearer
    one stays `static`. (O7, P4)"""
    from defender.tests.support.tenancy import _systems1366 as R

    access = R.declaration("http://soc-playground:8004", scheme=R.OAUTH, token_url="https://soc-playground:8004/token",
                           writes=(("POST", "/tickets/*/comments"),))
    assert (await scripted.put_system(TICKET, 0, access=access)).status_code == 201
    pair = {"client_id": "client-1", "client_secret": TOKEN}
    assert (await scripted.put_credentials(TICKET, 1, pair)).status_code == 204
    assert scripted.stored_set(TICKET, 1) == {"kind": "oauth-client-credentials", "fields": pair}
    refused = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})  # the bearer shape no longer fits
    assert refused.status_code == 422, refused.text
    assert holds_no_value(refused, {"api_key": TOKEN}), ("a credential value was printed", refused.text)  # N1


# --- O7 / O9: the post-write re-read ---------------------------------------------------------------------------------

@anyio_mark
@postgres
async def test_o7_o9_a_set_stored_for_a_generation_that_moved_meanwhile_is_409_and_announced_as_unused(scripted, caplog):
    """Another admin saves v2 with a new base while the set is being written: the re-read sees a new generation → 409
    naming 2, the set stays at g1, announced `stored for an unused generation`. (O7, O9, scenario)"""
    caplog.set_level(logging.DEBUG)
    await _ticket(scripted)
    caplog.clear()

    async def other_admin_moves_the_base(path: str) -> None:
        with anyio.fail_after(30):  # a stuck second request fails the test rather than hanging it
            saved = await scripted.put_system(TICKET, 1, access=TICKET_ACCESS.replace(*BASE_MOVED))
        assert saved.status_code == 200, saved.text

    scripted.scripted.on_write = other_admin_moves_the_base
    refused = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})
    assert refused.status_code == 409, refused.text
    assert refused.json()["current_version"] == 2
    assert "faults" not in refused.json()
    assert scripted.stored_generations(TICKET) == [1]
    assert (await scripted.get_system(TICKET)).json()["has_credentials"] is False
    [event] = audit_events(caplog, "system.credentials")
    assert MARKER_UNUSED in told(event)
    assert event.target == TICKET
    assert TOKEN not in told(event)
    scripted.scripted.on_write = None
    assert (await scripted.put_credentials(TICKET, 2, {"api_key": TOKEN})).status_code == 204  # control


@anyio_mark
@postgres
async def test_o7_o9_a_save_that_keeps_the_generation_meanwhile_leaves_the_write_a_204_with_no_marker(scripted, caplog):
    """v2 changes only an index key (same generation) during the write: 204, announced plainly. (O7, O9, scenario)"""
    caplog.set_level(logging.DEBUG)
    await _ticket(scripted)
    caplog.clear()

    async def other_admin_changes_a_setting(path: str) -> None:
        with anyio.fail_after(30):
            saved = await scripted.put_system(TICKET, 1, settings=TICKET_SETTINGS | {"TICKET_TIMEOUT_SEC": "20"})
        assert saved.status_code == 200, saved.text

    scripted.scripted.on_write = other_admin_changes_a_setting
    done = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})
    assert done.status_code == 204, done.text
    [event] = audit_events(caplog, "system.credentials")
    assert MARKER_UNUSED not in told(event)
    assert MARKER_POSSIBLY not in told(event)
    assert (await scripted.get_system(TICKET)).json()["has_credentials"] is True


@anyio_mark
@postgres
async def test_o7_o9_a_system_deleted_during_the_write_is_409_naming_0_and_announced_as_unused(scripted, caplog):
    """Deleted while the set is being written: 409 with `current_version` 0, announced as unused. (O7, O9)"""
    caplog.set_level(logging.DEBUG)
    await _ticket(scripted)
    caplog.clear()

    async def other_admin_deletes(path: str) -> None:
        with anyio.fail_after(30):
            deleted = await scripted.delete_system(TICKET, 1)
        assert deleted.status_code == 204

    scripted.scripted.on_write = other_admin_deletes
    refused = await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})
    assert refused.status_code == 409
    assert refused.json()["current_version"] == 0, refused.text
    [event] = audit_events(caplog, "system.credentials")
    assert MARKER_UNUSED in told(event)
    assert (await scripted.get_system(TICKET)).status_code == 404


# --- O9: one event per stored write ----------------------------------------------------------------------------------

MAPPING_ENTRIES = ("signature", "event_time", "summary", "case_key", "title", "description")
AUDITED = ("system.update", "system.delete", "case_record.update", "case_record.delete", "system.credentials",
           "alert_mapping.update")


@anyio_mark
@postgres
async def test_o9_each_stored_write_announces_one_event_naming_the_member_and_the_target_and_refused_writes_none(configured, caplog):
    """System put x2, case put/delete, credentials, system delete, mapping: one event each by Ann in A, targets the
    system (system and credential events) or the tenant (case and mapping events); a stale put, a judged put, a stale
    delete, a refused credential set and a request for another tenant announce nothing; the credential event names
    fields, never values. (O9)"""
    caplog.set_level(logging.DEBUG)
    caplog.clear()
    assert (await configured.put_system(TICKET, 0)).status_code == 201
    assert (await configured.put_system(TICKET, 1)).status_code == 200
    assert (await configured.put_system(TICKET, 1)).status_code == 409
    assert (await configured.put_system(TICKET, 2, settings={})).status_code == 422
    assert (await configured.put_case(0)).status_code == 201
    assert (await configured.put_case(0)).status_code == 409
    assert (await configured.delete_case(1)).status_code == 204
    assert (await configured.delete_case(1)).status_code == 404
    assert (await configured.put_credentials(TICKET, 2, {"api_key": TOKEN})).status_code == 204
    assert (await configured.put_credentials(TICKET, 9, {"api_key": TOKEN})).status_code == 409
    assert (await configured.put_credentials(TICKET, 2, {"api_key": "x"})).status_code == 422
    assert (await configured.delete_system(TICKET, 1)).status_code == 409
    assert (await configured.delete_system(TICKET, 2)).status_code == 204
    assert (await configured.delete_system(TICKET, 3)).status_code == 404
    mapping = await configured.put_raw(f"/tenants/{A}/alert-mapping", {e: FIXTURE_ALERT_MAPPING.get(e) for e in MAPPING_ENTRIES})
    assert mapping.status_code == 200, mapping.text

    events = audit_events(caplog, *AUDITED)
    assert [e.action for e in events] == ["system.update", "system.update", "case_record.update", "case_record.delete",
                                          "system.credentials", "system.delete", "alert_mapping.update"], \
        [(e.action, e.target) for e in events]
    assert {(e.actor, e.tenant_id) for e in events} == {(configured.user_id(ANN), A)}
    assert {e.target for e in events if e.action.startswith("system.")} == {TICKET}
    assert {e.target for e in events if not e.action.startswith("system.")} == {A}
    [credentials] = [e for e in events if e.action == "system.credentials"]
    assert "api_key" in told(credentials)
    assert MARKER_UNUSED not in told(credentials)
    assert MARKER_POSSIBLY not in told(credentials)
    assert TOKEN not in " ".join(told(e) for e in events)


@anyio_mark
@postgres
async def test_o7_a_credential_write_asks_the_secret_store_for_no_existence_check_and_no_value(scripted):
    """The write goes straight to the secret store: no metadata (existence) read, no value read, the slot decided by the
    record store alone. Base: "an existence check, not a read". (O7, Flows: set credentials)"""
    await _ticket(scripted)
    scripted.scripted.calls.clear()
    assert (await scripted.put_credentials(TICKET, 1, {"api_key": TOKEN})).status_code == 204
    calls = scripted.scripted.calls
    assert calls, "premise: the write reached the secret store"
    assert [c for c in calls if c[1].split("/")[1:2] == ["metadata"]] == [], "an existence check, not a read"
    assert scripted.scripted.value_reads == []


class _Probe(logging.Handler):
    """A handler on the root logger that, as each audited event arrives, asks the `expect[action]` callable whether the
    write the event announces is already visible to another connection; `seen` is (action, visible) in arrival order."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.expect: dict[str, object] = {}
        self.seen: list[tuple[str, bool]] = []

    def emit(self, record: logging.LogRecord) -> None:
        action = getattr(record, "action", None)
        if action in AUDITED and action in self.expect:
            self.seen.append((action, bool(self.expect.pop(action)())))  # type: ignore[operator]


@anyio_mark
@postgres
async def test_o9_each_config_write_is_announced_only_after_it_is_visible(configured, caplog):
    """When each config write's event arrives, its version row, set or mapping is already visible to another connection
    (the event follows the commit). Base: `log.visible_on_arrival == [True]`. (O9: "after it commits")"""
    from defender.tests.support.shared._postgres1339 import execute
    from defender.tests.support.tenancy import _systems1366 as R

    caplog.set_level(logging.DEBUG)
    probe = _Probe()
    logging.getLogger().addHandler(probe)
    try:
        mapping = {e: f"vendor.c12.{e}" for e in MAPPING_ENTRIES}
        steps = [
            ("system.update", lambda: any(v.version == 1 for v in configured.versions(TICKET)),
             lambda: configured.put_system(TICKET, 0)),
            ("case_record.update", lambda: [v.deleted for v in R.case_versions(configured.dsn, A)] == [False],
             lambda: configured.put_case(0)),
            ("case_record.delete", lambda: [v.deleted for v in R.case_versions(configured.dsn, A)] == [False, True],
             lambda: configured.delete_case(1)),
            ("system.credentials", lambda: configured.stored_set(TICKET, 1) == {"kind": "static", "fields": {"api_key": TOKEN}},
             lambda: configured.put_credentials(TICKET, 1, {"api_key": TOKEN})),
            ("alert_mapping.update",
             lambda: execute(configured.dsn, "SELECT title FROM tenancy.alert_mappings WHERE tenant_id = %s", (A,)) == [("vendor.c12.title",)],
             lambda: configured.put_raw(f"/tenants/{A}/alert-mapping", mapping)),
            ("system.delete", lambda: [v.deleted for v in configured.versions(TICKET)] == [False, True],
             lambda: configured.delete_system(TICKET, 1)),
        ]
        for action, visible, write in steps:
            probe.expect[action] = visible
            answered = await write()
            assert answered.status_code < 300, (action, answered.text)
    finally:
        logging.getLogger().removeHandler(probe)
    assert probe.seen == [(action, True) for action, _, _ in steps], probe.seen


class _AnnouncementFails(logging.Handler):
    """A handler on the root logger whose `handle` raises for one audited action: the announcement itself fails, as an
    audit sink that refuses it would, with no patching of the app."""

    def __init__(self, action: str) -> None:
        super().__init__(logging.DEBUG)
        self.action, self.refused = action, 0

    def handle(self, record: logging.LogRecord) -> bool:
        if getattr(record, "action", None) == self.action:
            self.refused += 1
            raise RuntimeError("the audit sink refuses the announcement")
        return False


async def _set_up(served: Configured, *, system: bool = False, case: bool = False) -> None:
    if system:
        assert (await served.put_system(TICKET, 0)).status_code == 201
    if case:
        assert (await served.put_case(0)).status_code == 201


async def _write(client: httpx.AsyncClient, served: Configured, method: str, path: str, **kw: object) -> httpx.Response:
    return await client.request(method, f"/tenants/{A}{path}", headers=served.ann(), **kw)  # type: ignore[arg-type]


#: (action, what the case needs first, the write, a check of the stored state after it). O9: an announcement that fails
#: after the commit answers 500 and the write stands (#1083 Am-2/P2); base asserted it over the demo ports.
_ANNOUNCED = [
    ("system.update", {}, lambda c, s: _write(c, s, "PUT", f"/systems/{TICKET}", json={
        "replaces": 0, "enabled": True, "settings": TICKET_SETTINGS, "access": TICKET_ACCESS}),
     lambda s: [v.version for v in s.versions(TICKET)] == [1]),
    ("system.delete", {"system": True}, lambda c, s: _write(c, s, "DELETE", f"/systems/{TICKET}", params={"replaces": 1}),
     lambda s: [v.deleted for v in s.versions(TICKET)] == [False, True]),
    ("case_record.update", {"system": True}, lambda c, s: _write(c, s, "PUT", "/case-record", json={
        "replaces": 0, "system_id": TICKET, "comment_body": BODY}),
     lambda s: [v.deleted for v in _case_versions(s)] == [False]),
    ("case_record.delete", {"system": True, "case": True}, lambda c, s: _write(c, s, "DELETE", "/case-record", params={"replaces": 1}),
     lambda s: [v.deleted for v in _case_versions(s)] == [False, True]),
    ("system.credentials", {"system": True}, lambda c, s: _write(c, s, "PUT", f"/systems/{TICKET}/credentials", json={
        "for_version": 1, "credentials": {"api_key": TOKEN}}),
     lambda s: s.stored_set(TICKET, 1) == {"kind": "static", "fields": {"api_key": TOKEN}}),
    ("alert_mapping.update", {}, lambda c, s: _write(c, s, "PUT", "/alert-mapping", json={
        e: f"vendor.q3.{e}" for e in MAPPING_ENTRIES}),
     lambda s: _mapping_title(s) == [("vendor.q3.title",)]),
]


def _case_versions(served: Configured) -> list[object]:
    from defender.tests.support.tenancy import _systems1366 as R

    return R.case_versions(served.dsn, A)


def _mapping_title(served: Configured) -> list[tuple[object, ...]]:
    from defender.tests.support.shared._postgres1339 import execute

    return execute(served.dsn, "SELECT title FROM tenancy.alert_mappings WHERE tenant_id = %s", (A,))


@anyio_mark
@postgres
@pytest.mark.parametrize(("action", "needs", "write", "stands"), _ANNOUNCED, ids=[a[0] for a in _ANNOUNCED])
async def test_o9_an_announcement_that_fails_after_the_commit_answers_500_and_the_write_stands(
        scripted, caplog, action, needs, write, stands):
    """The event for each config write fails to be announced: the answer is 500 and what was written stays written (no
    rollback, no second attempt at the write). The same write with the sink healthy is the control for each. (O9, #1083
    Am-2/P2; base `test_a_demo_announcement_that_fails_after_the_write_answers_500_and_the_write_stands`)"""
    caplog.set_level(logging.DEBUG)
    await _set_up(scripted, system=needs.get("system", False), case=needs.get("case", False))
    failing = _AnnouncementFails(action)
    logging.getLogger().addHandler(failing)
    try:
        async with scripted.lenient() as client:
            served = await write(client, scripted)
    finally:
        logging.getLogger().removeHandler(failing)
    assert failing.refused == 1, "premise: the write was announced, and the announcement was the thing that failed"
    assert served.status_code == 500, served.text
    assert stands(scripted), "the write stands"


# --- C10: the writer policy ------------------------------------------------------------------------------------------

def _writer_calls(transport: httpx.BaseTransport | None, addr: str, token: str, mount: str) -> list[int]:
    """The statuses of: a write, a metadata read of it, a metadata read of a path never written, a value read, a delete,
    a list, and a read with another token: the answers `ScriptedOpenBao` was written from."""
    with httpx.Client(transport=transport, base_url=addr, headers={"X-Vault-Token": token}) as client:
        data, metadata = f"/v1/{mount}/data/t/s/g1", f"/v1/{mount}/metadata/t/s/g1"
        statuses = [client.post(data, json={"data": {"kind": "static", "fields": {"api_key": TOKEN}}}).status_code,
                    client.get(metadata).status_code, client.get(f"/v1/{mount}/metadata/t/s/g2").status_code,
                    client.get(data).status_code, client.delete(data).status_code,
                    client.request("LIST", f"/v1/{mount}/metadata/t").status_code]
        statuses.append(client.get(metadata, headers={"X-Vault-Token": "not-a-token"}).status_code)
    return statuses


#: write 200, metadata of it 200, of nothing 404, a value read 403, delete 403, list 403, an unknown token 403.
WRITER_STATUSES = [200, 200, 404, 403, 403, 403, 403]


def test_c10_the_scripted_stand_in_answers_as_the_writer_policy_was_observed_to():
    """The stand-in's answers to the calls the API makes and the ones the writer must not: the same list the real server
    gives in the next test. (C10, stand-in fidelity)"""
    bao = ScriptedOpenBao()
    assert _writer_calls(bao, "http://openbao.test", WRITER_TOKEN, KV_MOUNT) == WRITER_STATUSES
    assert bao.value_reads == ["t/s/g1"]


@pytest.mark.openbao
def test_c10_the_writer_policy_creates_and_updates_a_set_and_reads_metadata_but_cannot_read_a_value_back(openbao):
    """With the API's role (`store_policies` writer): a set is written, its metadata read, and a value read, delete and
    list are refused, as is another token. (C10)"""
    from defender.credential_proxy._openbao import store_policies

    writer = openbao.token_for(openbao.apply_policy("api-writer-c10", store_policies(kv_mount=openbao.kv_mount)["writer"]))
    tenant = openbao.tenant()
    data = f"{openbao.kv_mount}/data/{tenant}/s/g1"
    with httpx.Client(base_url=openbao.addr, headers={"X-Vault-Token": writer}) as client:
        write = client.post(f"/v1/{data}", json={"data": {"kind": "static", "fields": {"api_key": TOKEN}}})
        again = client.post(f"/v1/{data}", json={"data": {"kind": "static", "fields": {"api_key": TOKEN + "-2"}}})
        got = [client.get(f"/v1/{openbao.kv_mount}/metadata/{tenant}/s/g1").status_code,
               client.get(f"/v1/{openbao.kv_mount}/metadata/{tenant}/s/g2").status_code,
               client.get(f"/v1/{data}").status_code, client.delete(f"/v1/{data}").status_code,
               client.request("LIST", f"/v1/{openbao.kv_mount}/metadata/{tenant}").status_code]
    assert (write.status_code, again.status_code) == (200, 200)
    assert got == [200, 404, 403, 403, 403]
    stored = openbao.call("GET", data)
    assert stored.json()["data"]["data"]["fields"] == {"api_key": TOKEN + "-2"}  # read as root: the set is there, replaced whole
    assert stored.json()["data"]["metadata"]["version"] == 2
