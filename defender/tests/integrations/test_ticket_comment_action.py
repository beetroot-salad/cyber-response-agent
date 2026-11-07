"""#1359 the playground `ticket` adapter's `add_case_comment` on the docker route: one confined
POST of {author, body} on the key as one path segment, its link, and the shared fault classes
(a 4xx is an `UpstreamFault` carrying the status). The agent-facing entry stays read-only."""
from __future__ import annotations

import json

import pytest

from defender.integrations import _stub_transport as transport
from defender.integrations import ticket_adapter
from defender.integrations.confinement import ConfinementFault
from defender.kit.faults import TransportFault, UpstreamFault
from defender.tests.support.runtime.engine import _spec767 as M
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

#: The status attribute on `UpstreamFault` (r4 "UpstreamFault carries the store's HTTP status";
#: the attribute name is not settled by the design: provisional, one place).
STATUS_ATTR = "status"


def _ctx(tmp_path, monkeypatch, *answers):
    M.use_case_record(monkeypatch, tmp_path / "dfn")
    store = M.FakeStore(tmp_path / "store", answers=list(answers) or None)
    ctx = S.verb_context(M.current_record(), tmp_path / "run", store.env({}))
    return ctx, store


def test_o1_the_action_posts_author_and_body_on_the_key_and_returns_the_link(tmp_path, monkeypatch):
    """One POST /tickets/<key>/comments of {author, body}; returns `<URL_BASE>/tickets/<key>`. O1, r4."""
    ctx, store = _ctx(tmp_path, monkeypatch)
    link = ticket_adapter.add_case_comment(ctx, key="SOC-1042", body="line one\nline two")
    assert [(c.method, c.path) for c in store.calls] == [("POST", "/tickets/SOC-1042/comments")]
    payload = store.only_comment()
    assert set(payload) == {"author", "body"}, payload
    assert payload["body"] == "line one\nline two"
    assert payload["author"].strip()
    assert link == f"{M.CONFIG['URL_BASE']}/tickets/SOC-1042"


@pytest.mark.parametrize(("key", "segment"), [
    ("SOC-1?x=1", "SOC-1%3Fx%3D1"), ("SOC-1#frag", "SOC-1%23frag"), ("a%2Fb", "a%252Fb"),
    ("SOC-λ42", "SOC-%CE%BB42")])
def test_p3_the_key_is_one_percent_encoded_path_segment(tmp_path, monkeypatch, key, segment):
    """A key with URL-special characters cannot reshape the request. P3."""
    ctx, store = _ctx(tmp_path, monkeypatch)
    ticket_adapter.add_case_comment(ctx, key=key, body="x")
    assert [c.path for c in store.calls] == [f"/tickets/{segment}/comments"]


@pytest.mark.parametrize(("answer", "fault", "status"), [
    (S.answer(json.dumps({"detail": "no such ticket"}), "404"), UpstreamFault, 404),
    (S.answer(json.dumps({"detail": "bad"}), "422"), UpstreamFault, 422),
    (S.answer(json.dumps({"detail": "down"}), "503"), TransportFault, None),
    (S.curl_timed_out(), TransportFault, None),
])
def test_o3_store_answers_map_to_the_shared_fault_classes(tmp_path, monkeypatch, answer, fault, status):
    """A 4xx raises `UpstreamFault` with the status; a 5xx or unreachable store a `TransportFault`. O3, r4."""
    ctx, store = _ctx(tmp_path, monkeypatch, answer)
    with pytest.raises(fault) as raised:
        ticket_adapter.add_case_comment(ctx, key="SOC-1", body="x")
    assert len(store.writes()) == 1 or fault is TransportFault
    if status is not None:
        assert getattr(raised.value, STATUS_ATTR, None) == status, vars(raised.value)


def test_p2_the_agent_facing_post_entry_cannot_write_a_comment(tmp_path, monkeypatch):
    """The shared transport's agent-facing `http_post` is still refused on the comment path; only
    the host's write entry (the adapter action) reaches it, so no query verb can comment. P2, O4."""
    ctx, store = _ctx(tmp_path, monkeypatch)
    cfg = transport.load_config(ctx, "ticket", "TICKET", ("URL_BASE", "BASTION_HOST", "TIMEOUT_SEC"))
    with pytest.raises(ConfinementFault):
        transport.http_post(ctx, cfg, "/tickets/SOC-1/comments", {"author": "a", "body": "b"},
                            system="ticket")
    assert store.calls == [], "the read-class POST reached the store"
    ticket_adapter.add_case_comment(ctx, key="SOC-1", body="b")
    assert len(store.writes()) == 1, "positive control: the host action reaches it"


#: The fact a `TransportFault` carries (#1374 r2): may the request have reached the store?
MAYBE_DELIVERED = "maybe_delivered"


@pytest.mark.parametrize(("answer", "maybe"), [
    (S.answer("", "000", rc=7, stderr="curl: (7) Failed to connect to ticket port 80"), False),
    (S.answer("", "000", rc=6, stderr="curl: (6) Could not resolve host: ticket"), False),
    (S.answer("", None, rc=125, stderr="docker: invalid flag"), False),
    (S.answer("", None, rc=127, stderr="curl: not found"), False),
    (S.no_such_container("bastion"), True),
    (S.container_not_running(), True),
    (S.curl_timed_out(), True),
    (S.answer("", "000", rc=52, stderr="curl: (52) Empty reply from server"), True),
    (S.answer("", "000", rc=56, stderr="curl: (56) Recv failure: Connection reset by peer"), True),
    (S.answer(json.dumps({"detail": "down"}), "503"), True),
    (S.answer("", None, rc=137), True),
], ids=["refused", "dns", "docker-125", "no-curl-in-the-box", "no-container", "container-stopped", "timeout", "empty-reply", "reset",
        "store-503", "curl-killed-with-no-status-line"])
def test_1374_a_curl_route_write_fault_says_whether_it_may_have_reached_the_store(
        tmp_path, monkeypatch, answer, maybe):
    """#1374 P1/P2 on the docker route: "did not reach the store" only where proven from data —
    curl's exit 6/7, or docker's own 125-127 with no status line. Docker's exit 1 also follows a
    client that lost its daemon after curl started, so it proves nothing; every other failure, a
    5xx included, may have reached it."""
    ctx, store = _ctx(tmp_path, monkeypatch, answer)
    with pytest.raises(TransportFault) as raised:
        ticket_adapter.add_case_comment(ctx, key="SOC-1", body="x")
    assert getattr(raised.value, MAYBE_DELIVERED) is maybe, raised.value


def test_1374_a_missing_docker_cli_did_not_reach_the_store(tmp_path, monkeypatch):
    """#1374: with no docker on the PATH nothing was sent."""
    M.use_case_record(monkeypatch, tmp_path / "dfn")
    empty = tmp_path / "empty"
    empty.mkdir()
    ctx = S.verb_context(M.current_record(), tmp_path / "run", {"PATH": str(empty)})
    with pytest.raises(TransportFault) as raised:
        ticket_adapter.add_case_comment(ctx, key="SOC-1", body="x")
    assert "docker CLI not found" in raised.value.detail, "positive control: the CLI was missing"
    assert getattr(raised.value, MAYBE_DELIVERED) is False, raised.value
