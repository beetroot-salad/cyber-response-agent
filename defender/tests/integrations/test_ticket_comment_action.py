"""#1359 the playground `ticket` adapter's `add_case_comment`, through the credential proxy (#1391
O1): one POST of {author, body} on the key as one path segment, its link, and the shared fault
classes (a 4xx is an `UpstreamFault` carrying the status)."""
from __future__ import annotations

import json

import pytest

from defender.integrations import ticket_adapter
from defender.kit.faults import TransportFault, UpstreamFault
from defender.tests.support.runtime.engine import _spec767 as M
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

#: The status attribute on `UpstreamFault` (r4 "UpstreamFault carries the store's HTTP status";
#: the attribute name is not settled by the design: provisional, one place).
STATUS_ATTR = "status"


def _ctx(tmp_path, monkeypatch, *answers):
    M.use_case_record(monkeypatch, tmp_path / "dfn")
    store = M.FakeStore(tmp_path / "store", answers=list(answers) or None)
    ctx = S.verb_context(M.current_record(), tmp_path / "run", store.env({}),
                         proxy_url=store.url, request_token=M.WRITE_TOKEN)
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
    assert link == f"{M.TICKET_BASE}/tickets/SOC-1042"


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
    (S.timed_out(), TransportFault, None),
])
def test_o3_store_answers_map_to_the_shared_fault_classes(tmp_path, monkeypatch, answer, fault, status):
    """A 4xx raises `UpstreamFault` with the status; a 5xx or unreachable store a `TransportFault`. O3, r4."""
    ctx, store = _ctx(tmp_path, monkeypatch, answer)
    with pytest.raises(fault) as raised:
        ticket_adapter.add_case_comment(ctx, key="SOC-1", body="x")
    assert len(store.writes()) == 1 or fault is TransportFault
    if status is not None:
        assert getattr(raised.value, STATUS_ATTR, None) == status, vars(raised.value)


# Retired by #1391 O1/O2 (the docker route is gone):
# - `test_p2_the_agent_facing_post_entry_cannot_write_a_comment` pinned the docker route's
#   write-endpoint table. Every request now goes through the proxy, whose route check is the only
#   guard (#1163 A6): a read token's POST on the comment route is refused unsent there
#   (`credential_proxy_1163/test_proxy_scope.py::test_s3_only_declared_reads_and_granted_writes_are_sent`).
# - `test_1374_a_curl_route_write_fault_says_whether_it_may_have_reached_the_store` and
#   `test_1374_a_missing_docker_cli_did_not_reach_the_store` pinned how curl's and docker's exits
#   decided "may have reached the store". On the proxy route the proxy says so (`sent`), covered by
#   `credential_proxy_1163/test_ticket_flow.py` and
#   `test_1359_ready_made_adapters.py::test_1374_a_lost_answer_is_settled_through_the_real_proxy`.
