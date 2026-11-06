"""#1163 O9 at the proxy: one audit record per proxied request, refusals included, and never
a secret value."""
from __future__ import annotations

import json
import threading
import time
from typing import Any

import pytest

from defender.kit.faults import ConfigFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _stream1412 as W
from defender.tests.integrations.credential_proxy_1163 import _tenant as T
from defender.tests.integrations.credential_proxy_1163._target import AUDIT_KEYS, proxy

BASE = T.BASE_PATH


def test_a1_every_request_is_one_record_naming_who_what_and_how_it_ended(tmp_path, data_root):
    """Sent, upstream-refused and policy-refused requests each leave one record with tenant,
    system, investigation, commit, method, relative path and outcome. O9, A4."""
    with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
            u + BASE, writes=(("POST", "/tickets"),))) as r:
        r.up.replies[f"{BASE}/missing"] = (404, {}, b"{}")
        r.ask(path="/users/dana")
        r.ask(path="/missing")
        r.ask("POST", "/tickets", grant={("identity", "r")}, body="{}")
        r.ask("DELETE", "/users/dana")
        r.ask(url=f"{r.up.url}/outside")

    assert len(r.audit.records) == 5
    for record in r.audit.records:
        assert set(AUDIT_KEYS) <= set(record), record
        assert (record["tenant"], record["system"], record["investigation"]) == (
            r.t.tenant_id, "identity", T.RUN_ID)
        assert record["commit"] == r.t.commit
    assert [(x["method"], x["outcome"]) for x in r.audit.records] == [
        ("GET", "sent 200"), ("GET", "sent 404"), ("POST", "ConfinementFault"),
        ("DELETE", "ConfinementFault"), ("GET", "ConfigFault")]
    assert [x["path"] for x in r.audit.records[:4]] == [
        "/users/dana", "/missing", "/tickets", "/users/dana"]


def test_a1_a_request_refused_on_its_token_is_still_one_record(tmp_path, data_root):
    """An unverifiable and a garbage token are each audited with their fault class,
    not in the fields asserted. O9, O8."""
    with T.rig(tmp_path / "forge", data_root) as r:
        r.verifier = H.FakeVerifier(False)
        r.rebuild()
        r.ask(tok=r.tok())
        r.ask(tok="not-a-token")

    assert [x["outcome"] for x in r.audit.records] == ["ConfigFault", "ConfigFault"]


def test_a1_no_secret_value_is_in_the_audit(tmp_path, data_root):
    """Across static and OAuth requests, the key, client secret, access token, request token
    and its signature are absent from every record. O9, O4."""
    issued: list[str] = []
    with H.upstream() as auth:
        auth.replies["/token"] = H.token_endpoint(issued)
        with T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(
                u + BASE, scheme=H.oauth_scheme(auth.url + "/token")),
                creds=T.oauth_set()) as r:
            tok = r.tok()
            r.ask(tok=tok)
            r.store.sets[(r.t.tenant_id, "identity")] = T.static_set()
            r.ask(tok=tok)  # kind mismatch: refused
            r.ask(tok=tok, url=f"{r.up.url}/outside")

    text = json.dumps(r.audit.records)
    assert len(r.audit.records) == 3
    for secret in (H.CANARY_KEY, H.CANARY_SECRET, issued[0], tok, tok.rpartition(".")[2]):
        assert secret not in text


def test_a2_the_file_sink_appends_one_json_object_per_line_and_never_truncates(tmp_path):
    """The shipped file sink adds one JSON object per line after what the file already holds,
    across sink instances, and creating one leaves the file as it was. A13, O9."""
    path = tmp_path / "audit.log"
    existing = '{"earlier": "line"}\nnot json but kept\n'
    path.write_text(existing, encoding="utf-8")

    proxy().FileAuditSink(path)
    assert path.read_text(encoding="utf-8") == existing
    first = {"tenant": "t1", "outcome": "sent 200", "path": "/a"}
    second = {"tenant": "t2", "outcome": "ConfigFault", "path": "/b"}
    proxy().FileAuditSink(path).record(first)
    proxy().FileAuditSink(path).record(second)

    text = path.read_text(encoding="utf-8")
    assert text.startswith(existing)
    lines = text[len(existing):].splitlines()
    assert [json.loads(line) for line in lines] == [first, second]
    assert text.endswith("\n")


@pytest.mark.parametrize("sink", ["working", "failing"])
def test_a2_an_audit_that_cannot_be_written_withholds_the_upstreams_answer(
        tmp_path, data_root, sink):
    """When the audit record cannot be written the answer is `TransportFault` (r7 A18: the
    operator's disk, not the tenant's setup) and the upstream's body is not returned; with a
    working sink the body is. A13, O9."""
    body = b"UPSTREAM-BODY-1163"
    audit = H.AuditRecorder() if sink == "working" else H.FailingAudit()
    with T.rig(tmp_path / "forge", data_root, audit=audit) as r:
        r.up.replies[f"{BASE}/users/x"] = (200, {"X-Up": "upstream-header-1163"}, body)
        answer = r.ask()

    if sink == "working":
        assert answer["fault"] is None
        assert "UPSTREAM-BODY-1163" in answer["body"]
        assert len(audit.records) == 1
    else:
        assert answer["fault"] == "TransportFault"
        assert (answer["status"], answer["body_whole"]) == (None, False)
        assert "withheld" in answer["detail"]
        assert audit.attempts >= 1
        assert "UPSTREAM-BODY-1163" not in json.dumps(answer)
        assert "upstream-header-1163" not in json.dumps(answer)


def _directory(tmp_path):
    (tmp_path / "audit-is-a-directory").mkdir()
    return tmp_path / "audit-is-a-directory"


def _full_device(tmp_path):
    # A link to /dev/full: opens for append and every write fails (ENOSPC), even as root. The
    # link keeps a sink that rewrites its file (temp + replace) off the real device.
    (tmp_path / "audit.log").symlink_to("/dev/full")
    return tmp_path / "audit.log"


@pytest.mark.parametrize("unwritable", [_directory, _full_device],
                         ids=["cannot open", "opens but cannot write"])
def test_a2_the_real_file_sink_that_cannot_write_fails_the_request_closed(
        tmp_path, data_root, unwritable):
    """The shipped `FileAuditSink` that cannot write fails loudly (at construction or on
    `record`); an app built on it answers `TransportFault` without the upstream body. A13, O9,
    r7 A18."""
    path = unwritable(tmp_path)
    try:
        sink = proxy().FileAuditSink(path)
    except (OSError, ConfigFault):
        return  # refused at construction: the proxy cannot start on it, which is closed too
    try:
        sink.record({"tenant": "t", "outcome": "sent 200"})
    except (OSError, ConfigFault):
        pass
    else:
        pytest.fail("the file sink swallowed a failed audit write (fails open)")
    with T.rig(tmp_path / "forge", data_root, audit=sink) as r:
        r.up.replies[f"{BASE}/users/x"] = (200, {"X-Up": "upstream-header-1163"},
                                           b"UPSTREAM-BODY-1163")
        answer = r.ask()

    assert answer["fault"] == "TransportFault"
    assert "UPSTREAM-BODY-1163" not in json.dumps(answer)
    assert "upstream-header-1163" not in json.dumps(answer)


# --- #1412 O4: the rule holds when the reply streams ------------------------------------------

CAP = 1024


@pytest.mark.parametrize(("ending", "outcome"), [
    pytest.param("complete", "sent 200", id="complete"),
    pytest.param("over-limit-declared", "sent 200", id="over-limit-declared"),
    pytest.param("over-limit-undeclared", "sent 200", id="over-limit-undeclared"),
    pytest.param("upstream-broke", "sent 200", id="upstream-broke"),
    pytest.param("refused", "ConfigFault", id="refused"),
])
def test_o4_exactly_one_record_whatever_ended_the_exchange(tmp_path, data_root, ending, outcome):
    """One audit record per request, naming how it ended, for a complete, over-limit, broken or
    refused exchange. #1412 O4."""
    from defender.tests.integrations.credential_proxy_1163.test_proxy_faults_proxy_side import _chunked_upstream

    def upstream_of(default: str) -> str:
        return {"over-limit-undeclared": chunked, "upstream-broke": broken}.get(ending, default)

    with H.breaks_after_status(200) as broken, _chunked_upstream([b"a" * CAP, b"a"]) as chunked, \
            T.rig(tmp_path / "forge", data_root, lambda u: H.declaration(upstream_of(u) + BASE),
                  max_response_bytes=CAP) as r:
        size = CAP + 1 if ending == "over-limit-declared" else CAP
        r.up.replies[f"{BASE}/users/x"] = (200, W.JSON, b"a" * size)
        r.ask(url=f"{upstream_of(r.up.url)}{BASE}/users/x", **({"grant": set()} if ending == "refused" else {}))

    assert [record["outcome"] for record in r.audit.records] == [outcome]


def test_o4_a_departed_reader_still_leaves_exactly_one_record(tmp_path, data_root):
    """A reader that leaves mid-body: the exchange runs on and writes its one record. #1412 O4."""
    audit = H.AuditRecorder()
    with T.rig(tmp_path / "forge", data_root) as r, A.proxy_for(r.t, r.store, audit=audit) as (url, _tap):
        r.up.replies[f"{BASE}/big"] = (200, W.JSON, b"x" * W.DEFAULT_LIMIT)
        with W.unread(url, r.tok(), W.doc(f"{r.up.url}{BASE}/big")) as response:
            next(response.iter_raw(64 * 1024))
        assert W.until(lambda: audit.records, 10), "no record after the reader left"
        time.sleep(0.3)

    assert [record["outcome"] for record in audit.records] == ["sent 200"]


class _HeldAudit(H.AuditRecorder):
    """An audit port that holds each `record` until released, so a reader can look at what has
    arrived while the record is being written."""

    def __init__(self) -> None:
        super().__init__()
        self.entered, self.release = threading.Event(), threading.Event()

    def record(self, entry: Any) -> None:
        self.entered.set()
        self.release.wait(10)
        super().record(entry)


def test_o4_the_body_arrives_before_the_record_and_the_final_frame_after_it(tmp_path, data_root):
    """While the record is being written the reader holds the body and no final frame; once it is
    written the reply completes; the worker thread is held until then. #1412 O4, P1, P3."""
    audit, arrived = _HeldAudit(), bytearray()
    marker = b"BODY-BEFORE-THE-RECORD"
    with T.rig(tmp_path / "forge", data_root) as r, A.proxy_for(r.t, r.store, audit=audit) as (url, _tap):
        r.up.replies[f"{BASE}/users/x"] = (200, W.JSON, marker)
        tok = r.tok()

        def read() -> None:
            with W.unread(url, tok, W.doc(f"{r.up.url}{BASE}/users/x")) as response:
                for chunk in response.iter_raw():
                    arrived.extend(chunk)

        reader = threading.Thread(target=read)
        reader.start()
        try:
            assert audit.entered.wait(10), "no audit record was started"
            assert W.until(lambda: marker in bytes(arrived), 5), "the body never arrived"
            time.sleep(0.3)  # a negative needs time to happen: a final frame sent early lands now
            before = bytes(arrived)
            lent = W.borrowed(url)
        finally:
            audit.release.set()
            reader.join(20)

    assert lent == 1, "the worker thread was not held until the record was written"
    assert marker in before, "the body had not been forwarded when the record was written"
    with pytest.raises(ValueError):  # noqa: PT011 — the one error type the design names
        W.fmt().decode_reply(before)
    assert W.decoded(bytes(arrived))[1]["status"] == 200


def test_o4_an_audit_failure_withholds_what_was_already_forwarded(tmp_path, data_root):
    """Audit down after 1 MiB was forwarded: the run gets the withheld refusal, no status, no
    body, though the wire shows the bytes did travel. #1412 O4."""
    body = b"x" * W.MIB
    with T.rig(tmp_path / "forge", data_root) as r, A.proxy_for(
            r.t, r.store, audit=H.FailingAudit()) as (url, _tap):
        r.up.replies[f"{BASE}/users/x"] = (200, W.JSON, body)
        target = f"{r.up.url}{BASE}/users/x"
        answer = W.call(url, r.tok(), target)
        forwarded, final = W.decoded(W.raw_post(url, r.tok(), W.doc(target)).content)

    assert (answer.status, answer.body, answer.fault) == (0, "", "TransportFault")
    assert "withheld" in answer.detail
    assert answer.from_system is False
    assert (final["status"], final["body_whole"]) == (None, False)
    assert forwarded == body
