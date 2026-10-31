"""#1163 O9 at the proxy: one audit record per proxied request, refusals included, and never
a secret value."""
from __future__ import annotations

import json

import pytest

from defender.kit.faults import ConfigFault
from defender.tests.integrations.credential_proxy_1163 import _harness as H
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
    """When the audit record cannot be written the answer is `ConfigFault` and the upstream's
    body is not returned; with a working sink the body is. A13, O9."""
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
        assert answer["fault"] == "ConfigFault"
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
    `record`); an app built on it answers `ConfigFault` without the upstream body. A13, O9."""
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

    assert answer["fault"] == "ConfigFault"
    assert "UPSTREAM-BODY-1163" not in json.dumps(answer)
    assert "upstream-header-1163" not in json.dumps(answer)
