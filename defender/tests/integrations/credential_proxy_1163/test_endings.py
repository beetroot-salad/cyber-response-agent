"""#1412 O4 and O8 over every way an exchange can end: one audit record per request (its outcome
`sent 200` when the status went out, else the fault; its `fault` that of the final frame),
written before the final frame, failing closed; the system's status standing. The rows are
generated from `E.ENDINGS`, not picked."""
from __future__ import annotations

import pytest

from defender.kit.transport import host_write
from defender.kit.faults import TransportFault, UpstreamFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _endings1412r as E
from defender.tests.integrations.credential_proxy_1163 import _stream1412 as W
from defender.tests.integrations.credential_proxy_1163 import _tenant as T


def _rows(endings, *axes):
    """`endings` crossed with each of `axes` (lists of values), ids `ending-axis-axis`."""
    import itertools

    return [pytest.param(e, *combo, id="-".join([e.name, *map(str, combo)]))
            for e in endings for combo in itertools.product(*axes)]


@pytest.mark.parametrize(("ending", "mode"), _rows(E.ENDINGS, ["written", "held", "failing"]))
def test_o4_every_ending_is_one_record_before_the_final_frame_and_a_failed_one_withholds(
        tmp_path, data_root, ending, mode):
    """Whatever ended the exchange, one record per request, its fault agreeing with the final frame's; it
    is written before the final frame; a record that cannot be written withholds the answer. #1412 O4."""
    audit = E.audit_of(mode)
    with E.served(tmp_path, data_root, ending, audit=audit) as ex:
        got = E.run(ex, ending, hold=mode == "held")

    if mode == "failing":
        assert audit.attempts >= 1, audit.attempts
    else:
        assert len(audit.records) == 1, audit.records
    if ending.reader_leaves:
        if mode != "failing":
            assert [r["outcome"] for r in audit.records] == ["sent 200"]
        return
    forwarded, final = W.decoded(got.raw)
    if mode == "failing":
        assert (final["status"], final["body_whole"]) == (None, False), final
        assert "withheld" in final["detail"], final
        assert final["sent"] is (ending.how is None), "a withheld answer still says whether the call began (#1374)"
        return
    (record,) = audit.records
    assert record["outcome"] == ("sent 200" if ending.status_arrives else final["fault"]), record
    assert record["fault"] == final["fault"], (record, final)
    assert final["sent"] is (ending.how is None), "sent: true iff the proxy began the system's call (#1374)"
    if mode == "held":
        with pytest.raises(ValueError):  # noqa: PT011 — the one error type the design names
            W.fmt().decode_reply(got.before)


@pytest.mark.parametrize(("ending", "status"), _rows(E.STATUSED, [200, 401, 503]))
def test_o8_the_system_status_stands_whatever_became_of_its_reply(tmp_path, data_root, ending, status):
    """The run is told the status the system answered, on every ending where it answered, however
    its body fared. #1412 O8."""
    with E.served(tmp_path, data_root, ending, status=status) as ex:
        answer = W.call(ex.url, ex.tok, ex.target, timeout_sec=ending.timeout)

    assert answer.status == status, answer


@pytest.mark.parametrize(("ending", "method", "status"), [
    pytest.param(e, m, s, id=f"{e.name}-{m}") for e in E.STATUSED for m, s in (("POST", 201), ("PUT", 200))])
def test_o8_a_write_the_system_took_is_accepted_whatever_became_of_its_reply(
        tmp_path, data_root, ending, method, status):
    """A 2xx write is judged by its status alone on every ending where the status arrived, so a
    reply that broke or was withheld never makes an accepted write look refused. #1412 O8, #1359."""
    with E.served(tmp_path, data_root, ending, status=status, writes=(("POST", "/tickets"), ("PUT", "/tickets")),
                  grant="rw") as ex:
        ctx = A.ctx_for(tmp_path, T.run_record(ex.rig.t), ex.url, ex.tok)
        host_write(ctx, "identity", method, "/tickets", body={"body": "x"},  # raises if refused
              timeout_sec=ending.timeout)


@pytest.mark.parametrize(("status", "fault"), [(404, UpstreamFault), (500, TransportFault)])
def test_o8_the_write_judgement_still_refuses_a_non_2xx_status_on_a_complete_reply(
        tmp_path, data_root, status, fault):
    """Control for the test above: the same rig on the `complete` ending raises when the system's
    status is a refusal, so "did not raise" there is a real result. #1412 O8, #1359."""
    ending = E.ENDINGS[0]
    assert ending.name == "complete"
    with E.served(tmp_path, data_root, ending, status=status, writes=(("POST", "/tickets"),),
                  grant="rw") as ex:
        ctx = A.ctx_for(tmp_path, T.run_record(ex.rig.t), ex.url, ex.tok)
        with pytest.raises(fault):
            host_write(ctx, "identity", "POST", "/tickets", body={"body": "x"}, timeout_sec=ending.timeout)


@pytest.mark.parametrize("ending", E.STATUSED, ids=lambda e: e.name)
def test_o8_a_401_on_an_oauth_system_evicts_the_cached_token_whatever_became_of_its_reply(
        tmp_path, data_root, ending):
    """A 401 evicts the cached access token however its body ended, so the next request exchanges
    afresh. #1412 O8."""
    issued: list[str] = []
    with E.served(tmp_path, data_root, ending, status=401, oauth=issued, then_clean=True) as ex:
        first = W.call(ex.url, ex.tok, ex.target, timeout_sec=ending.timeout)
        second = W.call(ex.url, ex.tok, ex.target, timeout_sec=ending.timeout)

    assert first.status == 401, first
    assert second.fault is None, second
    assert len(ex.exchanged) == 2, "the token was not exchanged afresh after the 401"
