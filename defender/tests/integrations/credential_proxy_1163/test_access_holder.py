"""#1363 O1/O5/D8/B1: the process's access holder, reached as a run reaches it (`run._TokenMint.for_run`, which
takes the holder's own `clock=` as an added keyword; pre-flight takes the same clock through the launcher's
`clock=`). It signs a read token when first asked, reuses it while more than 60 s of its 600 s remain, signs once
for concurrent first requests, latches its own failed sign (cause sign), and latches an `access` fault the client
reports to it (`access.report(fault)`). Signing is a seam (`signer=`); no OpenBao, no database."""
from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from defender.kit.faults import AdapterFault, TransportFault
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import test_run_start_tokens as R

TOKEN_SEC, REUSE_MARGIN_SEC = 600, 60
#: How close the signed expiry is held to the holder's clock plus a token's life (seconds).
EXP_SLACK = 1


class Clock:
    """The holder's clock (seconds since the epoch), moved only by the test."""

    def __init__(self) -> None:
        self.now = time.time()

    def __call__(self) -> float:
        return self.now


class SwitchSigner(A.MarkedSigner):
    """A signer that raises `error` (when set) instead of signing, and counts the asks."""

    def __init__(self) -> None:
        super().__init__()
        self.error: BaseException | None = None
        self.asked = 0

    def sign(self, payload: bytes) -> str:
        self.asked += 1
        if self.error is not None:
            raise self.error
        return super().sign(payload)


class GatedSigner(SwitchSigner):
    """A signer that holds every sign at `release` and says when one has begun, so callers can pile up behind it."""

    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()

    def sign(self, payload: bytes) -> str:
        self.entered.set()
        assert self.release.wait(10), "the test never released the sign"
        return super().sign(payload)


@pytest.fixture
def clock() -> Clock:
    return Clock()


def _access(tmp_path, data_root, signer: A.MarkedSigner, clock: Clock) -> Any:
    """The read access of a run's mint (`identity` and `ticket` on `http-proxy`), the holder's clock the test's."""
    R._plant(data_root, proxy=("identity", "ticket"))
    return R._mint_for(tmp_path, data_root, signer, world=None, clock=clock).access_kwargs()["access"]


def _exp(signer: A.MarkedSigner, n: int) -> float:
    return A.claims_of_payload(signer.payloads[n])["exp"]


def _lost(detail: str) -> TransportFault:
    """A fault the client would report: before any answer, so `access`."""
    fault = TransportFault(detail)
    fault.origin = "access"
    return fault


def test_h1_a_token_is_signed_when_first_asked_for_the_600_s_the_clock_gives_it(tmp_path, data_root, clock):
    """Building the holder signs nothing; the first ask signs one read token expiring 600 s after the holder's
    clock, over the run's reads only. #1363 O1"""
    signer = A.MarkedSigner()
    access = _access(tmp_path, data_root, signer, clock)
    assert signer.payloads == [], "building the holder signed"
    token = access.token()
    assert A.SIGNATURE_CANARY in token
    (payload,) = signer.payloads
    claims = A.claims_of_payload(payload)
    assert abs(claims["exp"] - (clock.now + TOKEN_SEC)) <= EXP_SLACK, claims["exp"] - clock.now
    assert A.grant_of(claims) == [("identity", "r"), ("ticket", "r")]


@pytest.mark.parametrize("elapsed", [0, 1, TOKEN_SEC - REUSE_MARGIN_SEC - 0.5], ids=["at once", "1 s", "just over 60 s left"])
def test_h2_a_token_with_more_than_the_margin_left_is_reused(tmp_path, data_root, clock, elapsed):
    """With more than 60 s of life left the held token is handed out again and nothing is signed. Control: h3.
    #1363 O1"""
    signer = A.MarkedSigner()
    access = _access(tmp_path, data_root, signer, clock)
    first = access.token()
    clock.now += elapsed
    assert access.token() == first
    assert len(signer.payloads) == 1


@pytest.mark.parametrize("elapsed", [TOKEN_SEC - REUSE_MARGIN_SEC, TOKEN_SEC - REUSE_MARGIN_SEC + 1, TOKEN_SEC, 5 * TOKEN_SEC],
                         ids=["exactly 60 s left", "59 s left", "none left", "long expired"])
def test_h3_a_token_with_the_margin_or_less_left_is_replaced_by_one_signed_from_the_clock(
        tmp_path, data_root, clock, elapsed):
    """At 60 s of life left (not more) and below, the next ask signs a fresh token expiring 600 s after the clock
    then, and the one after reuses it. Control: h2. #1363 O1"""
    signer = A.MarkedSigner()
    access = _access(tmp_path, data_root, signer, clock)
    first = access.token()
    clock.now += elapsed
    second = access.token()
    assert second != first
    assert len(signer.payloads) == 2
    assert abs(_exp(signer, 1) - (clock.now + TOKEN_SEC)) <= EXP_SLACK
    assert access.token() == second, "the fresh token was not reused"
    assert len(signer.payloads) == 2


def test_h4_concurrent_first_requests_make_one_sign_and_share_its_token(tmp_path, data_root, clock):
    """Callers arriving while the first sign is in progress wait for it: one sign, one token for all. #1363 O1, D7"""
    signer = GatedSigner()
    access = _access(tmp_path, data_root, signer, clock)
    got: list[str] = []
    threads = [threading.Thread(target=lambda: got.append(access.token())) for _ in range(4)]
    for thread in threads:
        thread.start()
    assert signer.entered.wait(10), "no sign began"
    time.sleep(0.2)  # the other callers reach the holder while the first sign is held
    signer.release.set()
    for thread in threads:
        thread.join(10)
    assert len(got) == 4, "a caller did not get a token"
    assert len(set(got)) == 1
    assert len(signer.payloads) == 1, "concurrent first requests signed more than once"


def test_h5_a_failed_sign_is_latched_at_once_for_every_later_ask(tmp_path, data_root, clock):
    """A sign that fails raises its fault to the asker; every later ask raises a fresh fault with the same detail
    and asks the signer nothing, though it would now succeed and the clock has moved past any token's life.
    Control: h1. #1363 D8, O5"""
    signer = SwitchSigner()
    signer.error = TransportFault("OpenBao is sealed")
    access = _access(tmp_path, data_root, signer, clock)
    with pytest.raises(TransportFault) as failed:
        access.token()
    assert signer.asked == 1
    signer.error = None
    clock.now += 5 * TOKEN_SEC
    for _ in range(2):
        with pytest.raises(AdapterFault) as again:
            access.token()
        assert again.value is not failed.value
        assert again.value.detail == failed.value.detail
    assert (signer.asked, signer.payloads) == (1, []), "the signer was asked again after it failed"


def test_h6_a_re_sign_that_fails_latches_and_the_held_token_is_not_handed_out_again(tmp_path, data_root, clock):
    """The first token signed; at the margin the re-sign fails: the asker gets the fault, and a later ask raises the
    same detail rather than the expiring token or a new sign. #1363 D8, O5"""
    signer = SwitchSigner()
    access = _access(tmp_path, data_root, signer, clock)
    access.token()
    clock.now += TOKEN_SEC - REUSE_MARGIN_SEC
    signer.error = TransportFault("OpenBao is sealed")
    with pytest.raises(TransportFault) as failed:
        access.token()
    signer.error = None
    clock.now -= 10  # even with the old token valid again
    with pytest.raises(AdapterFault) as again:
        access.token()
    assert again.value.detail == failed.value.detail
    assert (signer.asked, len(signer.payloads)) == (2, 1)


def test_h7_concurrent_requests_behind_a_failing_sign_share_its_failure_without_signing_again(
        tmp_path, data_root, clock):
    """Callers waiting on the lock while the first sign fails each get the failure; the signer is asked once.
    #1363 D8, O1"""
    signer = GatedSigner()
    signer.error = TransportFault("OpenBao is sealed")
    access = _access(tmp_path, data_root, signer, clock)
    raised: list[AdapterFault] = []

    def ask() -> None:
        try:
            access.token()
        except AdapterFault as fault:
            raised.append(fault)

    threads = [threading.Thread(target=ask) for _ in range(3)]
    for thread in threads:
        thread.start()
    assert signer.entered.wait(10)
    time.sleep(0.2)
    signer.release.set()
    for thread in threads:
        thread.join(10)
    assert len(raised) == 3, "a caller got a token or hung"
    assert len({fault.detail for fault in raised}) == 1, "the waiting callers were told different causes"
    assert signer.asked == 1, "a waiting caller signed after the first sign failed"


def test_h8_an_access_fault_the_client_reports_loses_access_and_nothing_signs_afterwards(
        tmp_path, data_root, clock):
    """The client reports a fault of origin `access`: from then on every ask raises a fresh fault with that
    fault's detail (the first one reported), even with a live token held and the clock moved, and nothing is
    signed. Control: h2 (without the report the held token is handed out). #1363 O5, B1"""
    signer = A.MarkedSigner()
    access = _access(tmp_path, data_root, signer, clock)
    assert access.token(), "positive control: the holder signs before access is lost"
    access.report(_lost("the credential proxy answered nothing"))
    access.report(_lost("a second, later fault"))
    for moved in (0, 5 * TOKEN_SEC):
        clock.now += moved
        with pytest.raises(AdapterFault) as lost:
            access.token()
        assert lost.value.detail == "the credential proxy answered nothing"
    assert len(signer.payloads) == 1, "a token was signed after access was lost"


@pytest.mark.parametrize("origin", ["system", "request", None])
def test_h9_a_fault_that_is_not_process_wide_access_does_not_lose_it(tmp_path, data_root, clock, origin):
    """A reported fault of origin `system` or `request`, or with no origin (a missing origin is not read as
    `access`), leaves the holder serving: the held token is reused and, expired, replaced. Control: h8. #1363 O5, O4"""
    signer = A.MarkedSigner()
    access = _access(tmp_path, data_root, signer, clock)
    first = access.token()
    fault = TransportFault("an answer or a request of one call")
    if origin is not None:
        fault.origin = origin
    access.report(fault)
    assert access.token() == first
    clock.now += TOKEN_SEC
    assert access.token() != first
    assert len(signer.payloads) == 2


def test_h10_the_holder_shows_no_token_in_any_repr(tmp_path, data_root, clock):
    """After a token is signed, neither the access nor anything it holds shows the token in its repr or str. O10"""
    signer = A.MarkedSigner()
    access = _access(tmp_path, data_root, signer, clock)
    token = access.token()
    assert A.SIGNATURE_CANARY in token, "positive control: a token was signed"
    shown = [repr(access), str(access), *(repr(v) for v in vars(access).values())]
    assert "proxy.invalid" in " ".join(shown), "positive control: the address shows"
    for text in shown:
        assert A.SIGNATURE_CANARY not in text, "the request token shows in a repr (O10)"
