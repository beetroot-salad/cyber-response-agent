"""Forked runs continue the source clock and elapsed budget."""
from __future__ import annotations

import contextlib
import json
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from defender._io import read_jsonl_rows
from defender.learning.branch.estate.oracle import BASE_HANDLE
from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
from defender.tests.integrations.credential_proxy_1163 import _harness as H
from defender.tests.integrations.credential_proxy_1163 import _stream1412 as W
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.support.runtime.state import _1255_clock as C
from defender.tests.support.learning.branch import _triplet_947 as T

pytestmark = pytest.mark.e2e

START = C.SOURCE_START
L1, L2, L3 = C.LESSONS
R = C.BRANCH_READING


@pytest.fixture(autouse=True)
def _roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Isolate configured roots and enable the real unboxed executor."""
    T.isolate_learning_state(tmp_path, monkeypatch)
    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")


def launch_arm(tmp_path: Path, tenant_id: str, source: Path, *steps: C.Step,  # noqa: PLR0913 — the arm's seams, one keyword each
               clock: C.FakeClock, limits: dict | None = None, gather: Any = None,
               oracle: Any = None, verifier: Any = None,
               seams: dict | None = None) -> tuple[C.Launched, C.Clocked]:
    """Launch a recorded source at its L2 read, with scripted clocked main and gather models."""
    branch = C.branch_response(source, tool="read_file", arg_suffix=f"/{L2}.md")
    ep = C.control_episode(tmp_path, source, branch)
    main = C.Clocked(clock, steps)
    out = C.run_main(C.arm_argv(tenant_id, ep.name, "a"), clock=clock, main=main, gather=gather,
                     limits=limits, oracle=oracle, verifier=verifier, seams=seams)
    return out, main


def _launched(out: C.Launched) -> None:
    """The arm ran its investigation (it was not refused at launch or at store setup)."""
    assert out.exit == 0, f"the arm did not run: exit={out.exit} refusal={out.refusal} summary={out.summary}"
    assert out.summary is not None, f"the arm did not run: exit={out.exit} refusal={out.refusal} summary={out.summary}"
    assert out.summary.get("truncated_by") != "store", (
        f"the arm ended at store setup: {out.summary}")


def test_a1_an_arms_visible_times_start_at_the_sources_reading_at_the_branch_point(tmp_path):
    tenant_id, source = C.record_source(tmp_path)
    arm_clock = C.FakeClock(C.ARM_START)
    out, main = launch_arm(tmp_path, tenant_id, source,
                           (20, C.read_lesson(L3)), (5, C.DONE), clock=arm_clock)

    _launched(out)
    arm_dir = out.run_dir
    assert C.lesson_reads(arm_dir, L1) == [C.FIRST_READ_READING], (
        "the arm's lessons log does not hold the source's pre-cut L1 read at its own time "
        f"({C.FIRST_READ_READING}): {C.lesson_rows(arm_dir)}")
    assert C.lesson_reads(arm_dir, L2) == [R], (
        "the arm's lessons log does not hold exactly one L2 read, the re-run dangling call "
        f"stamped with the source's reading at the branch point ({R}): {C.lesson_rows(arm_dir)}")
    assert C.lesson_reads(arm_dir, L3) == [C.at(R, 20)], (
        "the arm's next visible time is not the branch point's reading plus the arm's own 20 s "
        f"({C.at(R, 20)}): {C.lesson_rows(arm_dir)}")
    stamps = [C.instant(r.get("ts")) for r in C.lesson_rows(arm_dir)]
    assert all(s is not None for s in stamps), f"a row carries no readable time: {stamps}"
    assert stamps == sorted(stamps), (
        f"a visible time in the arm runs earlier than one its history already holds: {stamps}")
    assert all(s < C.ARM_START for s in stamps), (
        f"the arm shows its own clock source's absolute time: {stamps}")


@pytest.mark.parametrize(("arm_seconds", "arm_timeout", "refused"),
                         [(300, 900, True), (200, 900, False), (300, 3600, True)],
                         ids=["past-the-sources-limit", "inside-the-sources-limit",
                              "configured-longer-still-the-sources-limit"])
def test_a2_an_arm_reaches_the_wall_clock_limit_where_its_source_would_have(
        tmp_path, monkeypatch, arm_seconds, arm_timeout, refused):
    monkeypatch.setenv(C.FLAG, "true")
    limits = C.caps(wall_clock_timeout=900, grace_seconds=600, max_tool_calls=50)
    arm_limits = C.caps(wall_clock_timeout=arm_timeout, grace_seconds=600, max_tool_calls=50)
    tenant_id, source = C.record_source(tmp_path, limits=limits)
    out, main = launch_arm(tmp_path, tenant_id, source,
                           (arm_seconds, C.bash("echo arm-call-ran")), (0, C.DONE),
                           clock=C.FakeClock(C.ARM_START), limits=arm_limits)

    _launched(out)
    assert len(main.seen) >= 2, f"the arm stopped before its bash call was answered: {main.seen}"
    shown = main.seen[1]
    if refused:
        assert C.refusal_stem() in shown, (f"610 s at the fork + {arm_seconds} s in the arm passes a 900 s limit and nothing "
            "was refused — the arm's clock or its budget origin restarted at the fork")
        assert "wall-clock" in shown, (f"610 s at the fork + {arm_seconds} s in the arm passes a 900 s limit and nothing "
            "was refused — the arm's clock or its budget origin restarted at the fork")
        assert "arm-call-ran" not in shown, "the refused call ran anyway"
    else:
        assert C.refusal_stem() not in shown, (
            f"610 s + {arm_seconds} s is inside a 900 s limit and the arm was refused")
        assert "arm-call-ran" in shown, "the call inside the limit did not run"


DENIED = ("ticket", "get-ticket")


def _summary(text: str = "Summary: measured the lead.") -> Any:
    return C.H.Turn(text=text)


def test_a3_an_arms_denial_log_continues_from_the_sources_reading_at_the_branch_point(tmp_path):
    tenant_id, source = C.record_source(tmp_path)
    arm_clock = C.FakeClock(C.ARM_START)
    system, verb = DENIED
    gather = C.script(arm_clock, (10, C.query(system, verb, {"key": "T-1"})), (0, _summary()))
    out, _main = launch_arm(tmp_path, tenant_id, source,
                            (20, C.gather_turn("l-002", system)), (0, C.DONE),
                            clock=arm_clock, gather=gather)

    _launched(out)
    rows = [r for r in C.denial_rows(out.run_dir) if r.get("verb") == verb]
    assert len(rows) == 1, (
        f"one denied call in the arm, one denial row; got {C.denial_rows(out.run_dir)}")
    assert [C.instant(r.get("ts")) for r in rows] == [C.at(R, 30)], (
        "the arm's denial row is not stamped with the branch point's reading plus the arm's own "
        f"30 s ({C.at(R, 30)}): {rows}")


#: What the host-state service answers the arm's new `proc-tree` question with, and what the
#: adapter makes of it (#1391 O5's shape).
PS_OUTPUT = "PID PPID\n1 0 init\n"


async def _host_state_proxy(scope: Any, receive: Any, send: Any) -> None:
    """A credential proxy stand-in (ASGI): every request is answered with host-state's
    `proc-tree` reply, in the proxy's framed reply format."""
    while (await receive()).get("more_body"):
        pass
    answer = json.dumps({"ps_output": PS_OUTPUT}).encode()
    framed = W.fmt().encode_body(answer) + W.fmt().encode_final(W.final_record())
    await send({"type": "http.response.start", "status": 200,
                "headers": [(b"content-type", W.fmt().REPLY_CONTENT_TYPE.encode())]})
    await send({"type": "http.response.body", "body": framed})


@contextlib.contextmanager
def _proxied_host_state() -> Iterator[tuple[str, A.Tap, A.MarkedSigner]]:
    """The proxy stand-in served on loopback behind a `Tap` (every token it is sent), and the
    run's request-token signer, which records each token it is asked to sign."""
    tap = A.Tap(_host_state_proxy)
    with H.serve_asgi(tap) as url:
        yield url, tap, A.MarkedSigner()


def test_1449_an_arms_new_question_is_read_live_through_the_proxy_and_served_by_the_oracle(
        tmp_path, monkeypatch):
    """A branched run is a run (#1449 W1, W2), over one arm launch: the arm's new host-state
    question (one its source never asked) reaches the proxy with a read token over the run's
    granted systems naming the arm's own run; the answer is served to its lead, stamped by the
    platform with the arm's run clock (#1255 A4); and the oracle is handed the run-clock fork
    time, not a wall-clock source timestamp (#1255 A5)."""
    monkeypatch.setenv(S.KNOB_RATE, "1e6")
    tenant_id, source = C.record_source(tmp_path)
    time.sleep(1.1)
    oracle = S.oracle(then=S.submit(BASE_HANDLE, S.EMPTY_CLAIM))
    arm_clock = C.FakeClock(C.ARM_START)
    gather = C.script(arm_clock, (10, C.query("host-state", "proc-tree", {"host": "web-1"})),
                      (0, _summary("Summary: captured the process tree.")))
    with _proxied_host_state() as (url, tap, signer):
        out, _main = launch_arm(tmp_path, tenant_id, source,
                                (20, C.gather_turn("l-002", "host-state")), (0, C.DONE),
                                clock=arm_clock, gather=gather, oracle=oracle.model,
                                verifier=S.passing_verifier().model,
                                seams={"signer": signer, "proxy_url": url})
    _launched(out)

    # W1: the token the proxy was sent is one the run signed, for the arm's own run, read-only.
    assert tap.tokens, "the arm's new host-state question never reached the proxy"
    signatures = {f"{A.SIGNATURE_CANARY}-{n}": p for n, p in enumerate(signer.payloads, start=1)}
    for sent in tap.tokens:
        payload = signatures.get(sent.rsplit(".", 1)[-1])
        assert payload is not None, f"the proxy was sent a token the run never signed: {sent!r}"
        claims = A.claims_of_payload(payload)
        assert claims["investigation"] == out.run_dir.name != source.name, (
            f"the arm's token does not name the arm's own run {out.run_dir.name}: {claims}")
        assert all(mode == "r" for _s, mode in A.grant_of(claims)), (
            f"the arm's token is not a read grant: {A.grant_of(claims)}")
        assert ("host-state", "r") in A.grant_of(claims), (
            f"the arm's read token does not grant the system the source never asked: {claims}")

    # A4: served to its lead, stamped by the platform with the arm's run clock.
    rows = [r for r in read_jsonl_rows(out.run_dir / "executed_queries.jsonl")
            if r.get("lead_id") == "l-002" and r.get("verb") == "proc-tree"]
    assert len(rows) == 1, f"the arm's host-state question was not served to its lead: {rows}"
    assert rows[0].get("exit_code") == 0, f"the arm's host-state question was not served to its lead: {rows}"
    assert rows[0].get("payload_path"), f"the arm's host-state question was not served to its lead: {rows}"
    assert oracle.submissions() == 1, (
        f"the control world's new question took {oracle.submissions()} oracle turns, not one")
    payload = json.loads((out.run_dir / rows[0]["payload_path"]).read_text(encoding="utf-8"))
    assert payload.get("ps_output") == PS_OUTPUT, f"the arm was not served the system's answer: {payload}"
    assert "captured_at" not in payload, f"the adapter stamped a time of its own: {payload}"
    assert C.instant(rows[0].get("received_at")) == C.at(R, 30), (
        "the arm's host-state reply is not stamped by the platform with its run clock's reading "
        f"at the call ({C.at(R, 30)}): {rows[0].get('received_at')!r}")

    # A5: the oracle is handed the run-clock fork time, never the source's wall-clock stamps.
    shown = oracle.all_seen()
    assert C.mentions(shown, R), (
        f"the oracle was not handed the snapshot's run-clock reading {R} as the fork time")
    framework_times = C.source_message_times(source)
    assert framework_times, "the source's messages carry no timestamps; the check below is empty"
    leaked = [t for t in framework_times if C.mentions(shown, t)]
    assert not leaked, (
        "the oracle was handed a fork time taken from the source's message timestamps (the "
        f"wall clock) rather than the run clock: {leaked}")
