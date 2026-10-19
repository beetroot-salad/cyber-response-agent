"""World serving preserves recorded bytes and reconstructs live answers at the fork."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.support.runtime.state import _1255_world as W
from defender.tests.learning.judge.contrast_contracts import _spec1234 as S34  # noqa: E402
from defender.tests.learning.oracle.live_contracts import _spec1224 as S24  # noqa: E402

pytestmark = pytest.mark.e2e

ALICE = S24.query_params("user:alice")
BOB = S24.query_params("user:bob")
CAROL = S24.query_params("user:carol")

ALICE_ANSWER = {"rows": [{"user": "alice", "host": "web-1", "event_id": "e-100",
                          "action": "logon"}], "total": 1}
BOB_ANSWER = {"total": 1, "rows": [{"user": "bob", "host": "db-1", "event_id": "e-200",
                                    "action": "logon"}]}

#: A verb every fixture system declares and the fixture grant withholds from gather.
WITHHELD = ("edr", "lookup")

BOB_LIVE = {"total": 1, "rows": [{"user": "bob", "host": "db-live-1255", "event_id": "e-200",
                                  "action": "logon"}]}
BOB_AT_FORK = {"total": 1, "rows": [{"user": "bob", "host": "db-fork-1255", "event_id": "e-200",
                                     "action": "logon"}]}
BOB_CHANGE = S24.claim(changed=[S24.changed("bob", "host", "db-live-1255", "db-fork-1255")])

CASE = {"entity": "CASE-1255"}
ANALYST_NOTE = {"comment_id": "c-1", "author": "soc-analyst", "body": "escalated for triage"}
CLOSING_MARKER = "CLOSING-NOTE-1255: verdict malicious, account disabled"
TICKET_AT_FORK = {"ticket": "CASE-1255", "status": "open", "comments": [ANALYST_NOTE]}
#: The side query a removal of the closing comment is claimed with: it selects that comment.
CLOSING_SIDE = S24.query_params("comment_id:c-2")

_LEDGER = "learning.branch.ledger"

_PRE_1255_DECISIONS = frozenset({"base", "passthrough", "refused", "fault", "captured", "oracle",
                                 "real-error", "staged", "patched"})


@pytest.fixture(autouse=True)
def _roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return W.configure_roots(tmp_path, monkeypatch)


def _resorted(payload: Any) -> Any:
    """Return equal JSON with sorted keys to detect unintended reserialization."""
    return json.loads(json.dumps(payload, sort_keys=True))


def _routed_passing(*answers: tuple[dict, Any]) -> Any:
    """Route oracle calls to equal answers with sorted keys."""
    return S34.Routed({params["q"]: S24.oracle(then=S24.submit(_resorted(answer),
                                                                S24.EMPTY_CLAIM))
                       for params, answer in answers}, name="oracle-1255", last_wins=True)


def _closing_comment() -> dict:
    """Build the source agent’s tagged closing comment."""
    from defender.runtime import case_ticket
    return {"comment_id": "c-2", "author": "defender",
            "body": f"{case_ticket.agent_comment_tag(S24.SOURCE_RUN_ID)}\n{CLOSING_MARKER}"}


def _closing_tag() -> str:
    from defender.runtime import case_ticket
    return case_ticket.agent_comment_tag(S24.SOURCE_RUN_ID)


def _ticket_after_close(est: Any) -> dict:
    """Seed the live ticket and a query selecting its closing comment."""
    comment = _closing_comment()
    est.answer("siem-x", "lookup", CASE, {"ticket": "CASE-1255", "status": "open",
                                          "comments": [ANALYST_NOTE, comment]})
    est.answer("siem-x", "query", CLOSING_SIDE, {"rows": [comment]})
    return comment


def _removing_closing_comment() -> Any:
    """Serve the ticket with the post-fork closing comment removed."""
    return S24.oracle(then=S24.submit(TICKET_AT_FORK, S24.claim(removed=[S24.removed(
        _closing_comment(), system="siem-x", verb="query", params=CLOSING_SIDE, count=1)])))


def _assert_reconstructed(decision: Any, where: str) -> None:
    """Require a distinct reconstruction decision preserved by ledger normalization."""
    oracle_word = S24.sym(_LEDGER, "ORACLE")
    passthrough = S24.sym(_LEDGER, "PASSTHROUGH")
    assert decision not in (oracle_word, passthrough), (
        f"{where}: the control world's changed answer was recorded {decision!r} (D5: a decision "
        f"of its own, neither {oracle_word!r} nor {passthrough!r})")
    assert decision not in _PRE_1255_DECISIONS, (
        f"{where}: the control world's changed answer was recorded {decision!r}, a decision word "
        f"the ledger already had (D5: a distinct word of its own; the judge reads every existing "
        f"word as something else — {sorted(_PRE_1255_DECISIONS)})")
    assert S24.sym(_LEDGER, "normalized_source")(decision) == decision, (
        f"{where}: {decision!r} is not a decision word of the ledger's own vocabulary")


def _rows_asking(rows: list[dict], params: dict) -> list[dict]:
    want = S24.canonical(params)
    return [r for r in rows if isinstance(r.get("params"), dict)
            and S24.canonical(r["params"]) == want]


def _files_naming(run_dir: Path, needle: str) -> list[str]:
    """Every file under `run_dir` whose bytes carry `needle`."""
    return sorted(str(p.relative_to(run_dir)) for p in Path(run_dir).rglob("*")
                  if p.is_file() and needle.encode("utf-8") in p.read_bytes())




@pytest.mark.parametrize("label", ["a", "b"], ids=["control-world", "world-with-facts"])
def test_1255_a_repeated_new_question_served_from_the_worlds_store_keeps_the_adapters_own_bytes(
        tmp_path: Path, label: str) -> None:
    est = W.ordered_estate(tmp_path)
    est.answer("idp", "query", BOB, BOB_ANSWER)
    turns = [S24.query_turn("idp", "query", BOB), S24.query_turn("idp", "query", BOB),
             S24.done_turn()]
    natural_dir, natural = W.drive_lead(tmp_path / "natural", verbs=S24.plain_registry(est),
                                        est=est, turns=list(turns))
    natural_rows = [r for r in _rows_asking(W.lead_rows(natural_dir), BOB)
                    if r.get("exit_code") == 0]
    assert len(natural_rows) == 2, f"fixture: the natural run asked twice: {natural_rows}"
    natural_bytes = [W.sidecar_bytes(natural_dir, r) for r in natural_rows]
    assert not any(W.is_key_sorted(b.decode("utf-8")) for b in natural_bytes), (
        "fixture: the adapter's answer is already key-sorted, so this test cannot tell")
    expected = [W.normalized(t, natural_dir) for t in natural.handed_back()]
    assert len(expected) == 2, f"fixture: two tool results reached the natural model: {expected}"
    assert expected[0] != expected[1], "fixture: the repeat carries no note to compare"

    ep = S24.episode_v2(tmp_path / "branch", base_rows=[])
    oracle = _routed_passing((BOB, BOB_ANSWER))
    reg = S24.sandboxed_registry(ep, label, est, oracle=oracle, verifier=S24.passing_verifier())
    arm_dir, arm = W.drive_lead(tmp_path / "arm", verbs=reg, est=est, turns=list(turns))
    arm_rows = [r for r in _rows_asking(W.lead_rows(arm_dir), BOB) if r.get("exit_code") == 0]
    assert len(arm_rows) == 2, f"fixture: the arm asked twice: {arm_rows}"

    for i, (arm_row, natural_row) in enumerate(zip(arm_rows, natural_rows, strict=True)):
        assert W.sidecar_bytes(arm_dir, arm_row) == natural_bytes[i], (
            f"ask {i + 1}: the investigator's payload file is not the adapter's bytes")
        assert arm_row["payload_sha256"] == natural_row["payload_sha256"], f"ask {i + 1}"
    handed = [W.normalized(t, arm_dir) for t in arm.handed_back()]
    assert handed == expected, "a tool result the model read differs from a natural run's"
    # One consumed `submit` is one oracle turn, however many model requests the turn cost.
    assert sum(double.submissions() for double in oracle.routes.values()) == 1, (
        "fixture: the repeat was not served from the world's store (it took its own turn)")


@pytest.mark.parametrize("label", ["a", "b"], ids=["control-world", "world-with-facts"])
def test_1255_an_answer_the_source_received_is_served_with_the_sources_own_bytes(
        tmp_path: Path, label: str) -> None:
    est = W.ordered_estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ANSWER)
    turns = [S24.query_turn("idp", "query", ALICE), S24.done_turn()]
    source_dir, _source = W.drive_lead(tmp_path / "source", verbs=S24.plain_registry(est),
                                       est=est, turns=list(turns))
    source_bytes = W.sidecar_bytes(source_dir, W.row_for(W.lead_rows(source_dir), ALICE))
    assert not W.is_key_sorted(source_bytes.decode("utf-8")), (
        "fixture: the source's sidecar is already key-sorted, so this test cannot tell")

    ep = S24.episode_v2(tmp_path / "branch")
    (ep / "served" / "base.jsonl").unlink()  # the episode is primed from the source, once
    episode_cls = S24.sym("episodes._episode_handle", "Episode")
    with episode_cls.open(ep) as handle:
        S24.sym("learning.branch.capture", "prime_base")(source_dir, handle)
    reads_before = len(est.calls("idp", "query"))

    oracle = _routed_passing((ALICE, ALICE_ANSWER))
    reg = S24.sandboxed_registry(ep, label, est, oracle=oracle, verifier=S24.passing_verifier())
    arm_dir, arm = W.drive_lead(tmp_path / "arm", verbs=reg, est=est, turns=list(turns))
    arm_row = W.row_for(W.lead_rows(arm_dir), ALICE)
    assert len(est.calls("idp", "query")) == reads_before, (
        "the recorded call was read live instead of served from the recording")
    if label == "a":
        assert oracle.unrouted == [], (
            "the control world took an oracle turn for an answer the source received")
        assert not _routed_requests(oracle), (
            "the control world took an oracle turn for an answer the source received")

    assert W.sidecar_bytes(arm_dir, arm_row) == source_bytes, (
        "the arm's payload file is not the source's own bytes")
    assert any(source_bytes.decode("utf-8") in W.normalized(t, arm_dir)
               for t in arm.handed_back()), "the model was not handed the source's bytes"


def _routed_requests(routed: Any) -> int:
    return sum(double.requests for double in routed.routes.values())


def test_1255_the_control_world_answers_a_question_the_source_never_asked_through_its_oracle(
        tmp_path: Path) -> None:
    est = S24.estate(tmp_path)
    est.answer("idp", "query", BOB, BOB_ANSWER)
    ep = S24.episode_v2(tmp_path, base_rows=[S24.captured("idp", "query", ALICE, ALICE_ANSWER)])
    fact_oracle = S24.oracle(then=S24.submit(_resorted(BOB_ANSWER), S24.EMPTY_CLAIM))
    fact_world = S24.sandboxed_registry(ep, "b", est, oracle=fact_oracle,
                                        verifier=S24.passing_verifier())
    assert S24.call(fact_world, "idp", "query", est.ctx(tmp_path / "run-b"), **BOB) == BOB_ANSWER
    for needle in ("user:bob", "e-200", W.FORK_TIME):
        assert needle in fact_oracle.all_seen(), f"positive control: {needle!r} not in b's inbound"
    reads_before = len(est.calls("idp", "query"))

    oracle = S24.oracle(then=S24.submit(_resorted(BOB_ANSWER), S24.EMPTY_CLAIM))
    control = S24.sandboxed_registry(ep, "a", est, oracle=oracle,
                                     verifier=S24.passing_verifier())
    ctx = est.ctx(tmp_path / "run")

    assert S24.call(control, "idp", "query", ctx, **ALICE) == ALICE_ANSWER
    assert oracle.requests == 0, "a recorded answer cost the control world an oracle turn"

    served = S24.call(control, "idp", "query", ctx, **BOB)
    live = est.calls("idp", "query")[reads_before:]
    assert [c["as_of"] for c in live] == [S24.AS_OF_DT.isoformat()], (
        "the control's base read was not one live read bounded by the fork time")
    assert oracle.requests >= 1, (
        "the control world served a question the source never asked as a raw live read")
    inbound = oracle.all_seen()
    assert "user:bob" in inbound, "the oracle was not handed the call it served"
    assert "e-200" in inbound, "the oracle was not handed the call's live base"
    assert W.FORK_TIME in inbound, "the oracle was not told the fork time"
    assert served == BOB_ANSWER
    rows = S24.ledger_rows(ep, "a")
    assert len(rows) == 2, "each investigator call is one ledger row"
    assert [r.get("source") for r in _rows_asking(rows, BOB)] == [S24.PASSTHROUGH], (
        "D5: a control-world oracle turn that leaves the base unchanged records `passthrough`")


def test_1255_the_control_world_serves_its_oracles_changed_answer_never_the_base(
        tmp_path: Path) -> None:
    est = W.ordered_estate(tmp_path)
    est.answer("idp", "query", BOB, BOB_LIVE)
    turns = [S24.query_turn("idp", "query", BOB), S24.done_turn()]
    _natural_dir, natural = W.drive_lead(tmp_path / "natural", verbs=S24.plain_registry(est),
                                         est=est, turns=list(turns))
    assert "db-live-1255" in "\n".join(natural.handed_back()), (
        "fixture: the live base does not carry the value the oracle changes")
    reads_before = len(est.calls("idp", "query"))

    ep = S24.episode_v2(tmp_path / "branch", base_rows=[])
    oracle = S24.oracle(then=S24.submit(BOB_AT_FORK, BOB_CHANGE))
    control = S24.sandboxed_registry(ep, "a", est, oracle=oracle,
                                     verifier=S24.passing_verifier())
    arm_dir, arm = W.drive_lead(tmp_path / "arm", verbs=control, est=est, turns=list(turns))
    assert [c["as_of"] for c in est.calls("idp", "query")[reads_before:]] == [
        S24.AS_OF_DT.isoformat()], "fixture: the control's base was not one fork-time live read"
    assert oracle.requests >= 1, "the control world's new question took no oracle turn (D3)"

    handed = "\n".join(arm.handed_back())
    assert "db-fork-1255" in handed, "the model was not handed the oracle's submission"
    assert "db-live-1255" not in handed, "the model was handed the pre-oracle base"
    arm_row = W.row_for(W.lead_rows(arm_dir), BOB)
    assert json.loads(W.sidecar_bytes(arm_dir, arm_row)) == BOB_AT_FORK, (
        "the investigator's payload file is not the oracle's submission")
    served = _rows_asking(S24.ledger_rows(ep, "a"), BOB)
    assert len(served) == 1, f"fixture: one ledger row for the call: {served}"
    _assert_reconstructed(served[0].get("source"), "the changed answer's ledger row")
    assert json.loads(served[0]["payload_text"]) == BOB_AT_FORK, (
        "the ledger recorded a payload other than the one served")


def test_1255_a_control_world_oracle_that_removes_the_sources_closing_comment_hides_it(
        tmp_path: Path) -> None:
    est = W.ordered_estate(tmp_path)
    _ticket_after_close(est)
    tag = _closing_tag()
    turns = [S24.query_turn("siem-x", "lookup", CASE), S24.done_turn()]
    natural_dir, natural = W.drive_lead(tmp_path / "natural", verbs=S24.plain_registry(est),
                                        est=est, turns=list(turns), system="siem-x")
    natural_text = "\n".join(natural.handed_back())
    assert tag in natural_text, "fixture: the live ticket does not carry the source's tag line"
    assert CLOSING_MARKER in natural_text, "fixture: the live ticket carries no closing note"
    assert _files_naming(natural_dir, CLOSING_MARKER), "fixture: the scan cannot find the note"

    ep = S24.episode_v2(tmp_path / "branch", base_rows=[])
    oracle = _removing_closing_comment()
    control = S24.sandboxed_registry(ep, "a", est, oracle=oracle,
                                     verifier=S24.passing_verifier())
    arm_dir, arm = W.drive_lead(tmp_path / "arm", verbs=control, est=est, turns=list(turns),
                                system="siem-x")
    assert oracle.requests >= 1, "the control world's ticket read took no oracle turn (D3)"

    handed = "\n".join(arm.handed_back())
    assert ANALYST_NOTE["body"] in handed, "fixture: the arm was not served the ticket at all"
    assert tag not in handed, "the model was handed the source's closing comment (its tag)"
    assert CLOSING_MARKER not in handed, "the model was handed the source's closing note"
    assert _files_naming(arm_dir, CLOSING_MARKER) == [], (
        "a file in the arm's run folder carries the source's closing note")
    served = _rows_asking(S24.ledger_rows(ep, "a"), CASE)
    assert len(served) == 1, f"fixture: one ledger row for the ticket read: {served}"
    _assert_reconstructed(served[0].get("source"), "the reconstructed ticket's ledger row")


@pytest.mark.parametrize("skip", ["failed", "unreadable"])
@pytest.mark.parametrize("label", ["a", "b"], ids=["control-world", "world-with-facts"])
def test_1255_a_pre_fork_question_with_no_recording_is_reconstructed_at_the_fork_time(
        tmp_path: Path, label: str, skip: str) -> None:
    est = W.ordered_estate(tmp_path)
    est.answer("idp", "query", ALICE, ALICE_ANSWER)
    if skip == "failed":
        est.fail("siem-x", "lookup", CASE, fault="UpstreamFault", detail="ticketing is down")
    else:
        est.answer("siem-x", "lookup", CASE, TICKET_AT_FORK)
    turns = [S24.query_turn("siem-x", "lookup", CASE), S24.query_turn("idp", "query", ALICE),
             S24.done_turn()]
    source_dir, _source = W.drive_lead(tmp_path / "source", verbs=S24.plain_registry(est),
                                       est=est, turns=list(turns))
    source_rows = W.lead_rows(source_dir)
    ticket_rows = _rows_asking(source_rows, CASE)
    assert len(ticket_rows) == 1, f"fixture: the source asked the ticket once: {ticket_rows}"
    if skip == "unreadable":
        assert ticket_rows[0]["exit_code"] == 0, "fixture: the source's ticket read succeeded"
        (source_dir / ticket_rows[0]["payload_path"]).write_bytes(b"\xff\xfe{ not json")
    else:
        assert ticket_rows[0]["exit_code"] != 0, "fixture: the source's ticket read failed"

    ep = S24.episode_v2(tmp_path / "branch")
    (ep / "served" / "base.jsonl").unlink()  # the episode is primed from the source, once
    with S24.sym("episodes._episode_handle", "Episode").open(ep) as handle:
        report = S24.sym("learning.branch.capture", "prime_base")(source_dir, handle)
    assert getattr(report, skip) == 1, f"fixture: the real primer did not skip it as {skip}"
    base = S24.read_jsonl(ep / "served" / "base.jsonl")
    assert not _rows_asking(base, CASE), "fixture: the recording holds the ticket read"
    assert _rows_asking(base, ALICE), "fixture: the recording holds the source's answered call"

    _ticket_after_close(est)  # after the fork the source closed its case
    key = S24.sym(_LEDGER, "request_key")
    prebranch = frozenset(key(r["system"], r["verb"], r["params"]) for r in source_rows)
    reads_before = len(est.calls("siem-x", "lookup"))
    oracle = _removing_closing_comment()
    world = S24.sandboxed_registry(ep, label, est, oracle=oracle,
                                   verifier=S24.passing_verifier(), prebranch=prebranch)
    try:
        served = S24.call(world, "siem-x", "lookup", est.ctx(tmp_path / "run"), **CASE)
    except S24.unservable_cls() as unservable:
        pytest.fail(f"world {label} refused the oracle's fork-time answer to a pre-fork call "
                    f"with no recording ({getattr(unservable, 'reason', None)!r}): D6 binds "
                    "only recorded answers unchanged")

    live = est.calls("siem-x", "lookup")[reads_before:]
    assert [c["as_of"] for c in live] == [S24.AS_OF_DT.isoformat()], (
        "the base was not one live read bounded by the fork time")
    assert oracle.requests >= 1, (
        f"world {label} served a pre-fork question with no recording as a raw live read")
    inbound = oracle.all_seen()
    assert "CASE-1255" in inbound, "the oracle was not handed the call it served"
    assert W.FORK_TIME in inbound, "the oracle was not told the fork time"
    assert served == TICKET_AT_FORK, (
        f"world {label} served {served}, not its oracle's fork-time answer")
    if label == "a":
        _assert_reconstructed(_rows_asking(S24.ledger_rows(ep, "a"), CASE)[0].get("source"),
                              "the control world's reconstructed pre-fork answer")


def test_1255_the_judge_reads_a_control_worlds_reconstructed_answer_as_baseline(
        tmp_path: Path) -> None:
    carol_live = {"rows": [{"user": "carol", "event_id": "e-300", "action": "logon",
                            "host": "web-live-1255", "ts": "2026-07-28T15:40:00Z"}]}
    carol_at_fork = {"rows": [{"user": "carol", "event_id": "e-300", "action": "logon",
                               "host": "web-fork-1255", "ts": "2026-07-28T15:40:00Z"}]}
    est = S34.Estate1234(tmp_path / "estate", withheld=(WITHHELD,))
    est.answer("idp", "query", CAROL, carol_live)
    control_oracle = S34.Routed(
        {CAROL["q"]: S24.oracle(then=S24.submit(carol_at_fork, S24.claim(changed=[
            S24.changed("carol", "host", "web-live-1255", "web-fork-1255")])))},
        default=S34.passing_oracle(), name="oracle-a", last_wins=True)
    built = S34.real_family(tmp_path, {"a": S34.RealWorld(
        "a", disposition="benign", oracle=control_oracle,
        turns=[S24.query_turn("idp", "query", CAROL), S24.done_turn()])}, estate=est)
    assert built.rc == 0, f"fixture: the launch failed ({built.rc}, {built.message!r})"

    carol = _rows_asking(built.ledger_rows("a"), CAROL)
    assert len(carol) == 1, f"fixture: the control world served CAROL once: {carol}"
    decision = carol[0].get("source")
    _assert_reconstructed(decision, "the archived control world's changed answer")
    assert json.loads(carol[0]["payload_text"]) == carol_at_fork, (
        "the control world recorded a payload other than its oracle's answer")

    ctx = S34.render_context(built, "b")
    rows = getattr(ctx, S34.COINED["ctx.contrast"])
    assert {"a", "b"} <= set(rows), f"fixture: the context holds no row for a or b: {set(rows)}"
    b, a = rows["b"], rows["a"]
    assert b[S34.COINED["contrast.shown"]] is True, "positive control: b was shown its facts"
    assert isinstance(b[S34.COINED["contrast.first_altered"]], int), (
        "positive control: b's altered call is numbered")
    assert list(b[S34.COINED["contrast.blocked"]]), (
        "positive control: b's withheld call is not in its blocked list")

    assert list(a[S34.COINED["contrast.errored"]]) == [], (
        "the judge reads the control's reconstructed answer as an outage (an errored call)")
    assert list(a[S34.COINED["contrast.blocked"]]) == [], (
        "the judge reads the control's reconstructed answer as a blocked call")
    assert a[S34.COINED["contrast.shown"]] is False, (
        "the judge reads the control's reconstructed answer as shown facts")
    assert a[S34.COINED["contrast.first_altered"]] is None, (
        "the judge reads the control's reconstructed answer as its first altered call")
    assert list(a[S34.COINED["contrast.altered_leads"]]) == [], "the control has an altered lead"
    assert list(a[S34.COINED["contrast.unserved"]]) == [], "the control's call lost its partner"
    assert list(a[S34.COINED["contrast.unmapped"]]) == [], "a control ledger row joined no row"
    entries = [e for e in getattr(ctx, S34.COINED["ctx.reference_calls"])["a"]
               if e[S34.COINED["entry.call"]] is not None
               and S24.canonical(e.get("params") or {}) == S24.canonical(CAROL)]
    assert [e[S34.COINED["entry.source"]] for e in entries] == [decision], (
        "the judge's call list does not carry the control call's own decision")


#: The oracle's own side query in the `fault` case below: a declared read verb of the system.
_SIDE_LOOKUP = {"entity": "bob"}


def _broken_verb_lookup(_system: str) -> Any:
    raise TypeError("the oracle door's verb lookup broke")


_UNSERVABLE_CAUSES = ("budget", "retries", "fault")


@pytest.mark.parametrize("cause", _UNSERVABLE_CAUSES)
def test_1255_a_control_world_whose_oracle_cannot_serve_never_falls_back_to_a_live_read(
        tmp_path: Path, cause: str) -> None:
    est = S24.estate(tmp_path)
    est.answer("idp", "query", BOB, BOB_ANSWER)
    est.answer("idp", "lookup", _SIDE_LOOKUP, {"user": "bob", "status": "active"})
    ep = S24.episode_v2(tmp_path, base_rows=[S24.captured("idp", "query", ALICE, ALICE_ANSWER)])
    knobs: dict[str, Any] = {}
    if cause == "budget":
        oracle = S24.oracle(then=S24.submit(_resorted(BOB_ANSWER), S24.EMPTY_CLAIM))
        knobs["budget"] = 0
    elif cause == "retries":
        oracle = S24.oracle(then=S24.text_only("I could not reconstruct this answer."))
        knobs["retry_cap"] = 2
    else:
        oracle = S24.oracle(S24.run_query("idp", "lookup", _SIDE_LOOKUP),
                            then=S24.submit(_resorted(BOB_ANSWER), S24.EMPTY_CLAIM))
    control = S24.sandboxed_registry(ep, "a", est, oracle=oracle,
                                     verifier=S24.passing_verifier(), **knobs)
    if cause == "fault":
        door = getattr(getattr(control, "oracle", None), "door", None)
        assert hasattr(door, "real_verbs"), (
            "fixture: the registry's oracle door (the seam #1224's broken-machine regression "
            "breaks) is not where that regression finds it")
        door.real_verbs = _broken_verb_lookup
    ctx = est.ctx(tmp_path / "run")

    assert S24.call(control, "idp", "query", ctx, **ALICE) == ALICE_ANSWER
    with pytest.raises(S24.unservable_cls()) as raised:
        S24.call(control, "idp", "query", ctx, **BOB)
    assert raised.value.reason == cause, (
        f"the control world's call ended unservable for {raised.value.reason!r}, not {cause!r}")
    if cause != "budget":
        assert oracle.requests >= 1, "fixture: the control world's oracle was never asked"
    rows = S24.ledger_rows(ep, "a")
    assert [S24.canonical(r["params"]) for r in rows] == [S24.canonical(ALICE)], (
        f"the unservable call ({cause}) left a ledger row: something was served for it")


@pytest.mark.parametrize("label", ["a", "b"], ids=["control-world", "world-with-facts"])
def test_1255_a_worlds_oracle_is_given_the_sources_own_closing_ticket_comment(
        tmp_path: Path, label: str) -> None:
    from defender.runtime import case_ticket
    from defender.tests.support.runtime.engine import _spec767 as S767
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    marker = "CLOSING-NOTE-1255: alice's db-1 logon was the TGT abuse; account disabled"
    source_dir = S767.make_run(tmp_path / "runs", name=S24.SOURCE_RUN_ID,
                               disposition="malicious", body=marker)
    store = S767.FakeStore()
    S767.record(source_dir, store)
    posted = store.wire_body()
    tag = case_ticket.agent_comment_tag(S24.SOURCE_RUN_ID)
    assert tag in posted, f"fixture: the source posted {posted!r}"
    assert marker in posted, f"fixture: the source posted {posted!r}"

    est = S24.estate(tmp_path)
    est.answer("idp", "query", BOB, BOB_ANSWER)
    ep = S24.episode_v2(tmp_path, base_rows=[S24.captured("idp", "query", ALICE, ALICE_ANSWER)])
    oracle = S24.oracle(then=S24.submit(_resorted(BOB_ANSWER), S24.EMPTY_CLAIM))
    world = W.world_registry_with_source(ep, label, est, source_run=fixture_run(source_dir),
                                         oracle=oracle, verifier=S24.passing_verifier())
    S24.call(world, "idp", "query", est.ctx(tmp_path / "run"), **BOB)

    assert oracle.requests >= 1, f"world {label}'s new question took no oracle turn"
    inbound = oracle.all_seen()
    assert W.FORK_TIME in inbound, "the oracle was not told the fork time"
    assert tag in inbound, "the oracle was not told the source's post-fork comment (its tag)"
    assert marker in inbound, "the oracle was not told what the source's closing comment says"


@pytest.mark.parametrize("post", ["post-failed", "never-posted"])
@pytest.mark.parametrize("label", ["a", "b"], ids=["control-world", "world-with-facts"])
def test_1255_a_worlds_oracle_is_not_told_a_closing_comment_the_source_never_posted(
        tmp_path: Path, label: str, post: str) -> None:
    from defender.runtime import case_ticket
    from defender.tests.support.runtime.engine import _spec767 as S767
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    marker = "CLOSING-NOTE-1255: alice's db-1 logon was the TGT abuse; account disabled"
    source_dir = S767.make_run(tmp_path / "runs", name=S24.SOURCE_RUN_ID,
                               disposition="malicious", body=marker)
    assert marker in (source_dir / "report.md").read_text(encoding="utf-8"), (
        "fixture: the source's report does not carry the narrative marker")
    if post == "post-failed":
        store = S767.FakeStore(status_by_suffix={S767.COMMENTS_SUFFIX: "500"})
        S767.record(source_dir, store)
        assert len(store.comment_payloads) == 1, "fixture: the source never attempted its comment"
        assert S767.receipt(source_dir).get("ok") is False, (
            f"fixture: the receipt does not record a failed post: {S767.receipt(source_dir)}")
    else:
        assert not S767.receipt_path(source_dir).exists(), "fixture: a receipt is already there"
    tag = case_ticket.agent_comment_tag(S24.SOURCE_RUN_ID)

    est = S24.estate(tmp_path)
    est.answer("idp", "query", BOB, BOB_ANSWER)
    ep = S24.episode_v2(tmp_path, base_rows=[S24.captured("idp", "query", ALICE, ALICE_ANSWER)])
    oracle = S24.oracle(then=S24.submit(_resorted(BOB_ANSWER), S24.EMPTY_CLAIM))
    world = W.world_registry_with_source(ep, label, est, source_run=fixture_run(source_dir),
                                         oracle=oracle, verifier=S24.passing_verifier())
    S24.call(world, "idp", "query", est.ctx(tmp_path / "run"), **BOB)

    assert oracle.requests >= 1, f"fixture: world {label}'s new question took no oracle turn"
    inbound = oracle.all_seen()
    assert W.FORK_TIME in inbound, "positive control: the oracle was not told the fork time"
    assert tag not in inbound, (
        f"the oracle was handed a closing comment ({post}): the source's tag line, though the "
        "source wrote nothing to the ticket")
    assert marker not in inbound, (
        f"the oracle was handed the source's report narrative as its closing comment ({post}), "
        "though the source wrote nothing to the ticket")


def test_1255_every_refusal_the_control_world_can_give_reads_as_a_natural_runs(
        tmp_path: Path) -> None:
    deep: dict = {"leaf": "x"}
    for _ in range(40):
        deep = {"n": deep}
    est = S24.estate(tmp_path, withheld=(WITHHELD,))
    est.fail("idp", "query", CAROL, fault="UpstreamFault", detail="shard 3 is down")
    turns = [S24.query_turn("idp", "query", {"q": "user:alice", "filter": deep}),
             S24.query_turn(*WITHHELD, {"entity": "alice"}),
             S24.query_turn("idp", S24.WRITE_VERB, {"host": "db-1"}),
             S24.query_turn("crm", "query", {"q": "*"}),
             S24.query_turn("idp", "no_such_verb", {}),
             S24.query_turn("idp", "query", CAROL),
             S24.done_turn()]
    natural_dir, natural = W.drive_lead(tmp_path / "natural", verbs=S24.plain_registry(est),
                                        est=est, turns=list(turns))
    ep = S24.episode_v2(tmp_path / "branch", base_rows=[])
    oracle = S24.oracle(then=S24.submit({"canary": "1255"}, S24.EMPTY_CLAIM))
    control = S24.sandboxed_registry(ep, "a", est, oracle=oracle,
                                     verifier=S24.passing_verifier())
    arm_dir, arm = W.drive_lead(tmp_path / "arm", verbs=control, est=est, turns=list(turns))

    expected = [W.normalized(t, natural_dir) for t in natural.handed_back()]
    handed = [W.normalized(t, arm_dir) for t in arm.handed_back()]
    assert len(expected) == 6, f"fixture: six refusals reached the natural run's model: {expected}"
    assert all(t.strip() for t in expected), f"fixture: a refusal text was empty: {expected}"
    assert len(set(expected)) == 6, "fixture: the six refusal classes read alike"
    sources = {r.get("source") for r in S24.ledger_rows(ep, "a")}
    assert {S24.REFUSED, S24.REAL_ERROR} <= sources, (
        f"fixture: the control world's registry saw the refused and errored calls: {sources}")
    for i, (got, want) in enumerate(zip(handed, expected, strict=True)):
        assert got == want, f"refusal {i} reads differently in the control world:\n{got}\n---\n{want}"
