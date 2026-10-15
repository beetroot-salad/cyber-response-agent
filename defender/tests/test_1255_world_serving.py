"""#1255 slice C — what a world serves: the adapter's own bytes (G8), and in every world, the
control included, a question the source never asked answered through the oracle, which is told
the fork time and the source's own writes after it (D3, O6, P5).

The design (issue #1255, design rev 4, "Time" / "The world at the fork" and "Served bytes"):

  * Served bytes. A world serves an answer byte-for-byte as the adapter produced it or the
    source recorded it — no `sort_keys` re-serialisation (today the ledger's `payload_text`
    re-dumps every answer key-sorted, and the primer re-dumps the source's own sidecars).
  * D3. Today the control world (no facts) passes its base straight through
    (`registry.serve_one`), so a question the source never asked is a raw live read, "as of
    now" for five of the eight adapters, and a ticket read shows the source run's own closing
    comment. Under D3 the control world runs an oracle turn whenever its base came from a live
    read; answers the source actually received are served from the recording, unchanged, in
    every world. The oracle is given the fork time and the source's own writes after the fork
    (its closing ticket comment). Where an adapter honours a cut-off, its live read uses the
    fork time.

Design rev 5 (the amendment to rev 4) adds two owner decisions this file holds the world to:

  * D5. When the control world's oracle serves an answer that DIFFERS from its base, the
    control serves what the oracle submitted — never the pre-oracle base — and the served
    ledger records a decision word of its own (e.g. `reconstructed`), not `oracle`. The judge
    reads it as baseline: not "shown facts", no first altered call. A turn that leaves the base
    unchanged stays `passthrough`. The tests never spell the new word: they demand a member of
    the ledger's own decision vocabulary that is neither `oracle` nor `passthrough`.
  * D6. Every live-read base goes through the oracle at the fork time — including a question
    the source asked before the fork that has no recording (its call failed, or its payload was
    unreadable: the real primer's `failed` / `unreadable` skips). The oracle may remove the
    source's own post-fork writes from it; "served unchanged" binds only answers the source
    received and the recording holds.

Every changed submission here carries a claim today's host checks accept with no facts (a
`changed` entry; a `removed` entry whose side query selects the removed row) — probed at base
in world b, where both are served.

The observation for O6 is what the oracle RECEIVES: every oracle here is #1224's recording
`ScriptedModel`, and the assertions read its inbound requests (`seen`), never its canned reply.
The served-bytes observation is the model's own channel: the payload sidecar the investigator
reads (`gather_raw/<lead>/<seq>.json`), the table row's `payload_sha256`, and the tool result
the gather model was handed — each compared with a NATURAL run over the same estate.

Residual (design "Residuals"; owned by this slice): the world registry's arm-only refusal
texts. Audited at base 4b3628ed — `_refuse_unstorable`'s `LedgerError` ("... was not served:
...") is pre-empted by the query tool's own `call_args_too_deep` check (`PARAMS_TOO_DEEP`, the
natural run's text); `PREBRANCH_REFUSAL` is said to the oracle, never the investigator;
`OracleUnservable` / `CallRecordWriteFailed` end the run (no text reaches the model); `EstateError`
is construction-time. The last test here pins the outcome: every refusal class the control world
can meet reads exactly as on a natural run.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests import _1255_world as W  # noqa: E402
from defender.tests.judge_contrast_1234 import _spec1234 as S34  # noqa: E402
from defender.tests.live_oracle_1224 import _spec1224 as S24  # noqa: E402

pytestmark = pytest.mark.e2e

ALICE = S24.query_params("user:alice")
BOB = S24.query_params("user:bob")
CAROL = S24.query_params("user:carol")

#: Answers whose keys are deliberately NOT in sorted order, at the top level and nested, so a
#: re-serialisation with sorted keys changes their bytes at every level.
ALICE_ANSWER = {"rows": [{"user": "alice", "host": "web-1", "event_id": "e-100",
                          "action": "logon"}], "total": 1}
BOB_ANSWER = {"total": 1, "rows": [{"user": "bob", "host": "db-1", "event_id": "e-200",
                                    "action": "logon"}]}

#: A verb every fixture system declares and the fixture grant withholds from gather.
WITHHELD = ("edr", "lookup")

#: A new question's live answer and the answer as the world stood at the fork, differing in one
#: value whose spellings occur nowhere else — what a control-world oracle's changed submission
#: (D5) looks like, claimed as one `changed` entry (no fact needed).
BOB_LIVE = {"total": 1, "rows": [{"user": "bob", "host": "db-live-1255", "event_id": "e-200",
                                  "action": "logon"}]}
BOB_AT_FORK = {"total": 1, "rows": [{"user": "bob", "host": "db-fork-1255", "event_id": "e-200",
                                     "action": "logon"}]}
BOB_CHANGE = S24.claim(changed=[S24.changed("bob", "host", "db-live-1255", "db-fork-1255")])

#: A ticket-shaped read (fixture system `siem-x`, verb `lookup`): the case ticket, its comments
#: a table. An analyst's note was on it at the fork; the source's own closing comment (posted
#: after the fork, tagged with the source run's id) is on it live.
CASE = {"entity": "CASE-1255"}
ANALYST_NOTE = {"comment_id": "c-1", "author": "soc-analyst", "body": "escalated for triage"}
CLOSING_MARKER = "CLOSING-NOTE-1255: verdict malicious, account disabled"
TICKET_AT_FORK = {"ticket": "CASE-1255", "status": "open", "comments": [ANALYST_NOTE]}
#: The side query a removal of the closing comment is claimed with: it selects that comment.
CLOSING_SIDE = S24.query_params("comment_id:c-2")

_LEDGER = "learning.branch.ledger"


@pytest.fixture(autouse=True)
def _roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    return W.configure_roots(tmp_path, monkeypatch)


def _resorted(payload: Any) -> Any:
    """`payload` re-spelled with every object's keys in sorted order — the same answer as a model
    re-writing it would naturally spell it, so a world serving the SUBMISSION's bytes rather than
    the base's is caught."""
    return json.loads(json.dumps(payload, sort_keys=True))


def _routed_passing(*answers: tuple[dict, Any]) -> Any:
    """An oracle that submits, for each call it is handed, that call's base answer unchanged
    (in sorted spelling), routed by the `q` the call carries (#1234's `Routed`)."""
    return S34.Routed({params["q"]: S24.oracle(then=S24.submit(_resorted(answer),
                                                                S24.EMPTY_CLAIM))
                       for params, answer in answers}, name="oracle-1255", last_wins=True)


def _closing_comment() -> dict:
    """The source run's own closing comment as the ticketing system holds it: the real agent
    tag line naming the source run (`case_ticket.agent_comment_tag`), then its verdict note."""
    from defender.runtime import case_ticket
    return {"comment_id": "c-2", "author": "defender",
            "body": f"{case_ticket.agent_comment_tag(S24.SOURCE_RUN_ID)}\n{CLOSING_MARKER}"}


def _closing_tag() -> str:
    from defender.runtime import case_ticket
    return case_ticket.agent_comment_tag(S24.SOURCE_RUN_ID)


def _ticket_after_close(est: Any) -> dict:
    """Script the live ticket as it stands after the source closed its case — the analyst's
    note plus the source's closing comment — and the side query that selects that comment.
    Returns the comment."""
    comment = _closing_comment()
    est.answer("siem-x", "lookup", CASE, {"ticket": "CASE-1255", "status": "open",
                                          "comments": [ANALYST_NOTE, comment]})
    est.answer("siem-x", "query", CLOSING_SIDE, {"rows": [comment]})
    return comment


def _removing_closing_comment() -> Any:
    """An oracle that serves the ticket as it stood at the fork: the closing comment removed,
    claimed as one removal whose side query selects it."""
    return S24.oracle(then=S24.submit(TICKET_AT_FORK, S24.claim(removed=[S24.removed(
        _closing_comment(), system="siem-x", verb="query", params=CLOSING_SIDE, count=1)])))


def _assert_reconstructed(decision: Any, where: str) -> None:
    """D5: the decision a control world records for an oracle answer that differs from its base
    is a word of the ledger's own decision vocabulary (`ledger.normalized_source` keeps it) and
    is neither `oracle` (a world shown its facts) nor `passthrough` (the base, unchanged). The
    word itself is the implementation's."""
    oracle_word = S24.sym(_LEDGER, "ORACLE")
    passthrough = S24.sym(_LEDGER, "PASSTHROUGH")
    assert decision not in (oracle_word, passthrough), (
        f"{where}: the control world's changed answer was recorded {decision!r} (D5: a decision "
        f"of its own, neither {oracle_word!r} nor {passthrough!r})")
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


# ======================================================================================
# G8 — served byte-for-byte.
# ======================================================================================


@pytest.mark.parametrize("label", ["a", "b"], ids=["control-world", "world-with-facts"])
def test_1255_a_new_question_served_unchanged_keeps_the_adapters_own_bytes(tmp_path: Path,
                                                                            label: str) -> None:
    """G8 (and O1 for the control world) — a question the source never asked, whose answer the
    world's oracle leaves unchanged, reaches the investigator with exactly the bytes the adapter
    produced: the payload sidecar, the row's `payload_sha256` and the tool result the gather
    model is handed equal a natural run's over the same estate — even though the oracle spelled
    its (equal) submission with sorted keys.

    Today the ledger re-dumps the answer with `sort_keys`, so the arm's sidecar and tool result
    are key-sorted where the natural run's are in the adapter's order.

    Fixture check first: the natural run's sidecar is NOT key-sorted (otherwise a sorting world
    would pass)."""
    est = W.ordered_estate(tmp_path)
    est.answer("idp", "query", BOB, BOB_ANSWER)
    turns = [S24.query_turn("idp", "query", BOB), S24.done_turn()]
    natural_dir, natural = W.drive_lead(tmp_path / "natural", verbs=S24.plain_registry(est),
                                        est=est, turns=list(turns))
    natural_row = W.row_for(W.lead_rows(natural_dir), BOB)
    natural_bytes = W.sidecar_bytes(natural_dir, natural_row)
    assert not W.is_key_sorted(natural_bytes.decode("utf-8")), (
        "fixture: the adapter's answer is already key-sorted, so this test cannot tell")

    ep = S24.episode_v2(tmp_path / "branch", base_rows=[])
    oracle = _routed_passing((BOB, BOB_ANSWER))
    reg = S24.sandboxed_registry(ep, label, est, oracle=oracle, verifier=S24.passing_verifier())
    arm_dir, arm = W.drive_lead(tmp_path / "arm", verbs=reg, est=est, turns=list(turns))
    arm_row = W.row_for(W.lead_rows(arm_dir), BOB)
    assert [r.get("source") for r in S24.ledger_rows(ep, label)], "fixture: the world served it"

    assert W.sidecar_bytes(arm_dir, arm_row) == natural_bytes, (
        "the investigator's payload file is not the adapter's bytes")
    assert arm_row["payload_sha256"] == natural_row["payload_sha256"]
    handed = [W.normalized(t, arm_dir) for t in arm.handed_back()]
    expected = [W.normalized(t, natural_dir) for t in natural.handed_back()]
    assert handed == expected, "the tool result the model read differs from a natural run's"


@pytest.mark.parametrize("label", ["a", "b"], ids=["control-world", "world-with-facts"])
def test_1255_a_repeated_new_question_served_from_the_worlds_store_keeps_the_adapters_own_bytes(
        tmp_path: Path, label: str) -> None:
    """G8 on the repeat path — a question the source never asked, asked TWICE in one lead: the
    first ask takes the world's oracle turn (unchanged answer), the second is served from the
    world's own store with no second turn. Both payload files and both tool results equal a
    natural run's that asks the same question twice over the same estate — the second tool
    result included, which carries the query tool's repeat note (it names the earlier call
    and says whether the payload is the same, by digest and sha).

    A world that keeps the adapter's bytes for the first serve but re-serialises its stored
    answer for the repeat (today's store holds the parsed answer and re-dumps it key-sorted)
    fails on the second file and on the second note. Today both asks are key-sorted.

    Fixture checks: the natural run's two payloads are not key-sorted, and its two tool results
    differ (the repeat note is there to compare). Last, the repeat cost no second oracle turn —
    it was the store's answer that was compared."""
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
    """G8, D3 ("answers the source actually received are served from the recording, unchanged,
    in every world") — a call the source run made is served to an arm byte-for-byte as the
    source's own payload sidecar holds it, from the family's recording (the real primer,
    `capture.prime_base`, over a real natural source run), with no live read of the estate.

    Today the primer re-dumps the source's sidecar with `sort_keys`, and the world serves that.

    Fixture check first: the source's sidecar is NOT key-sorted. In the control world the call
    also costs no oracle turn (D3: only a base read live goes through the control's oracle)."""
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
    episode_cls = S24.sym("_episode_handle", "Episode")
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


# ======================================================================================
# D3 / O6 / P5 — the control world answers new questions through its oracle.
# ======================================================================================


def test_1255_the_control_world_answers_a_question_the_source_never_asked_through_its_oracle(
        tmp_path: Path) -> None:
    """D3, O6, P5 — in the control world (no facts):

      * a call the source made (recorded) is served from the recording with no oracle turn;
      * a call the source never asked takes an oracle turn: the oracle is handed that call and
        its live base, and is told the fork time; the base's live read itself is bounded by the
        fork time (`as_of`, the adapter's cut-off); what the investigator gets is what the
        oracle's verified turn served.

    Today the second call is a raw live read passed straight through (`passthrough`, no turn):
    the oracle is never asked. Positive controls: a world WITH facts over the same episode is
    asked first, and its oracle's inbound carries the call, its live base and the fork time in
    exactly the spellings asserted below (so those assertions can hold for the control); the
    recorded call shows the control's double is countable at zero."""
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
    """D5 (R2-C1), D3, O6 — when the control world's oracle submits an answer that DIFFERS from
    the live base (one value changed, claimed as one `changed` entry: no fact needed), the
    investigator is handed the SUBMISSION, never the base: the tool result and the payload file
    carry the fork-time value and not the live one. The served ledger records the answer with a
    decision of its own (neither `oracle` nor `passthrough`) and the submission's payload.

    Discriminates a world that runs the oracle turn and then serves the base anyway (the
    review's oracle-discard mutant): every other control-world oracle in this suite submits the
    base unchanged, which such a world passes. Today the control takes no turn at all.

    Positive controls: the natural run over the same estate is handed the live value (the base
    really carries it), and the control's base was one live read at the fork time."""
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
    """D5 (R2-C1, ticket-shaped), D3, P5 — a ticket read the source never made: the live ticket
    carries the source run's own closing comment (posted after the fork, its tag line naming
    the source run). The control world's oracle submits the ticket as it stood at the fork,
    the comment removed (one claimed removal, its side query selecting the comment). The
    investigator never sees the comment: not in any tool result, not in any file of its run
    folder; it does see the ticket (the analyst's note that was there at the fork). The ledger
    records the decision of its own (D5).

    Positive control: a natural run over the same estate is handed the comment — tag line and
    note — and its run folder holds it, so the absence on the arm is the oracle's removal, not
    a ticket that never carried it. Today the control serves the live ticket, comment and all."""
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
    """D6 — a question the source asked BEFORE the fork that has no recording, asked again by
    an arm, goes through the world's oracle at the fork time, and the oracle may remove the
    source's own post-fork write from it: the arm is served the oracle's fork-time answer, not
    the live one, and not refused as a fixed pre-branch call (M01=A binds only answers the
    source received and the recording holds).

    The source is a REAL natural run (replay harness, real query tool) whose ticket read
    either failed (`failed`: the system errored) or was answered and its payload file then
    became unreadable (`unreadable`); the episode is primed from it by the REAL primer
    (`capture.prime_base`), whose report names that skip class. After the fork the source
    closed its case, so the live ticket carries its closing comment. The registry is handed the
    source's pre-branch request keys as `prebranch_calls` derives them (every captured call of
    the lead the source held at the branch point; its failed and unreadable rows included).

    Today the control world serves the live ticket (`passthrough`, no turn) and a world with
    facts refuses the oracle's change as a fixed pre-branch answer until the world goes
    unservable. Positive controls: the primer's skip count, the fork-time live read, and the
    oracle's inbound carrying the call and the fork time."""
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
    with S24.sym("_episode_handle", "Episode").open(ep) as handle:
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
    """D5 — on the REAL path (launcher, in-process siblings, archive), the control world asks a
    question the source never asked and its oracle changes the answer (one `changed` entry).
    The archived control world records that call with a decision of its own (neither `oracle`
    nor `passthrough`), and the judge's computed context reads it as baseline: the control's
    contrast row is not "shown its facts", has no first altered call and no altered lead; the
    call is joined to its ledger row (its entry carries that decision; nothing is unserved or
    unmapped).

    Positive control in the same family: world b's oracle alters the post-branch call, and
    b's contrast row IS shown its facts with a first altered call — so the flags this test
    demands false can be true here. Today the control takes no turn and records the live base
    `passthrough`."""
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


def test_1255_a_control_world_whose_oracle_cannot_serve_never_falls_back_to_a_live_read(
        tmp_path: Path) -> None:
    """O6 ("never by a raw live read"), D3 — when the control world's oracle cannot serve (its
    budget is zero), a question the source never asked is NOT answered with the live read: the
    call ends the world unservable (reason `budget`), as it does in a world with facts, and no
    ledger row records an answer for it.

    Positive control in the same registry: the recorded call is still served from the recording
    — a zero budget costs nothing where no oracle turn is needed. Today the new question is
    served the live answer, `passthrough`."""
    est = S24.estate(tmp_path)
    est.answer("idp", "query", BOB, BOB_ANSWER)
    ep = S24.episode_v2(tmp_path, base_rows=[S24.captured("idp", "query", ALICE, ALICE_ANSWER)])
    oracle = S24.oracle(then=S24.submit(_resorted(BOB_ANSWER), S24.EMPTY_CLAIM))
    control = S24.sandboxed_registry(ep, "a", est, oracle=oracle,
                                     verifier=S24.passing_verifier(), budget=0)
    ctx = est.ctx(tmp_path / "run")

    assert S24.call(control, "idp", "query", ctx, **ALICE) == ALICE_ANSWER
    with pytest.raises(S24.unservable_cls()) as raised:
        S24.call(control, "idp", "query", ctx, **BOB)
    assert raised.value.reason == S24.REASON_BUDGET
    rows = S24.ledger_rows(ep, "a")
    assert [S24.canonical(r["params"]) for r in rows] == [S24.canonical(ALICE)], (
        "the unservable call left a ledger row: something was served for it")


@pytest.mark.parametrize("label", ["a", "b"], ids=["control-world", "world-with-facts"])
def test_1255_a_worlds_oracle_is_given_the_sources_own_closing_ticket_comment(
        tmp_path: Path, label: str) -> None:
    """O6, P5 — in EVERY world, the oracle serving a question the source never asked is handed
    the source run's own write to the world after the fork: the closing comment the source
    posted on its case ticket, which names its run id (the agent tag line) and carries its
    verdict and narrative — so the oracle can serve the world as it stood at the fork, without
    it.

    The source's comment is posted by the REAL writer (`ticket_writer.record_case_ticket`)
    through its one seam, a recording store fake (#767's `FakeStore`); the registry is handed
    the source run through its own `source_run=` keyword. Assertion on what the oracle
    RECEIVED (P-receipt: the host-side receipt carries no comment text, so where the host reads
    the body from is the implementer's; what reaches the oracle is the contract).

    Positive control: the store fake received exactly that body (the tag line and the
    narrative marker), so a missing marker in the oracle's inbound is the oracle's input,
    not an empty comment. Today the control world takes no oracle turn at all, and a world with
    facts takes one without the source's comment."""
    from defender.runtime import case_ticket
    from defender.tests import _spec767 as S767
    from defender.tests._spec1077 import fixture_run

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


# ======================================================================================
# Residual — the control world's refusals are a natural run's refusals.
# ======================================================================================


def test_1255_every_refusal_the_control_world_can_give_reads_as_a_natural_runs(
        tmp_path: Path) -> None:
    """Residual ("arm-only refusal texts in the world registry"; O1 for the control world) — for
    every refusal class a control-world investigator can meet, the tool result it is handed is
    exactly a natural run's over the same estate: params nested past the storable bound, a
    withheld read verb, the never-granted write verb, a system the tenant does not serve, a verb
    the system does not declare, and the real system erroring on a call the source never asked.

    Compared modulo only the frame salt and each run's own run dir. Positive controls: every
    class produced a non-empty tool result on both runs, the classes are told apart (six
    distinct texts), and the control world's ledger recorded its refused and errored calls — so
    the registry did see them. Holds at base (regression guard for D3: a control world that now
    runs oracle turns must not grow a refusal of its own)."""
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
    # A canary: no call here should reach the control's oracle (each is refused or errors before
    # serving); one that did would be served this odd answer and differ from the natural run.
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
