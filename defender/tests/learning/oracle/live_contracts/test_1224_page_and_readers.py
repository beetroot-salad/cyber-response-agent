"""#1224 — the episode page and episode readers over an oracle-era episode (outcome record, ledgers, judge record).
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from defender.tests.support.presentation import _episode_1025 as E
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.learning.oracle.live_contracts import _spec1224 as S

#: The page's rendered TEXT is what a reader sees; markup must arrive there as text and never
#: as live HTML in the raw bytes.


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    """The runs base, the episodes root and the learning state root, all per test."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


def _render(ep: Path) -> E.Page:
    """`render_episode(<dir>)` — the real entry point — then the page it wrote, parsed."""
    return E.render(ep, module=S.mod(S.VISUALIZE))


class _ScopedJudge(J.FakeJudge):
    """The judge double answering a world-scope draw with the world reply (top-level `bucket`
    and `systems`) and the family-scope draw with the family reply (world findings only; #1234
    retired the family's `verdict_word`).
    It scripts content only; the judge decides what the reply means."""

    def __init__(self, world: dict[str, str], family: str) -> None:
        super().__init__()
        self.world_text = {T.fixture_world_id(label) if label != "*" else "*": reply
                           for label, reply in world.items()}
        self.family_text = family

    def __call__(self, prompt, *, role=None, agent_id: str = "judge", **kw):
        label = agent_id.split(":")[1] if agent_id.count(":") >= 1 else ""
        self.default = (self.family_text if label == "family"
                        else self.world_text.get(label, self.world_text.get("*", "")))
        return super().__call__(prompt, role=role, agent_id=agent_id, **kw)


def _world_reply(bucket: str, systems: list[str], *, claim: str = "the lead never moved",
                 ) -> str:
    return S.as_reply_text(J.reply_doc(
        findings=[J.finding_doc(bucket=bucket, claim=claim)], bucket=bucket, systems=systems))


def _family_reply() -> str:
    return S.as_reply_text(J.family_reply())


def _grade(ep: Path, tmp_path: Path, judge: J.FakeJudge) -> None:
    """The REAL judge over the episode, driven by `judge` (it writes `judge.yaml`): by id
    (#1105 PR 2, `_judge_921.grade_at`)."""
    J.grade_at(ep, judge=judge, draws=1, state=_state1135.env_state())


def _oracle_row(label: str = "b", *, q: str = "user:alice", payload: object = None) -> dict:
    """One served `oracle` world-ledger row with the coined oracle fields."""
    return S.ledger_row(S.ORACLE_DECISION, label=label, params=S.query_params(q),
                        payload=payload if payload is not None else {"rows": [{"user": "alice"}]},
                        base_digest=S.digest('{"rows": []}'),
                        claim=S.claim(added=[S.added("fg-1", "f1")]),
                        verifier_verdict={"passed": True, "reason": "present"}, attempts=1)


def _raw_has_live(raw: str, markup: str) -> bool:
    """Whether `markup` reaches the page's raw bytes unescaped (i.e. as live HTML)."""
    return markup in raw


def _malformed_counts(page: E.Page) -> list[int]:
    """Every `<n> malformed row` count the page shows, read per TEXT NODE: `page.text` joins
    adjacent nodes with no separator, so a digit ending one node would glue onto the next
    node's count there."""
    return [int(n) for node in page.root.descendants() for piece in node.order
            if isinstance(piece, str) for n in re.findall(r"(\d+)\s+malformed row", piece)]


def _empty_decision_slot(raw: str) -> bool:
    return re.search(r'class="[^"]*decision[^"]*"[^>]*>\s*(?:None|-|—)?\s*<', raw) is not None


def test_manifest_ledger_and_judge_strings_reach_the_page_as_inert_text(tmp_path):
    fact_markup = "<script>alert('fact')</script> alice obtained a TGT"
    entity_markup = "<b>alice</b>"
    forged_markup = "<img src=x onerror=alert('forged')>"
    finding_markup = "<svg onload=alert('judge')>"
    doc = S.family_v2(worlds=[
        S.control_world("a"),
        S.world_v2("b", facts=[S.fact("f1", fact_markup, (entity_markup, "db-1"))]),
        S.world_v2("c"),
    ])
    ep = S.judged_episode(tmp_path / "v2", doc=doc, ledgers={
        "b": [_oracle_row("b", payload={"rows": [{"user": forged_markup}]})], "c": []})
    _grade(ep, tmp_path, _ScopedJudge(
        {"*": _world_reply("lead-quality", ["idp"], claim=finding_markup)}, _family_reply()))
    page = _render(ep)
    for markup in (fact_markup, entity_markup, forged_markup, finding_markup):
        assert not _raw_has_live(page.raw, markup), f"{markup!r} reached the page as live HTML"
    assert fact_markup in page.text, "the fact statement is not shown as text"
    assert finding_markup in page.text, "the judge's finding is not shown as text"


def test_1224_episode_page_renders_a_v2_episode_from_the_models_output(tmp_path):
    ep = S.judged_episode(tmp_path, ledgers={
        "b": [_oracle_row("b"), S.ledger_row(S.REAL_ERROR, label="b",
                                             params=S.query_params("host:db-9"),
                                             payload="UpstreamFault: upstream said no")],
        "c": [S.ledger_row(S.PASSTHROUGH, label="c")]})
    S.outcome_record(ep, "accepted", reason="pre-flight calibrated every world")
    # #1234: `observability` left the buckets (P-a), and a discipline bucket needs a world that
    # was shown its facts (A5) — b, whose oracle answered a call; c was served passthrough only.
    _grade(ep, tmp_path, _ScopedJudge({"b": _world_reply("decision-discipline", ["idp"]),
                                       "c": _world_reply("lead-quality", ["edr"])},
                                      _family_reply()))
    page = _render(ep)
    text = page.text
    assert "pre-flight calibrated every world" in text, "the outcome record is not shown"
    assert "accepted" in text
    manifest = S.family_v2()
    for world in manifest["worlds"]:
        for fact in world["facts"]:
            assert fact["statement"] in text, f"world {world['world_id']}'s fact is not shown"
    assert "lead-quality" in text, "the judge model's per-world buckets are not shown"
    assert "decision-discipline" in text, "the judge model's per-world buckets are not shown"
    for decision in (S.ORACLE_DECISION, S.REAL_ERROR, S.PASSTHROUGH):
        assert decision in text, f"the served-answer decision {decision!r} is not shown"


def test_1224_outcome_and_world_record_reasons_render_inert_on_the_page_and_in_the_judge_record(
        tmp_path):
    reason = "world b could not serve <script>alert('reason')</script>\nsecond line"
    call_markup = "<img src=x onerror=alert('call')>"
    drift_markup = "<svg onload=alert('drift')>"
    detail_markup = "<iframe src=javascript:alert('detail')>"
    ep = S.judged_episode(tmp_path, outcome=None)
    S.outcome_record(
        ep, "unusable", reason=reason,
        unservable=[{"world": "b", "reason": S.REASON_UNSERVABLE,
                     "call": {"system": "idp", "verb": "query",
                              "params": S.query_params(call_markup)}}],
        drift=[{"system": "edr", "verb": "query", "params": S.query_params(drift_markup),
                "status": "drifted"}])
    S.world_record(ep, "c", S.REASON_DID_NOT_FINISH,
                   call={"system": "idp", "verb": "query", "params": S.query_params(call_markup)},
                   detail=detail_markup)
    judge = J.FakeJudge(default=_family_reply())
    _grade(ep, tmp_path, judge)
    assert judge.calls == 0, "an unusable episode reached the judge model"
    record = J.judge_record(ep)
    assert any(reason in s for s in S.strings_in(record)), (
        "the not-graded record does not carry the outcome reason, verbatim, as data")
    assert any("unusable" in s for s in S.strings_in(record)), (
        "the not-graded record does not name the word")

    page = _render(ep)
    for markup in ("<script>alert('reason')</script>", call_markup, drift_markup,
                   detail_markup):
        assert not _raw_has_live(page.raw, markup), f"{markup!r} reached the page as live HTML"
    assert "world b could not serve" in page.text, "the outcome reason is not shown"
    assert "alert('reason')" in page.text, "the reason's quoted params are not shown as text"
    assert S.REASON_DID_NOT_FINISH in page.text, "world c's own record is not shown"


def test_1224_episode_page_renders_a_section_per_system_from_the_samples_record(tmp_path):
    ep = S.judged_episode(tmp_path)
    S.samples_record(ep, {
        "idp": {"verbs": {"query": ['{"rows": [{"user": "sample-alice-7"}]}']}},
        "edr": {"verbs": {"lookup": ['{"entity": "db-1", "risk": "sample-low-3"}']}},
        "siem-x": {"unavailable": "no answer was captured for siem-x"},
    })
    page = _render(ep)
    text = page.text
    assert "samples record unreadable" not in text.lower(), "the per-system record was refused"
    assert "sample-alice-7" in text, "idp's example answer is not rendered"
    assert "sample-low-3" in text, "edr's example answer is not rendered"
    assert "no answer was captured for siem-x" in text, "siem-x's unavailable reason is missing"


def test_1224_episode_page_shows_unusable_and_refused_with_their_reason(tmp_path):
    for word, reason in (("unusable", "worlds b and c were unservable in pre-flight"),
                         ("refused", "pre-flight had no call to calibrate")):
        ep = S.judged_episode(tmp_path / word, outcome=None)
        S.outcome_record(ep, word, reason=reason)
        page = _render(ep)
        assert word in page.text, f"the outcome word {word!r} is not shown"
        assert reason in page.text, f"the {word!r} reason is not shown"
        assert not _empty_decision_slot(page.raw), f"an empty decision slot rendered for {word}"


def test_1224_episode_page_counts_oracle_rows_without_a_malformed_row_note(tmp_path):
    rows = [_oracle_row("b"), _oracle_row("b", q="user:bob"),
            S.ledger_row(S.REAL_ERROR, label="b", params=S.query_params("host:db-9"),
                         payload="UpstreamFault: upstream said no")]
    ep = S.judged_episode(tmp_path / "clean", ledgers={"b": rows, "c": []})
    page = _render(ep)
    assert "malformed row" not in page.text, "served oracle/real-error rows read as malformed"
    assert S.ORACLE_DECISION in page.text, "the page does not show the served `oracle` rows"
    assert S.REAL_ERROR in page.text, "the page does not show the served `real-error` row"

    control = S.judged_episode(tmp_path / "torn", ledgers={"b": rows, "c": []})
    J.write_ledger(control, "b", [], raw="".join(json.dumps(r) + "\n" for r in rows)
                   + '{"system": "idp", "verb": "query", "params": {"q": "TORN-MARKER-1224')
    side = S.oracle_dir(control, "b")
    side.mkdir(parents=True, exist_ok=True)
    (side / "ledger.jsonl").write_text("".join(
        json.dumps({"actor": "oracle", "system": "idp", "verb": "query",
                    "params": S.query_params(f"ORACLE-SIDE-MARKER-{i}")}) + "\n"
        for i in range(3)), encoding="utf-8")
    torn = _render(control)
    counts = _malformed_counts(torn)
    assert counts, "a torn row raised no malformed-row note (dead channel)"
    assert counts == [1], (
        f"the page's malformed-row count is {counts}, not exactly 1 for one torn line beside "
        f"two served `oracle` rows and one `real-error` row — the served rows were counted as "
        f"malformed (or the oracle-side store's rows were read as the world's)")
    assert "TORN-MARKER-1224" not in torn.text, "the page showed a torn partial row"
    assert "ORACLE-SIDE-MARKER" not in torn.text, (
        "an oracle-side store row was shown as the sibling's own ledger")
    assert S.REAL_ERROR in torn.text, "the world ledger's complete row is not shown"


def test_1224_episode_readers_refuse_unusable_refused_and_no_record(tmp_path):
    verdicts = S.sym(S.EPISODE, "verdicts")
    delta_o = S.sym(S.EPISODE, "delta_o")
    refusal = S.sym(S.EPISODE, "EpisodeError")

    for word in ("unusable", "refused"):
        ep = S.judged_episode(tmp_path / word, outcome=None)
        S.outcome_record(ep, word, reason=f"the family is {word}")
        for reader in (verdicts, delta_o):
            with pytest.raises(refusal) as refused:
                J.through_view(ep, reader)
            assert word in str(refused.value), f"{reader.__name__} did not name {word!r}"

    absent = S.judged_episode(tmp_path / "absent", outcome=None)
    torn = S.judged_episode(tmp_path / "torn", outcome=None)
    (torn / S.OUTCOME_NAME).write_text("outcome: [accep", encoding="utf-8")
    for ep in (absent, torn):
        for reader in (verdicts, delta_o):
            with pytest.raises(refusal) as refused:
                J.through_view(ep, reader)
            assert "no record" in str(refused.value).lower() or S.OUTCOME_NAME in str(
                refused.value), f"{reader.__name__} did not report the missing record"

    accepted = S.judged_episode(tmp_path / "accepted")
    assert set(J.through_view(accepted, verdicts)) == {"a", "b", "c"}
    J.through_view(accepted, delta_o)
