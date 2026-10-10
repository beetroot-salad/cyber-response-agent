"""#1224 — the episode page, the frontend serializers and the episode readers over an
oracle-era episode (M05=A, M16=A, M19=A, O15, N02).

Every episode here is built with `_spec1224`'s builders (`judged_episode`, `outcome_record`,
`world_record`, `write_ledger` + `ledger_row`) and read RAW off disk or through the real
reader under test: `render_episode` (the page), `serialize.build_view` /
`serialize_queues.build_view` (the frontend), `episode.verdicts` / `episode.delta_o` (the
readers). The judge's record, where a scenario needs one, is written by the REAL judge
(`grade_episode`) driven by a scripted judge double; nothing here hand-writes `judge.yaml`.

RED AGAINST HEAD (96e4cdb0) IS THE EXPECTED STATE: the page still imports staging and reads
`review.yaml`; the readers key on `incomplete`; the lesson fields name `pattern`.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from defender.tests import _episode_1025 as E
from defender.tests import _judge_921 as J
from defender.tests import _state1135
from defender.tests import _triplet_947 as T
from defender.tests.live_oracle_1224 import _spec1224 as S

#: The page's rendered TEXT is what a reader sees; markup must arrive there as text and never
#: as live HTML in the raw bytes.
SCRIPT = "<script>alert('x1224')</script>"


@pytest.fixture(autouse=True)
def _roots(tmp_path, monkeypatch):
    """The runs base, the episodes root and the learning state root, all per test."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")


# --------------------------------------------------------------------------------------
# Private helpers.
# --------------------------------------------------------------------------------------


def _render(ep: Path) -> E.Page:
    """`render_episode(<dir>)` — the real entry point — then the page it wrote, parsed."""
    return E.render(ep, module=S.mod(S.VISUALIZE))


class _ScopedJudge(J.FakeJudge):
    """The judge double answering a world-scope draw with the v2 world reply (top-level
    `bucket` and `systems`) and the family-scope draw with the v2 family reply (`verdict_word`).
    It scripts content only; the judge decides what the reply means."""

    def __init__(self, world: dict[str, str], family: str) -> None:
        super().__init__()
        self.world_text = world
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
    return S.as_reply_text(J.reply_doc(findings=[], verdict_word="survived"))


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


# --------------------------------------------------------------------------------------
# O15 on the page.
# --------------------------------------------------------------------------------------


def test_1224_episode_page_shows_the_refusal_for_an_old_episode(tmp_path):
    """d01i_old_manifest_refused_on_page — the page over an episode whose manifest carries an
    old field shows the predates-the-oracle refusal and renders no world.

    (O15, N04: the predates-the-oracle reason is reported first.) Driven for `overlay` and for
    `captured_patterns`; the positive control is the same archive under a v2 manifest, which
    renders its worlds and shows no such reason (RF-9: the page refuses through the judge's
    reader)."""
    for key in ("overlay", "captured_patterns"):
        ep = S.judged_episode(tmp_path / key, doc=S.old_manifest(key))
        page = _render(ep)
        assert S.PREDATES in page.text.lower(), (
            f"an old manifest carrying {key!r} rendered without the predates-the-oracle reason")
        assert key in page.text, f"the refusal does not name the old field {key!r}"
        assert page.ids_with("world-") == [], (
            f"an old manifest carrying {key!r} still rendered world sections")
        assert "summary for world b" not in page.text, "the archived worlds were rendered"

    control = S.judged_episode(tmp_path / "v2")
    page = _render(control)
    assert page.ids_with("world-"), "the v2 control rendered no world sections"
    assert S.PREDATES not in page.text.lower()


def test_p069_old_manifest_keys_and_values_contain_markup_shown_on_the_page(tmp_path):
    """s_p032 — every manifest-, ledger- and judge-derived string reaches the page as inert text.

    Driven twice: an old manifest whose key and value carry markup (the refusal page), and a v2
    episode whose fact statement, entity name, served (forged) value and judge finding carry
    markup (the rendered page). Positive controls: the refusal reason and the fact statement and
    finding are SHOWN, as text."""
    old_doc = S.old_manifest("captured_patterns", value=[SCRIPT])
    old_doc["<img src=x onerror=alert('key')>"] = "<svg onload=alert('value')>"
    old = S.judged_episode(tmp_path / "old", doc=old_doc)
    page = _render(old)
    assert S.PREDATES in page.text.lower(), "the old manifest was not refused on the page"
    for markup in (SCRIPT, "<img src=x onerror=alert('key')>", "<svg onload=alert('value')>"):
        assert not _raw_has_live(page.raw, markup), f"{markup!r} reached the page as live HTML"

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


def test_1224_episode_page_over_an_old_episode_with_removed_step_timings(tmp_path):
    """s_p033 — over an old episode the page shows the predates-the-oracle refusal before any
    other reader fails.

    Other readers: timings, outcome record, ledger. The archive also carries a staged.yaml and
    a review.yaml, as a pre-oracle episode does."""
    ep = S.judged_episode(tmp_path, doc=S.old_manifest("overlay"), outcome=None)
    (ep / "staged.yaml").write_text("- {name: wv-old-logs, world: b}\n", encoding="utf-8")
    J.review_record(ep)
    E.write_timing(ep, [("questioner", "2026-07-28T10:00:00Z", "2026-07-28T10:01:00Z"),
                        ("staging", "2026-07-28T10:01:00Z", "2026-07-28T10:02:00Z"),
                        ("review", "2026-07-28T10:02:00Z", "2026-07-28T10:03:00Z")],
                   check=False)
    page = _render(ep)
    text = page.text.lower()
    assert S.PREDATES in text, "the old episode's page does not show the predates reason"
    for unrelated in ("timing record unreadable", "staging record unreadable",
                      "review record unreadable", "outcome record unreadable"):
        assert unrelated not in text, f"another reader failed first: {unrelated!r}"


# --------------------------------------------------------------------------------------
# The page over a v2 episode.
# --------------------------------------------------------------------------------------


def test_1224_episode_page_renders_a_v2_episode_from_the_models_output(tmp_path):
    """d12k_episode_page_reads_the_models_output — the page renders an oracle-era episode from
    the outcome record and the judge model's family record.

    With no staging, review-reachability or envelope sections (M19=A: the bucket is the judge
    model's; M16=A: the decision words). The staging module is gone, so a page that still
    imported it would fail to render."""
    ep = S.judged_episode(tmp_path, ledgers={
        "b": [_oracle_row("b"), S.ledger_row(S.REAL_ERROR, label="b",
                                             params=S.query_params("host:db-9"),
                                             payload="UpstreamFault: upstream said no")],
        "c": [S.ledger_row(S.PASSTHROUGH, label="c")]})
    S.outcome_record(ep, "accepted", reason="pre-flight calibrated every world")
    _grade(ep, tmp_path, _ScopedJudge({"b": _world_reply("observability", ["idp"]),
                                       "c": _world_reply("decision-discipline", ["edr"])},
                                      _family_reply()))
    page = _render(ep)
    text = page.text
    assert "pre-flight calibrated every world" in text, "the outcome record is not shown"
    assert "accepted" in text
    manifest = S.family_v2()
    for world in manifest["worlds"]:
        for fact in world["facts"]:
            assert fact["statement"] in text, f"world {world['world_id']}'s fact is not shown"
    assert "observability" in text, "the judge model's per-world buckets are not shown"
    assert "decision-discipline" in text, "the judge model's per-world buckets are not shown"
    for decision in (S.ORACLE_DECISION, S.REAL_ERROR, S.PASSTHROUGH):
        assert decision in text, f"the served-answer decision {decision!r} is not shown"
    lowered = text.lower()
    for gone in ("staging", "staged", "reachab", "envelope"):
        assert gone not in lowered, f"the page still renders a {gone!r} section"


def test_1224_episode_page_renders_with_neither_review_nor_staged_record(tmp_path):
    """o23_page_without_review_or_staged — the page renders an oracle-era episode with no
    review.yaml and no staged.yaml, and says nothing about their absence.

    No teardown-failure or staged-view block (O-23). Positive control: the page rendered the
    episode's worlds."""
    ep = S.judged_episode(tmp_path)
    assert not (ep / "review.yaml").exists()
    assert not (ep / "staged.yaml").exists()
    page = _render(ep)
    assert page.ids_with("world-"), "the page rendered no world at all"
    text = page.text.lower()
    for missing in ("review record", "staging record", "staged", "teardown",
                    "no review record"):
        assert missing not in text, f"the page reports {missing!r} for an oracle-era episode"


def test_1224_outcome_and_world_record_reasons_render_inert_on_the_page_and_in_the_judge_record(
        tmp_path):
    """o35_outcome_reasons_inert — reasons quoting investigator-influenced params render as
    inert text on the page and are kept as data in the judge's not-graded record.

    The reasons (markup, a newline) sit in the outcome record, its drift calls, and each
    world's own record; the reason text is shown (positive control). M05=A: `unusable` is
    stamped not-graded with no model call (PCO-02)."""
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
    """o40_page_samples_by_system — the page renders one section per system of the per-system
    samples record and never rejects it for lacking pattern keys.

    (O-40, O16.) The record shape is the coined one: a served system's verbs with their real
    example answers, and an unavailable system with its reason."""
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
    """pco03_page_records_block — the page shows an `unusable` and a `refused` outcome record
    with the word and its reason, and no empty decision slot.

    (PCO-03, M05=A.)"""
    for word, reason in (("unusable", "worlds b and c were unservable in pre-flight"),
                         ("refused", "pre-flight had no call to calibrate")):
        ep = S.judged_episode(tmp_path / word, outcome=None)
        S.outcome_record(ep, word, reason=reason)
        page = _render(ep)
        assert word in page.text, f"the outcome word {word!r} is not shown"
        assert reason in page.text, f"the {word!r} reason is not shown"
        assert not _empty_decision_slot(page.raw), f"an empty decision slot rendered for {word}"


def test_1224_episode_page_counts_oracle_rows_without_a_malformed_row_note(tmp_path):
    """pco09_page_counts_oracle_rows — the page's ledger read counts served `oracle` and `real-error` rows as rows: the malformed-row count it shows covers only a torn line, never them.

    (PCO-09, M16=A.) "Counts" is the page's ledger screening (`read_world_ledger`,
    65-regrounds PCO-09): every line is either a counted row or a malformed one, and the page
    shows the malformed count (`<n> malformed row`). Pinned as numbers: the torn line alone, not
    4 (today's reader counts every out-of-vocabulary `source` as malformed, GR-06). That twin is
    also the positive control: the note's channel is live. A per-decision tally on the page
    (e.g. "2 oracle · 1 real-error") is NOT pinned: no design element names one; the decision
    words being shown at all is d12k's.
    s_p236 — a page rendered while siblings append shows a consistent snapshot: no torn partial row, and no oracle-side store row shown as the sibling's own ledger (O9). The torn twin's world ledger ends in a partial line (an append in flight) and its oracle-side ledger carries its own rows.
    """
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


# --------------------------------------------------------------------------------------
# Timing.
# --------------------------------------------------------------------------------------


def test_1224_stage_timings_read_the_preflight_step_and_refuse_a_removed_step_legibly(tmp_path):
    """o49_stage_timings_read — the timing reader and the page read the pre-flight step, and a
    row naming a removed step fails with a legible reason.

    The removed steps are staging and review; the reason is consistent with O15's refusal
    (F-21: PREFLIGHT sits between QUESTIONER and RUNS)."""
    Step = S.sym(S.STEPS, "Step")
    preflight = getattr(Step, S.COINED["step.preflight"])
    order = [Step.QUESTIONER, preflight, Step.RUNS, Step.JUDGE]
    assert list(S.sym(S.STEPS, "STEPS")).index(preflight) == (
        list(S.sym(S.STEPS, "STEPS")).index(Step.QUESTIONER) + 1)
    timing = S.mod("learning.branch.timing")
    io = S.mod("_io")

    ep = S.judged_episode(tmp_path / "v2")
    steps = [(str(s), f"2026-07-28T10:0{i}:00Z", f"2026-07-28T10:0{i + 1}:00Z")
             for i, s in enumerate(order)]
    E.write_timing(ep, steps, check=False)
    with io.bind(ep) as bound:
        got = timing.read_stage_timings(bound)
    assert [r["step"] for r in got] == [str(s) for s in order]
    page = _render(ep)
    assert "timing record unreadable" not in page.text.lower()
    assert str(preflight) in page.text, "the page does not show the pre-flight step"

    for removed in ("staging", "review"):
        old = S.judged_episode(tmp_path / removed)
        E.write_timing(old, [("questioner", "2026-07-28T10:00:00Z", "2026-07-28T10:01:00Z"),
                             (removed, "2026-07-28T10:01:00Z", "2026-07-28T10:02:00Z")],
                       check=False)
        with io.bind(old) as bound, pytest.raises(ValueError, match=removed) as refused:
            timing.read_stage_timings(bound)
        message = str(refused.value)
        assert removed in message, f"the refusal does not name the removed step {removed!r}"
        assert S.PREDATES in message.lower(), (
            f"the refusal of {removed!r} is not O15's predates-the-oracle reason")


# --------------------------------------------------------------------------------------
# The episode readers (M05=A).
# --------------------------------------------------------------------------------------


def test_1224_episode_reader_reads_the_outcome_record(tmp_path):
    """d14i_episode_reader_reads_the_outcome_record — the episode reader takes the outcome and
    its reason from pre-flight's outcome record and refuses a not-accepted one.

    (M05=A: every word other than exactly `accepted` is not gradable; the retired word is not
    used.) The review.yaml a pre-oracle launcher wrote is no longer where the outcome lives: a
    stale one beside an accepted outcome record changes nothing."""
    recorded = S.sym(S.EPISODE, "_recorded_outcome")
    verdicts = S.sym(S.EPISODE, "verdicts")
    refusal = S.sym(S.EPISODE, "EpisodeError")
    io = S.mod("_io")

    ep = S.judged_episode(tmp_path / "unusable", outcome=None)
    S.outcome_record(ep, "unusable", reason="worlds b and c were unservable")
    with io.bind(ep) as bound:
        assert recorded(bound) == ("unusable", "worlds b and c were unservable")
    with pytest.raises(refusal) as refused:
        verdicts(ep)
    assert "worlds b and c were unservable" in str(refused.value)

    accepted = S.judged_episode(tmp_path / "accepted")
    J.review_record(accepted, outcome="rejected", reason="a stale pre-oracle record")
    with io.bind(accepted) as bound:
        assert recorded(bound)[0] == "accepted"
    assert set(verdicts(accepted)) == {"a", "b", "c"}


def test_1224_episode_readers_refuse_unusable_refused_and_no_record(tmp_path):
    """pco01_episode_readers_refuse_new_words — verdicts and delta_o refuse `unusable`,
    `refused`, an absent record and a torn record, each naming the word; `accepted` reads.

    (PCO-01, GR-01, M05=A.)"""
    verdicts = S.sym(S.EPISODE, "verdicts")
    delta_o = S.sym(S.EPISODE, "delta_o")
    refusal = S.sym(S.EPISODE, "EpisodeError")

    for word in ("unusable", "refused"):
        ep = S.judged_episode(tmp_path / word, outcome=None)
        S.outcome_record(ep, word, reason=f"the family is {word}")
        for reader in (verdicts, delta_o):
            with pytest.raises(refusal) as refused:
                reader(ep)
            assert word in str(refused.value), f"{reader.__name__} did not name {word!r}"

    absent = S.judged_episode(tmp_path / "absent", outcome=None)
    torn = S.judged_episode(tmp_path / "torn", outcome=None)
    (torn / S.OUTCOME_NAME).write_text("outcome: [accep", encoding="utf-8")
    for ep in (absent, torn):
        for reader in (verdicts, delta_o):
            with pytest.raises(refusal) as refused:
                reader(ep)
            assert "no record" in str(refused.value).lower() or S.OUTCOME_NAME in str(
                refused.value), f"{reader.__name__} did not report the missing record"

    accepted = S.judged_episode(tmp_path / "accepted")
    assert set(verdicts(accepted)) == {"a", "b", "c"}
    delta_o(accepted)


# --------------------------------------------------------------------------------------
# The frontend serializers.
# --------------------------------------------------------------------------------------

_QUESTIONER_LESSON = """---
name: {name}
description: a questioner pitfall keyed by the systems the judge model recorded
systems: {systems}
bucket: {bucket}
source_finding_ids: [ep-1/b/0/0]
created_at: 2026-10-01T00:00:00Z
---

Author worlds whose facts sit on a served system.
"""


def _lessons_tree(tmp_path: Path, lessons: dict[str, tuple[list[str], str]]) -> Path:
    tree = tmp_path / "defender"
    corpus = tree / "lessons-questioner"
    corpus.mkdir(parents=True)
    for name, (systems, bucket) in lessons.items():
        (corpus / f"{name}.md").write_text(_QUESTIONER_LESSON.format(
            name=name, systems=json.dumps(systems), bucket=bucket), encoding="utf-8")
    return tree


def test_1224_frontend_serializes_the_judge_models_buckets(tmp_path):
    """d12l_serialize_reads_the_models_output — the lessons view carries each lesson's bucket
    and systems as the judge model recorded them.

    (M19=A, O12.) The questioner group declares a systems field beside the bucket and no
    pattern or holding-system field."""
    serialize = S.mod(S.SERIALIZE)
    tree = _lessons_tree(tmp_path, {"facts-on-served-systems": (["idp", "edr"], "observability")})
    view = serialize.build_view(tree)
    group = view["groups"]["questioner"]
    keys = [f["key"] for f in group["fields"]]
    assert "systems" in keys, f"the questioner fields are {keys}"
    assert "bucket" in keys, f"the questioner fields are {keys}"
    assert "pattern" not in keys, f"stale fields: {keys}"
    assert "holding_system" not in keys, f"stale fields: {keys}"
    (lesson,) = group["lessons"]
    assert lesson["metadata"]["systems"] == ["idp", "edr"]
    assert lesson["metadata"]["bucket"] == "observability"


def test_1224_learning_page_renders_a_questioner_lesson_keyed_by_systems(tmp_path):
    """o44_learning_page_reads_systems_lessons — the learning page renders a questioner lesson
    keyed by systems, and the shipped seed lesson is migrated to an empty systems list.

    With no blank Pattern/Holding-system heading and no KeyError (O-44, N23)."""
    serialize = S.mod(S.SERIALIZE)
    tree = _lessons_tree(tmp_path, {"keyed-by-systems": (["siem-x"], "lead-quality")})
    view = serialize.build_view(tree)
    group = view["groups"]["questioner"]
    labels = [f["label"] for f in group["fields"]]
    assert "Pattern" not in labels, f"the questioner group still renders blank headings: {labels}"
    assert "Holding system" not in labels, (
        f"the questioner group still renders blank headings: {labels}")
    (lesson,) = group["lessons"]
    assert lesson["status"] != "malformed"
    assert lesson["metadata"]["systems"] == ["siem-x"]

    fm_mod = S.mod("_frontmatter")
    seed = S.source_text("lessons-questioner/example-seed-lesson.md")
    assert seed, "the shipped seed lesson is gone"
    frontmatter = fm_mod.parse_frontmatter_or_none(seed)
    assert frontmatter is not None
    assert frontmatter.get("systems") == [], "the seed lesson is not migrated to systems: []"
    assert "pattern" not in frontmatter
    assert "holding_system" not in frontmatter

    shipped = serialize.build_view(S.DEFENDER)
    seeds = [x for x in shipped["groups"]["questioner"]["lessons"]
             if x["title"] == "example-seed-lesson"]
    assert seeds
    assert seeds[0]["status"] != "malformed"


def test_1224_queue_page_renders_a_row_of_the_new_shape(tmp_path):
    """o43_queue_page_reads_new_rows — the queue page renders a findings row of the new shape
    (systems, a v2 bucket, no pattern or holding system) without a missing-field error.

    (O-43, M19=A: the bucket set is the five plus observability.) The row is queued, held and
    dead-lettered, so each of the channel's three readers sees it."""
    serialize_queues = S.mod("learning.frontend.serialize_queues")
    config = S.mod("learning.core.config")
    state_mod = S.mod("learning.core.state")
    paths = config.LoopPaths(repo_root=tmp_path / "repo", state_dir=tmp_path / "state")
    paths.state_root.mkdir(parents=True, exist_ok=True)
    row = {"finding_id": "ep-1/b/0/0", "run_id": "ep-1", "subject": "world",
           "type": "observability", "systems": ["idp", "edr"], "claim": "a v2 world finding"}
    held = dict(row, finding_id="ep-1/c/0/0", held_reason="waits on a person")
    channel = state_mod.QUESTIONER_FINDINGS
    (paths.state_root / channel.queue).parent.mkdir(parents=True, exist_ok=True)
    (paths.state_root / channel.queue).write_text(
        json.dumps(row) + "\n" + json.dumps(held) + "\n", encoding="utf-8")
    (paths.state_root / channel.deadletter).write_text(json.dumps(
        {"finding_id": "ep-1/a/0/0", "attempts": 3, "deadletter_reason": "never taken",
         "retired_at": "2026-10-01T00:00:00+00:00", "row": dict(row, finding_id="ep-1/a/0/0")})
        + "\n", encoding="utf-8")
    with state_mod.LearningState.open(paths) as state:
        view = serialize_queues.build_view(paths, state)
    (qf,) = [c for c in view["channels"] if c["name"] == "questioner_findings"]
    assert qf["unreadable"] == 0, "a new-shape row was counted unreadable"
    assert qf["depth"]["queued"] == 2
    assert qf["held"]["ids"] == ["ep-1/c/0/0"]
    (dead,) = qf["deadletter"]
    assert dead["row"]["systems"] == ["idp", "edr"]
    assert "pattern" not in dead["row"]
    assert "holding_system" not in dead["row"]
