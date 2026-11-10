"""#1278 A2 D1/D9: the real curators decide each item's fate from the claim; the store records it.

The tick is the real `author_drain` / `lead_author_drain` over `p4_tenant` (a real clone, loopback origin, forge fake)
with the store at `DEFENDER_DATABASE_DSN`. The curators are the REAL lessons, questioner and pitfalls curators: only
their model is scripted (`ScriptedModel`: `write_file` calls through the curators' own tools, then an AUTHOR_RESULT).
Nothing in the harness decides a fate; each case reads the items back from the store after the tick.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender.tests.support.learning.core._curators1278 import (  # noqa: E402
    LESSONS, PITFALLS, QUESTIONER, Reply, ScriptedModel, result, scripted)
from defender.tests.support.learning.core._store1278 import (  # noqa: E402
    AUTHOR_LANE, call, lapse_lease, lesson_citing, migrated_database, world, world_finding)  # noqa: F401 — fixtures
from defender.tests.support.learning.core._feedback1278 import framed  # noqa: E402
from defender.tests.tenancy.tenant_1108_delivery._support import (  # noqa: E402
    close_on_remote, comment_row, review_row)
from defender.tests.tenancy.tenant_1108_p4._drain_support import (  # noqa: E402
    BoxSpy, author_drain, critical_text, lead_author_drain, remote_branches)
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: E402, F401 — fixture `world` is built on

pytestmark = pytest.mark.postgres


def _row(fid: str, **extra):
    from defender.tests.support.learning.curation._drain719 import finding_row

    return finding_row(fid, run_id=f"run-{fid}", **extra)


def _seed(w, *ids: str, kind: str = "finding") -> None:
    rows = [world_finding(i) if kind == "questioner_finding" else _row(i) for i in ids]
    call(w.dsn, "publish_findings", w.t.tenant_id, "run-1", rows, kind=kind)


def _items(w) -> dict:
    return {(i.kind, i.key): i for i in call(w.dsn, "work", w.t.tenant_id)}


def _batches(w) -> dict:
    return {b.id: b for b in call(w.dsn, "batches", w.t.tenant_id)}


def _tick(w, model: ScriptedModel) -> int:
    with scripted(model, w.monkeypatch):
        return author_drain(w.t, w.paths, trigger=None, box=BoxSpy(), make_model=model.make_model)


def _lead_tick(w, model: ScriptedModel) -> int:
    with scripted(model, w.monkeypatch):
        return lead_author_drain(w.t, w.paths, box=BoxSpy(), run_lead_author=lambda *_a, **_k: None,
                                 make_model=model.make_model)


def _only_batch(w):
    [batch] = _batches(w).values()
    return batch


# --- control: the scripted model drives the real curator tools -----------------------------------------------------------


def test_harness_the_scripted_model_writes_through_the_curators_own_tools(tmp_path):
    """Control: a scripted reply lands as a file written by the real `write_file`, and the curator's result parses. (D1)"""
    import logging

    from pydantic_ai.models import override_allow_model_requests

    from defender.learning.author.curator_engine import _run_curator_pydantic, run_curator_stage
    from defender.tests.support.learning.core._stage_args import as_curator_stage_args

    stage = tmp_path / "stage"
    corpus = stage / "agent" / "lessons"
    corpus.mkdir(parents=True)
    prompt = tmp_path / "curator.md"
    prompt.write_text("Curate the corpus.\n", encoding="utf-8")
    run_dir = tmp_path / "call"
    run_dir.mkdir()
    model = ScriptedModel(lessons=Reply({"x.md": lesson_citing("f1")}, result(committed=["f1"])))
    args = as_curator_stage_args(dict(
        system_prompt_file=prompt, batch_id="b", user_prompt='batch_id: b\nlessons_dir: agent/lessons\n\n[{"finding_id": "f1"}]',
        corpus_dir=corpus, repo_root=stage, learning_run_dir=run_dir, model="glm-5.3", effort="low", request_limit=5,
        timeout=60, log=logging.getLogger("defender.test"), source_key=lambda m, label=None: None,
        run_author=lambda wiring, ctx, **kw: _run_curator_pydantic(wiring, ctx, **kw, make_model=model.make_model)))
    with override_allow_model_requests(False):
        got = run_curator_stage(**args)

    assert got["committed"] == ["f1"]
    assert "source_finding_ids" in (corpus / "x.md").read_text(encoding="utf-8")
    assert model.keys_shown(LESSONS) == ["f1"]


# --- D1: what each curator is handed -----------------------------------------------------------------------------------------


def test_d1_each_curator_is_handed_its_own_kinds_items_from_the_claim(world, caplog):  # noqa: F811 — the imported fixture
    """The claim holds a finding and a questioner finding: the lessons curator is shown the first only, the questioner
    curator the second only, and both ride one batch and one PR. (D1)"""
    w = world
    _seed(w, "f1")
    _seed(w, "q1", kind="questioner_finding")
    model = ScriptedModel(
        lessons=Reply({"l1.md": lesson_citing("f1")}, result(committed=["f1"])),
        questioner=Reply({"q1.md": lesson_citing("q1")}, result(committed=["q1"])))

    _tick(w, model)

    assert model.keys_shown(LESSONS) == ["f1"], critical_text(caplog)
    assert model.keys_shown(QUESTIONER) == ["q1"]
    assert all("q1" not in s.prompt for s in model.seen if s.curator == LESSONS), "the lessons curator saw a questioner item"
    assert all("f1" not in s.prompt for s in model.seen if s.curator == QUESTIONER), "the questioner curator saw a finding"
    batch = _only_batch(w)
    assert (batch.phase, len(w.t.forge.creates)) == ("in_review", 1)
    assert {k: i.status for k, i in _items(w).items()} == {("finding", "f1"): "in_batch", ("questioner_finding", "q1"): "in_batch"}


# --- D1: every outcome becomes a status at the batch's in_review (or its end, with no commits) -------------------------------


def test_d1_cited_committed_items_stay_in_their_batch_and_an_uncited_one_returns_to_waiting(world, caplog):  # noqa: F811 — the imported fixture
    """f1 and f2 are claimed, one lesson cites f1 and the model reports only f1: f1 stays in the batch with its PR,
    f2 is waiting again. (D1, H16 at in_review)"""
    w = world
    _seed(w, "f1", "f2")
    model = ScriptedModel(lessons=Reply({"l1.md": lesson_citing("f1")}, result(committed=["f1"])))

    _tick(w, model)

    assert sorted(model.keys_shown(LESSONS)) == ["f1", "f2"], critical_text(caplog)
    batch, items = _only_batch(w), _items(w)
    assert (batch.phase, batch.pr_number is not None) == ("in_review", True)
    assert (items[("finding", "f1")].status, items[("finding", "f1")].batch_id) == ("in_batch", batch.id)
    assert items[("finding", "f2")].status == "waiting"


def test_d1_a_reported_commit_no_lesson_cites_is_deferred_and_dead_at_the_ceiling(world, caplog):  # noqa: F811 — the imported fixture
    """The model reports f2 committed beside a lesson that cites only another finding: f2 waits with a deferral each
    tick and is dead at the third. (D1 deferred, deferrals)"""
    w = world
    w.monkeypatch.setenv("LEARNING_AUTHOR_MAX_ATTEMPTS", "3")
    _seed(w, "f2")
    for n in (1, 2, 3):
        fresh = f"g{n}"
        _seed(w, fresh)
        model = ScriptedModel(lessons=Reply({f"l{n}.md": lesson_citing(fresh)}, result(committed=[fresh, "f2"])))
        _tick(w, model)
        assert fresh in model.keys_shown(LESSONS), critical_text(caplog)
        f2 = _items(w)[("finding", "f2")]
        assert (f2.status, f2.deferrals) == (("dead", 3) if n == 3 else ("waiting", n))
        batch = next(b for b in _batches(w).values() if b.phase == "in_review")
        call(w.dsn, "end_review", w.t.tenant_id, batch.id, expect_phase="in_review", outcome="merged",
             published=[("finding", fresh)], held=[])
    assert _items(w)[("finding", "f2")].reason, "a dead item names why"


def test_d1_a_consumed_skip_is_skipped_with_the_models_reason_when_the_batch_enters_review(world, caplog):  # noqa: F811 — the imported fixture
    """f2 reported consumed_skip beside a committed f1: skipped, reason kept, the same transaction that puts the batch in
    review. (D1 consumed_skip)"""
    w = world
    _seed(w, "f1", "f2")
    model = ScriptedModel(lessons=Reply({"l1.md": lesson_citing("f1")},
                                        result(committed=["f1"], skipped=[("f2", "restates an existing lesson")])))

    _tick(w, model)

    items = _items(w)
    assert _only_batch(w).phase == "in_review", critical_text(caplog)
    assert items[("finding", "f2")].status == "skipped"
    assert "restates an existing lesson" in (items[("finding", "f2")].reason or "")
    assert items[("finding", "f1")].status == "in_batch"


def test_d1_with_no_commits_the_batch_ends_at_once_with_every_outcome_applied(world, caplog):  # noqa: F811 — the imported fixture
    """The model skips f1 and commits nothing; f2 is in no bucket: no branch and no PR, the batch ended, f1 skipped, f2
    waiting. (D1 end without commits)"""
    w = world
    _seed(w, "f1", "f2")
    model = ScriptedModel(lessons=Reply({}, result(skipped=[("f1", "duplicate")])))

    _tick(w, model)

    batch, items = _only_batch(w), _items(w)
    assert batch.phase == "ended", critical_text(caplog)
    assert (w.t.forge.creates, remote_branches(w.t.remote)) == ([], {})
    assert items[("finding", "f1")].status == "skipped"
    assert items[("finding", "f2")].status == "waiting"


def test_d1_the_gate_holds_a_retired_row_with_its_reason_and_the_model_never_sees_it(world, caplog):  # noqa: F811 — the imported fixture
    """A queued row the lessons gate cannot admit is held with the gate's reason and is not shown to the model; the
    admitted one is authored. (D1 gate held)"""
    w = world
    call(w.dsn, "publish_findings", w.t.tenant_id, "run-1", [_row("old", direction="per-case"), _row("f1")], kind="finding")
    model = ScriptedModel(lessons=Reply({"l1.md": lesson_citing("f1")}, result(committed=["f1"])))

    _tick(w, model)

    items = _items(w)
    assert model.keys_shown(LESSONS) == ["f1"], critical_text(caplog)
    assert items[("finding", "old")].status == "held"
    assert "retired_direction" in (items[("finding", "old")].reason or "")
    assert items[("finding", "f1")].status == "in_batch"


def test_d1_a_finding_the_corpus_already_cites_is_published_and_not_shown_to_the_model(world, caplog):  # noqa: F811 — the imported fixture
    """The corpus check at authoring stays: f1 is cited by a lesson already on main, so it is published at the batch's
    review and the model is shown f2 only. (D1 corpus check, P1)"""
    w = world
    w.t.merge({"agent/lessons/earlier.md": lesson_citing("f1")}, message="a lesson merged before this tick")
    _seed(w, "f1", "f2")
    model = ScriptedModel(lessons=Reply({"l2.md": lesson_citing("f2")}, result(committed=["f2"])))

    _tick(w, model)

    items = _items(w)
    assert model.keys_shown(LESSONS) == ["f2"], critical_text(caplog)
    assert (items[("finding", "f1")].status, items[("finding", "f2")].status) == ("published", "in_batch")


# --- D1: a takeover has no outcomes in memory -------------------------------------------------------------------------------


def test_d1_a_takeover_applies_only_the_citation_rule_and_does_not_rerun_the_curator(world, caplog):  # noqa: F811 — the imported fixture
    """The PR open fails after the commit and push, so nothing is applied; once the lease lapses the next tick takes
    over: f1, cited by the batch's commit, stays in the batch, f2 (reported skipped, outcome lost) is waiting, and no
    model call is made. (D1 takeover, P3, P5)"""
    w = world
    _seed(w, "f1", "f2")
    first = ScriptedModel(lessons=Reply({"l1.md": lesson_citing("f1")},
                                        result(committed=["f1"], skipped=[("f2", "duplicate")])))
    w.t.forge.fail_create = True
    _tick(w, first)
    batch = _only_batch(w)
    assert (batch.phase, {k: i.status for k, i in _items(w).items()}) == (
        "working", {("finding", "f1"): "in_batch", ("finding", "f2"): "in_batch"}), critical_text(caplog)
    w.t.forge.fail_create = False
    lapse_lease(w.dsn, batch.id)
    second = ScriptedModel(lessons=Reply({"never.md": lesson_citing("f2")}, result(committed=["f2"])))

    _tick(w, second)

    assert second.seen == [], "a takeover only finishes delivery: no new authoring run"
    items = _items(w)
    assert _only_batch(w).phase == "in_review"
    assert items[("finding", "f1")].status == "in_batch"
    assert (items[("finding", "f2")].status, items[("finding", "f2")].reason) == ("waiting", None)


# --- D9: the lead lane -------------------------------------------------------------------------------------------------------


@pytest.fixture
def lead(world, monkeypatch):  # noqa: F811 — the imported fixture
    """The world with the pitfalls lane awake at one pitfall."""
    monkeypatch.setenv("LEARNING_PITFALLS_THRESHOLD", "1")
    return world


def _reducer_note() -> str:
    """The fixture tenant's committed reducer page plus one bullet under its pitfalls section: a valid pitfalls edit
    (the content gate refuses a rewritten page, frontmatter included)."""
    from defender.tests.tenancy.tenant_1108_p4._support import FIXTURE

    page = (FIXTURE / _reducer_path()).read_text(encoding="utf-8")
    return page.rstrip("\n") + "\n- **Name the unnested column.**\n"


def _pitfall(pid: str):
    from defender.tests.support.learning.core._declared870 import shim_row

    return shim_row(pid)


def _reducer_path() -> str:
    from defender.learning.leads.pitfalls_curator import REDUCER_REL

    return REDUCER_REL


def test_d9_the_pitfalls_curator_is_handed_the_claims_pitfalls_and_its_commit_waits_in_the_batch_for_the_merge(lead):
    """A queued pitfall is claimed by the lead lane's batch, the real pitfalls curator is shown it and commits to the
    draft: the batch is in review on the lead prefix and the pitfall stays in_batch until the PR merges. (D9)"""
    w = lead
    call(w.dsn, "add_pitfall", w.t.tenant_id, _pitfall("p4-run:1"))
    model = ScriptedModel(pitfalls=Reply({_reducer_path(): _reducer_note()}))

    rc = _lead_tick(w, model)

    assert rc == 0
    assert model.keys_shown(PITFALLS) == ["p4-run:1"]
    batch = _only_batch(w)
    assert (batch.lane == AUTHOR_LANE, batch.phase) == (False, "in_review")
    assert list(remote_branches(w.t.remote, "lead-author/")) == [batch.branch]
    item = _items(w)[("pitfall", "p4-run:1")]
    assert (item.status, item.batch_id, item.pr_number) == ("in_batch", batch.id, batch.pr_number)


def test_d9_a_rejected_pr_no_longer_loses_the_pitfalls_it_carried(lead, caplog):
    """The lead PR is closed with no words: the reconcile ends the batch closed and the pitfall is held for a person,
    where it was once consumed before landing and lost. (D9, H2)"""
    w = lead
    call(w.dsn, "add_pitfall", w.t.tenant_id, _pitfall("p4-run:1"))
    _lead_tick(w, ScriptedModel(pitfalls=Reply({_reducer_path(): _reducer_note()})))
    batch = _only_batch(w)
    w.t.forge.scopes = {"write:repository", "read:issue"}  # the reconcile reads the PR's comments too (H2)
    close_on_remote(w.t.p3, batch.branch)

    author = ScriptedModel()
    _tick(w, author)  # the hosted post-step's tick reconciles every lane's batches

    item = _items(w)[("pitfall", "p4-run:1")]
    assert (item.status, item.batch_id) == ("held", batch.id), critical_text(caplog)
    assert _batches(w)[batch.id].outcome == "closed"
    assert author.seen == [], "the author lane authored nothing for a lead-lane item"


def test_d9_pitfalls_the_curator_cannot_teach_take_their_own_fates_at_the_batch_end(lead, caplog):
    """Beside a pitfall the curator commits: one of an undeclared system is skipped with its system named, one with no id
    is dead; the committed one stays in the batch. (D9 per-kind fates, D1 unkeyable)"""
    w = lead
    evil = {**_pitfall("p4-run:2"), "system": "evil", "query_id": "evil.esql", "stderr_digest": "exit=1; evil"}
    keyless = {k: v for k, v in _pitfall("p4-run:3").items() if k != "pitfall_id"}
    for row in (_pitfall("p4-run:1"), evil, keyless):
        call(w.dsn, "add_pitfall", w.t.tenant_id, row)
    model = ScriptedModel(pitfalls=Reply({_reducer_path(): _reducer_note()}))

    _lead_tick(w, model)

    items = _items(w)
    assert _only_batch(w).phase == "in_review", critical_text(caplog)
    assert items[("pitfall", "p4-run:1")].status == "in_batch"
    assert items[("pitfall", "p4-run:2")].status == "skipped"
    assert "evil" in (items[("pitfall", "p4-run:2")].reason or "")
    [dead] = [i for i in items.values() if i.status == "dead"]
    assert dead.kind == "pitfall"
    assert dead.reason


def test_d9_each_tick_claims_only_its_own_lanes_kinds(lead, caplog):
    """The lead tick takes the waiting pitfall and leaves a waiting finding alone; the author tick then takes the
    finding and leaves the pitfall in its lead batch. (D9, Locks)"""
    w = lead
    _seed(w, "f1")
    call(w.dsn, "add_pitfall", w.t.tenant_id, _pitfall("p4-run:1"))
    pitfalls = ScriptedModel(pitfalls=Reply({_reducer_path(): _reducer_note()}))

    _lead_tick(w, pitfalls)

    assert pitfalls.keys_shown(PITFALLS) == ["p4-run:1"], critical_text(caplog)
    assert pitfalls.keys_shown(LESSONS) == []
    assert _items(w)[("finding", "f1")].status == "waiting"
    [lead_batch] = _batches(w).values()
    authors = ScriptedModel(lessons=Reply({"l1.md": lesson_citing("f1")}, result(committed=["f1"])))

    _tick(w, authors)

    assert authors.keys_shown(LESSONS) == ["f1"]
    assert authors.keys_shown(PITFALLS) == []
    items = _items(w)
    assert items[("pitfall", "p4-run:1")].batch_id == lead_batch.id
    assert items[("finding", "f1")].batch_id != lead_batch.id


# --- Feedback: the real curators' prompts on a replacement tick (H13, G-F5) ------------------------------------------------

_WORDS = ("cite the alert rule, not the host", "wrong lane")


def _closed_with_words(w, branch: str, number: int) -> None:
    """A person asks for changes and closes the PR with a comment."""
    w.t.forge.scopes = {"write:repository", "read:issue"}
    w.t.forge.comments[number] = [comment_row(501, "analyst", _WORDS[0])]
    w.t.forge.reviews[number] = [review_row(651, "owner", "REQUEST_CHANGES", body=_WORDS[1])]
    close_on_remote(w.t.p3, branch)


@pytest.mark.parametrize(("kind", "mine", "other"), [
    ("finding", LESSONS, QUESTIONER), ("questioner_finding", QUESTIONER, LESSONS)], ids=["lessons-only", "questioner-only"])
def test_h13_the_replacement_hands_the_feedback_to_the_real_curator_of_its_kind_inside_the_untrusted_frame(
        world, caplog, kind, mine, other):  # noqa: F811 — the imported fixture
    """A PR of one kind is closed with words: on the replacement tick that kind's curator prompt carries both inside an
    untrusted frame, and the other curator is not given them. (H13, G-F5)"""
    w = world
    _seed(w, "x1", kind=kind)
    reply = Reply({"l1.md": lesson_citing("x1")}, result(committed=["x1"]))
    _tick(w, ScriptedModel(**{mine: reply}))
    first = _only_batch(w)
    _closed_with_words(w, first.branch, first.pr_number)
    model = ScriptedModel(**{mine: reply})

    _tick(w, model)

    [new] = [b for b in _batches(w).values() if b.replaces == first.id]
    assert new.phase == "in_review", critical_text(caplog)
    prompts = [s.prompt for s in model.seen if s.curator == mine]
    assert prompts, "the curator of the batch's kind never ran"
    for words in _WORDS:
        assert any(framed(p, words) for p in prompts), f"{words!r} is not inside an untrusted frame in the prompt"
    assert all(_WORDS[0] not in s.prompt and _WORDS[1] not in s.prompt for s in model.seen if s.curator == other), (
        "feedback reached a curator of another kind")


def test_h13_a_lead_pr_closed_with_words_is_left_to_the_operators_tick_which_hands_them_to_the_pitfalls_curator(lead, caplog):
    """The post-step's tick leaves the lead batch's pitfall due when its PR is closed with words; the operator's lead
    tick makes the replacement, `replaces` the closed batch, and the pitfalls curator's prompt carries the words framed. (H13, D9)"""
    w = lead
    call(w.dsn, "add_pitfall", w.t.tenant_id, _pitfall("p4-run:1"))
    note = Reply({_reducer_path(): _reducer_note()})
    _lead_tick(w, ScriptedModel(pitfalls=note))
    first = _only_batch(w)
    _closed_with_words(w, first.branch, first.pr_number)

    _tick(w, ScriptedModel())  # the hosted post-step's tick: reconciles every lane, authors nothing for the lead lane

    batches = _batches(w)
    assert (batches[first.id].phase, batches[first.id].outcome) == ("ended", "closed"), critical_text(caplog)
    assert [b for b in batches.values() if b.replaces == first.id] == [], "the post-step made a lead-lane replacement"
    item = _items(w)[("pitfall", "p4-run:1")]
    assert (item.status, item.batch_id) == ("in_batch", first.id), "the pitfall is not due on the closed batch"
    assert len(w.t.forge.creates) == 1

    model = ScriptedModel(pitfalls=note)
    _lead_tick(w, model)

    [new] = [b for b in _batches(w).values() if b.replaces == first.id]
    assert (new.lane, new.phase) == (first.lane, "in_review"), critical_text(caplog)
    assert _items(w)[("pitfall", "p4-run:1")].batch_id == new.id
    prompts = [s.prompt for s in model.seen if s.curator == PITFALLS]
    assert prompts
    for words in _WORDS:
        assert any(framed(p, words) for p in prompts), f"{words!r} is not inside an untrusted frame in the prompt"
