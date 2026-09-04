"""#921 — the outcome vocabulary, the 08-16 fixture, and the corrected write census.

THE DESIGN'S OWN SECURITY CENSUS IS WRONG AND THIS FILE CARRIES THE CORRECTION. It names two new
write sinks — `worlds/<X>/judge/` and `episodes/<id>/judge.yaml`. There are THREE:
`learning/branch/seams.py::model_seam` builds a `StageContext(learning_run_dir=episode_dir)` and
`_pydantic_stage.run_stage` writes every call's FULL wire stream to
`<episode_dir>/wire_logs/<agent_id>_trace.jsonl` — the seam's own docstring says "THE TRACE LANDS
IN THE EPISODE". #921's per-world judge calls multiply that stream by worlds x draws, each
carrying the whole 10-32K-token prompt verbatim, so the undeclared sink holds the LARGEST
artifact in the tree. J14, settled: declare it in the census and note in the same sentence that
it is already denied to the model, so the fix is a census correction rather than a mechanism.

M8's FIXTURE IS THE DEMAND THAT MAKES THE MECHANICAL HALF FALSIFIABLE, and the amendment revised
it: it must carry a world that lands a `staged`-served row on H and STILL gets the verdict wrong,
or it cannot tell a correct implementation from a degenerate one — which is exactly why the
original fixture could not catch the refuted table.

RED against `d1b8b06a`: `_vocab.py` has no `JUDGE_OUTCOME_ENUM` and no normalizer for one.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from defender.tests import _drain719 as D
from defender.tests import _judge_921 as J


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))


def _vocab():
    return J.mod("_vocab")


# ---------------------------------------------------------------------------------------
# D1 / M4 — the vocabulary and its normalizer
# ---------------------------------------------------------------------------------------


def test_921_judge_outcome_enum_and_its_normalizer_ship_in_defender_vocab(tmp_path):
    """`JUDGE_OUTCOME_ENUM` and its normalizer live in `defender/_vocab.py`, whose admission
    rule is "more than one schema has to agree on it" — the queue row, the family record and the
    curator gate all do.

    Shipping the normalizer BESIDE it is what self-arms `lint_borrowed_vocabulary` against every
    other module's borrowed `x in JUDGE_OUTCOME_ENUM`: the gate flags a borrowed membership test
    against a vocabulary whose defining module has an armed normalizer, and does not flag
    re-exports. So the normalizer is not a convenience — it is what makes the vocabulary's one
    home enforceable, and the lint run is the witness.
    """
    from defender.tests._by_path import load_lint_gate

    vocab = _vocab()
    assert vocab.JUDGE_OUTCOME_ENUM == frozenset(  # noqa: SIM300 — the vocabulary is the SUBJECT
        {"caught", "survived", "undecidable", "discard", "corpus-contradiction"})
    assert callable(vocab.normalized_judge_outcome)

    gate = load_lint_gate("lint_borrowed_vocabulary")
    synthetic = tmp_path / "synthetic"
    defender_dir = synthetic / "defender"
    tree = defender_dir / "learning" / "judge"
    tree.mkdir(parents=True, exist_ok=True)
    # `gate._scan(root)` builds its corpus ONLY from files under `root` (arming is a
    # whole-corpus property, deliberately, so a scenario can show both arming and disarming
    # without touching the real tree) — so the file that ARMS `JUDGE_OUTCOME_ENUM` has to be
    # IN this synthetic tree too, not just real `defender/_vocab.py`. This is a trimmed copy of
    # its actual shape: the owned vocabulary plus a function testing membership on it beside it.
    (defender_dir / "_vocab.py").write_text(
        "JUDGE_OUTCOME_ENUM = frozenset(\n"
        "    {'caught', 'corpus-contradiction', 'discard', 'survived', 'undecidable'})\n"
        "\n"
        "\n"
        "def normalized_judge_outcome(value):\n"
        "    return value if value in JUDGE_OUTCOME_ENUM else None\n", encoding="utf-8")
    (tree / "borrowed.py").write_text(
        "from defender._vocab import JUDGE_OUTCOME_ENUM\n"
        "\n"
        "def route(word):\n"
        "    return word in JUDGE_OUTCOME_ENUM\n", encoding="utf-8")
    borrowed = {str(f) for f in gate._scan(synthetic)}
    assert any("borrowed.py" in name for name in borrowed), (
        "the normalizer does not arm the gate, so nothing stops a second membership test")


def test_921_every_surface_tests_membership_through_the_shipped_normalizer(tmp_path):
    """`_gate_family`'s routing, M5's refusal and the reply's validation ALL go through the
    shipped normalizer, not a bare `x in JUDGE_OUTCOME_ENUM`.

    Exercise the SAME case/whitespace variant at every surface and assert one answer: a variant
    admitted at one surface and refused at its sibling is the canonical fail-open, and it is the
    #785 shape — one parser, six interpreters, three of which disagreed.
    """
    vocab = _vocab()
    variant = "  Survived "
    assert vocab.normalized_judge_outcome(variant) == "survived"

    # 1. the reply's validation
    run_mod = J.mod("learning.judge.run")
    reply = run_mod.validate_reply(J.as_reply_text(J.reply_doc(episode_outcome=" Gradable ")))
    assert reply.episode_outcome == "gradable"

    # 2. the appender's refusal
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    J.mod("learning.judge").grade_episode(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        runs_base=tmp_path / "defender-runs", draws=1)
    enqueue = J.mod("learning.judge.enqueue")
    row = dict(D.finding_row("ep-1/b/0/0", run_id="ep-1", direction="family"),
               type="lead-set", judge_outcome=variant, subject_anchor="l-001",
               subject_topic="topic", source_run_dir="episodes/ep-1/worlds/b")
    assert enqueue.append_rows(ep, [row]) == 1, (
        "the appender refused a case variant the shipped normalizer admits")

    # 3. the gate's routing
    paths = D.make_paths(tmp_path / "gate")
    channel = D.channel_of(paths, "findings")
    D.seed(channel, [dict(row, finding_id="ep-1/b/0/1")])
    agent = D.recording(D.committing("variant"))
    assert J.mod("learning.author.drain").run_batch(
        cfg=D.cfg_for(paths, "findings", invoke_agent=agent)) == 0
    assert [r["finding_id"] for r in agent.calls[0]["rows"]] == ["ep-1/b/0/1"], (
        "the gate refused a variant the appender admitted; that disagreement IS the fail-open")


def test_921_a_garbage_outcome_value_fails_the_normalizer(tmp_path):
    """The paired negative control for the membership demand above, which exercises only case
    variants and known aliases: a value that is NOT AN OUTCOME AT ALL — not a case variant, not
    an alias — is REJECTED by the normalizer, not silently coerced to the nearest member.

    Without it the membership demand certifies that the normalizer normalizes, never that it
    refuses; a normalizer that returned its nearest member for everything would pass it.
    """
    vocab = _vocab()
    for garbage in ("", "   ", "outcome", "survived-ish", "SURVIVEDD", None, 7, ["survived"]):
        assert vocab.normalized_judge_outcome(garbage) is None, (
            f"{garbage!r} was coerced to a member instead of being refused")
    assert vocab.normalized_judge_outcome("CAUGHT") == "caught"


# ---------------------------------------------------------------------------------------
# M8 — the fixture that makes the mechanical half falsifiable
# ---------------------------------------------------------------------------------------


def test_921_hand_built_episode_yields_lead_set_and_survived(tmp_path):
    """A hand-built ACCEPTED episode in the #947 layout — two non-control worlds with
    contrasting declared dispositions, NO row on H, both verdicts equal to the control's —
    yields `lead-set` for both and `verdict_word: survived`.

    No real archived episode exists (#947's "one real branched run" was never reported done), so
    "reproduce the 08-16 finding mechanically" means exactly this fixture, and the limit is
    declared rather than hidden: the suite tests the readers against a tree the suite wrote.

    Every non-control world carries a NON-NULL role. A world declared `role: null` is the
    REPLICATE arm — `runnable_worlds` drops it, so it is never staged, never reviewed and never
    run, and the review record then reads "1 worlds reviewed" for a three-world manifest and
    looks green. A fixture holding one pins a family the launcher would never have produced.
    """
    ep = J.accepted_episode(
        tmp_path,
        dispositions={"a": "benign", "b": "malicious", "c": "benign"},
        ledgers={"b": [], "c": []})
    for label in ("a", "b", "c"):
        (ep / "worlds" / label / "report.md").write_text(
            "disposition: benign\n", encoding="utf-8")

    import yaml
    doc = yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    assert all(world["role"] for world in doc["worlds"]), (
        "a non-control world carries `role: null`; the launcher would have dropped it")

    grade = J.mod("learning.judge.family").grade_family(ep)
    rows = J.rows(grade)
    assert rows["b"]["bucket"] == rows["c"]["bucket"] == "lead-set"
    assert J.word_of(grade) == "survived", (
        "world b's verdict (benign) differs from its declared disposition (malicious) and the "
        "family did not survive")


def test_921_fixture_carries_a_staged_row_world_with_a_wrong_verdict(tmp_path):
    """The fixture MUST carry a world that lands a `staged`-served row on H and STILL gets the
    verdict wrong, or it cannot tell a correct implementation from a degenerate one — the reason
    the original fixture could not catch the refuted table.

    `staged` is reachable only for `elastic`, the sole stager, so the fixture's H is `elastic` or
    another stager-backed system; a state-system H can carry the difference only as `patched`.

    The DISCRIMINATION is the assertion, not the fixture's contents: a degenerate implementation
    that answers `lead-set` for every world passes the 08-16 fixture above and fails here,
    because here the world demonstrably WAS shown the doctored evidence.
    """
    ep = J.accepted_episode(
        tmp_path, holding_system="elastic",
        dispositions={"a": "benign", "b": "malicious", "c": "malicious"},
        ledgers={"b": [J.staged_row("b")], "c": []})
    (ep / "worlds" / "b" / "report.md").write_text("disposition: benign\n", encoding="utf-8")

    rows = J.rows(J.mod("learning.judge.family").grade_family(ep))
    assert rows["b"]["doctored_answer_served"] is True
    assert rows["b"]["verdict"] != rows["b"]["declared"]
    assert rows["b"]["bucket"] == "decision-discipline", (
        "the world that was shown the doctored evidence and still got the verdict wrong was "
        "bucketed as if nothing had reached it; that is the degenerate implementation this "
        "fixture exists to fail")
    assert rows["c"]["bucket"] == "lead-set", (
        "the fixture no longer contrasts a served world with an unserved one")


# ---------------------------------------------------------------------------------------
# the corrected security write census
# ---------------------------------------------------------------------------------------


def test_921_the_three_judge_write_sinks_are_the_only_ones_and_land_on_distinct_paths(tmp_path):
    """Grading one family writes into EXACTLY THREE places under the episode dir —
    `worlds/<X>/judge/<n>.yaml`, `episodes/<id>/judge.yaml`, and
    `wire_logs/<agent_id>_trace.jsonl` — and every path is distinct across worlds and draws.

    The design's census names only the first two; the wire log is the third and it holds the
    largest artifact in the tree. This is a DEMAND rather than a claim because a census that is
    not driven is a sentence: the episode tree is enumerated before and after a real grading
    pass, and the difference is the census.
    """
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    before = {p.relative_to(ep) for p in ep.rglob("*") if p.is_file()}
    J.mod("learning.judge").grade_episode(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        runs_base=tmp_path / "defender-runs", draws=2)
    after = {p.relative_to(ep) for p in ep.rglob("*") if p.is_file()}
    created = sorted(after - before)

    sinks = {"judge.yaml": [], "worlds": [], "wire_logs": []}
    for rel in created:
        if rel == Path("judge.yaml"):
            sinks["judge.yaml"].append(rel)
        elif rel.parts[0] == "worlds" and "judge" in rel.parts:
            sinks["worlds"].append(rel)
        elif rel.parts[0] == "wire_logs":
            sinks["wire_logs"].append(rel)
        else:
            pytest.fail(f"grading wrote a FOURTH sink nobody censused: {rel}")

    assert len(sinks["judge.yaml"]) == 1
    assert len(sinks["worlds"]) == 4, "two worlds x two draws did not give four reply files"
    assert len(sinks["wire_logs"]) == 4, (
        "the wire log is the third sink and it is written once per call; the design's census "
        "names it not at all")
    assert len(created) == len(set(created)), "two writes landed on one path"


def test_921_the_wire_log_holding_the_framed_prompt_is_not_reachable_from_a_box(tmp_path):
    """Every judge call re-persists the whole framed-untrusted prompt AND the whole reply
    VERBATIM into `<episode_dir>/wire_logs/`, multiplied by worlds x draws at 10-32K input
    tokens per call.

    The sink is already denied to the model outright (`files.names_wire_log_dir`, both read
    surfaces, every role), so the fix is a census correction and this demand is its witness:
    assert the denial holds for a BOX BOUND INTO THE EPISODE TREE, where a sibling's run dir is
    `{episode_dir}/runs/<id>-<label>` and the episode dir is its parent.

    Positive control: the sibling's OWN run-root artifacts still read, so the denial is one
    directory rather than a policy that refuses everything.
    """
    pytest.importorskip("pydantic_ai")
    from defender.agents import GATHER_DEF, MAIN_DEF
    from defender.runtime import permission
    from defender.runtime.agent_definition import compile_policy_for

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    J.mod("learning.judge").grade_episode(
        ep, judge=J.FakeJudge(default=J.as_reply_text(J.reply_doc())),
        runs_base=tmp_path / "defender-runs", draws=1)
    traces = J.wire_logs(ep)
    assert traces, "the judge left no wire log at all; there is nothing to deny"

    runs = ep / "runs"
    run_dir = J.sibling_run_dir(runs, "b")
    dfn = tmp_path / "defender"
    (dfn / "lessons").mkdir(parents=True, exist_ok=True)
    env = SimpleNamespace(
        run=run_dir, dfn=dfn,
        main=compile_policy_for(MAIN_DEF, run_dir=run_dir, defender_dir=dfn),
        gather=compile_policy_for(GATHER_DEF, run_dir=run_dir, defender_dir=dfn))

    for which in ("main", "gather"):
        policy = getattr(env, which)
        for trace in traces:
            assert not permission.decide_read(
                Path(trace), run_dir=env.run, defender_dir=env.dfn, policy=policy).allow
            assert not permission.decide_bash(
                f"cat {trace}", policy=policy, run_dir=env.run, defender_dir=env.dfn).allow
        assert permission.decide_read(
            run_dir / "investigation.md", run_dir=env.run, defender_dir=env.dfn,
            policy=policy).allow, "the positive control failed: nothing reads at all"


def test_921_append_findings_writes_a_gate_conforming_row(tmp_path):
    """`append_findings` — the PRE-EXISTING generic queue writer every direction calls, not just
    the judge's new one — writes a row carrying `run_id` and `direction`.

    P6 shows a row missing either raises a bare `KeyError` inside the shared gate, which `_tick`
    stuck-records as the WHOLE keyed batch — every well-formed adversarial and benign row riding
    beside it — and then re-raises. The shared sink's shape guarantee has to hold for THIS
    writer too, not only for the family direction's new one: #921 makes the failure reachable
    from a new direction, but the sink was always shared.

    Driven through the real writer and then through the real gate, so "conforming" is the gate's
    answer rather than a key list this file re-states.
    """
    paths = D.make_paths(tmp_path)
    persist = J.mod("learning.core.persist")
    D.write_source_refs(paths, "run-adv", disposition="benign")
    learning_run_dir = paths.runs_dir / "run-adv"
    learning_run_dir.mkdir(parents=True, exist_ok=True)

    judge_doc = {"outcome": "survived", "defender_findings": [{
        "type": "lead-set", "subject_anchor": "l-001", "subject_topic": "coverage",
        "finding": "the holding system was never re-queried",
        "citations": [{"source": "investigation", "quote": "..."}]}]}
    written = persist.append_findings(judge_doc, "run-adv", "rule-5710", learning_run_dir,
                                      paths=paths)
    assert written == 1

    channel = D.channel_of(paths, "findings")
    row = D.pending(channel)[0]
    assert "run_id" in row, (
        "the shared writer emitted a row the shared gate indexes by a key it does not carry")
    assert "direction" in row, (
        "the shared writer emitted a row the shared gate indexes by a key it does not carry")

    agent = D.recording(D.committing("shared-writer"))
    assert J.mod("learning.author.drain").run_batch(
        cfg=D.cfg_for(paths, "findings", invoke_agent=agent)) == 0
    assert [r["finding_id"] for r in agent.calls[0]["rows"]] == [row["finding_id"]]
    assert not D.stuck_records(channel), (
        "the shared writer's own row took a tick to stuck.jsonl")
    assert json.dumps(row), "the row is not JSON-serialisable; the queue file is JSONL"
