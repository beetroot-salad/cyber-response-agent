"""#936 — the frontier-keyed lessons block survives the compaction fold, and the record says which push (or read) put a lesson in front of which agent."""
from __future__ import annotations

import re
import shutil

import json
from collections import Counter
from collections.abc import Callable
from pathlib import Path

import pytest

from defender.tests.support.runtime.state._1255_view import MODEL_AGENT, model_path

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import ToolReturnPart  # noqa: E402

from defender.tests.support.shared.contracts._fold_936 import (  # noqa: E402
    CLASS_LESSON,
    CLASS_SELECTOR,
    FOLD_HEADER,
    FOLDING_DOC,
    IDENT_SELECTOR,
    LEAD_ONLY_BLOCK,
    LOGINUID_LESSON,
    LOGINUID_SELECTOR,
    OPEN_LOGINUID_BLOCK,
    SECOND_LOOP,
    WRITE_RETURN_HEADER,
    _rows,
)
from defender.tests.support.learning.retrieval._lessons_corpus import _write_lesson  # noqa: E402
from defender.tests.support.storage._session_store_705 import StoreFault, sql, store_factory  # noqa: E402
from defender.tests.e2e._replay_harness import (  # noqa: E402
    DEFENDER,
    GOLDEN,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

pytestmark = pytest.mark.e2e

# the planted tree, and the run

_NOT_MIRRORED = frozenset({
    ".venv", "__pycache__", "tests", "fixtures-e2e", "lessons",
})


def _planted_defender(root: Path, *, corpus: bool = True) -> tuple[Path, Path]:
    """A defender tree the run reads (the #1003 `defender_dir` seam) and the agent tree its
    tenant publishes (`drive(agent=)`, #1108 P4 A8). Returns `(tree, agent)`; the run's corpus is
    `agent / "lessons"` (O2: a run reads its run copy's lessons, never the product tree's), the
    fixture tenant's agent content without its own lessons. The product tree has no `lessons/`."""
    from defender.tests.support.tenancy._tenants1106 import FIXTURE_AGENT

    tree = root / "repo" / "defender"
    tree.mkdir(parents=True)
    for entry in DEFENDER.iterdir():
        if entry.name in _NOT_MIRRORED:
            continue
        (tree / entry.name).symlink_to(entry)
    agent = root / "golden-936" / "agent"
    shutil.copytree(FIXTURE_AGENT, agent, symlinks=True)
    shutil.rmtree(agent / "lessons", ignore_errors=True)
    if corpus:
        (agent / "lessons").mkdir()
    return tree, agent


def _reads(run_dir: Path, n: int) -> list[Turn]:
    return [Turn(tool_calls=[("read_file", {"path": model_path(run_dir / "alert.json", run_dir=run_dir)})])
            for _ in range(n)]


def _frontier_rows(store) -> list[tuple[int, int, str]]:
    """Every synthesized row as `(id, seq, user-prompt text)`, straight out of the file."""
    out = []
    for rid, seq, payload in sql(
        store, "SELECT m.id, m.seq, p.payload FROM message m JOIN message_payload p "
               "ON p.message_id = m.id WHERE m.synthesized = 1 ORDER BY m.id"):
        body = json.loads(payload)
        out.append((rid, seq, body["parts"][0]["content"]))
    return out


def _append_returns(store) -> list[str]:
    """What MAIN's `append_block` calls returned, in order, off the store's analysis render
    (the `send` render has displaced them — that is the whole issue)."""
    from defender.runtime import session_store as ss

    session_id = sql(store, "SELECT session_id FROM session ORDER BY rowid")[0][0]
    out = []
    for message in ss.hydrate(store, session_id, role="analysis"):
        for part in getattr(message, "parts", []):
            if isinstance(part, ToolReturnPart) and part.tool_name == "append_block":
                out.append(str(part.content))
    return out


def _fold_run(tmp_path: Path, monkeypatch, *, tree: tuple[Path, Path],
              turns: Callable[[Path], list[Turn]], fault: StoreFault | None = None,
              doc: str = FOLDING_DOC):
    """One driven run under compaction on a document that folds on its first render.
    `turns` is called with the materialized run dir so a script can name its own alert."""
    monkeypatch.setenv("DEFENDER_COMPACTION", "1")
    rd = materialize(tmp_path, GOLDEN, run_id='fold-936')
    (rd / "investigation.md").write_text(doc, encoding="utf-8")
    opened: list = []
    replay = ReplayFn(turns(rd))
    defender_dir, agent = tree
    result = drive(rd, run_id="fold-936", main=replay, defender_dir=defender_dir, agent=agent,
                   store_factory=store_factory(tmp_path, sink=opened, fault=fault))
    return rd, replay, opened[0], result


def _expected_hits(doc: str, corpus: Path) -> list[str]:
    """The lesson names the shared derivation must produce for `doc` — the same two calls
    `_frontier_recall` makes, over the same corpus."""
    from defender.runtime.lessons_engine.lessons_frontier import match_lessons
    from defender.skills.invlang.frontier import frontier_from_text

    return [h.name for h in match_lessons(frontier_from_text(doc), corpus)]


def _model_path(lesson: Path) -> str:
    """The block's hit line for a lesson of the run's corpus: the lesson named through the
    model view's fixed agent path (#1255, design rev 4 P1 outbound — "the lessons block in the
    fold frontier row (today an absolute realpath)"; #1108 P4: the corpus is the run copy's
    `agent/lessons`), never the host realpath. The line's own `- ` lead is part of the match: the
    planted tree is `<tmp>/golden-936/agent`, so a bare `/agent/lessons/…` is a substring of the
    host realpath too."""
    return f"- {MODEL_AGENT}/lessons/{lesson.name} — matched"


# O1 / O2 / O3 — the fold row carries the block


def test_the_fold_row_carries_the_block_the_whole_document_matched(tmp_path, monkeypatch):
    """O1 / O3 / M1 / M2: the synthesized frontier row is `record + "\\n\\n" + block`, where the block names the lesson the FULL document matched at mint —..."""
    from defender.runtime import compaction

    tree = _planted_defender(tmp_path)
    corpus = tree[1] / "lessons"
    lesson = _write_lesson(corpus, CLASS_LESSON, nodes=CLASS_SELECTOR)
    rd, replay, store, _ = _fold_run(
        tmp_path, monkeypatch, tree=tree, turns=lambda rd: _reads(rd, 3) + [Turn(text="done")])

    rows = _frontier_rows(store)
    assert rows, "no synthesized frontier row was minted — the fixture folded nothing"
    (_rid, seq, text), = rows
    assert seq == 1
    record = compaction.frontier_text(FOLDING_DOC, 1)
    assert text.startswith(record), "the record is no longer the head of the frontier row"
    block = text[len(record):]
    assert block.startswith("\n\n"), f"the block is not separated from the record: {block[:40]!r}"
    assert _model_path(lesson) in block, (
        f"the frontier row carries no path for the lesson the document matched:\n{text}")
    assert str(lesson.resolve()) not in text, "the frontier row names the lesson's host path"
    assert FOLD_HEADER in block.strip().splitlines()[0], (
        f"the block's first line is not the fold header:\n{block.strip().splitlines()[0]}")
    assert WRITE_RETURN_HEADER not in text, (
        "the fold row carries the write-return header — the model is told a write moved "
        "the record when no write did")
    # the row is what MAIN sees, on every round after the fold
    assert replay.calls >= 2
    assert _model_path(lesson) in replay.seen[-1], (
        "the lesson path is in the store but not in the request MAIN received")


def test_the_fold_block_is_the_shared_derivation_top_three_and_lead_included(
    tmp_path, monkeypatch,
):
    """M1 / M4: with TWO slots open at mint against a corpus of three lessons (two match), the frontier row's block is byte-for-byte..."""
    from defender.runtime.lessons_engine.lessons_frontier import FOLD_LEAD, match_lessons, render
    from defender.skills.invlang.frontier import frontier_from_text

    tree = _planted_defender(tmp_path)
    corpus = tree[1] / "lessons"
    _write_lesson(corpus, CLASS_LESSON, nodes=CLASS_SELECTOR)
    _write_lesson(corpus, LOGINUID_LESSON, nodes=LOGINUID_SELECTOR)
    _write_lesson(corpus, "ident-open-936", nodes=IDENT_SELECTOR)
    doc = FOLDING_DOC + OPEN_LOGINUID_BLOCK
    expected = render(match_lessons(frontier_from_text(doc), corpus), lead=FOLD_LEAD)
    assert CLASS_LESSON in expected, "control: two hits"
    assert LOGINUID_LESSON in expected, "control: two hits"
    assert "history was folded" in FOLD_LEAD
    assert "matches now" in FOLD_LEAD
    assert "as it stands" in FOLD_LEAD
    assert "already been shown" not in FOLD_LEAD, "the lead must not claim a re-show"
    assert WRITE_RETURN_HEADER not in FOLD_LEAD

    rd, _replay, store, _ = _fold_run(
        tmp_path, monkeypatch, tree=tree, doc=doc,
        turns=lambda rd: _reads(rd, 2) + [Turn(text="done")])
    (_rid, _seq, text), = _frontier_rows(store)
    expected = expected.replace(str(corpus.resolve()), f"{MODEL_AGENT}/lessons")
    text, expected = (re.sub(r"run-[0-9a-f]{16}-", "run-<SALT>-", t) for t in (text, expected))
    assert text.endswith("\n\n" + expected), (
        f"the fold block is not the shared derivation:\n{text[-len(expected) - 200:]}")
    assert sorted(r["lesson_name"] for r in _rows(rd)) == sorted([CLASS_LESSON, LOGINUID_LESSON])


def test_a_second_boundary_re_derives_its_own_block_and_records_again(tmp_path, monkeypatch):
    """N3 / key flow 4 / O1 for every fold after the first"""
    from defender.runtime import compaction

    tree = _planted_defender(tmp_path)
    corpus = tree[1] / "lessons"
    class_lesson = _write_lesson(corpus, CLASS_LESSON, nodes=CLASS_SELECTOR)
    loginuid_lesson = _write_lesson(corpus, LOGINUID_LESSON, nodes=LOGINUID_SELECTOR)
    assert compaction.fold_boundary(FOLDING_DOC + SECOND_LOOP) == 2, "control: loop 2 closes"

    rd, replay, store, result = _fold_run(
        tmp_path, monkeypatch, tree=tree,
        turns=lambda rd: _reads(rd, 2) + [
            Turn(tool_calls=[("append_block", {"text": SECOND_LOOP})]),
            *_reads(rd, 1),
            Turn(text="done"),
        ])

    assert result["exit_reason"] is None, result
    rows = _frontier_rows(store)
    assert [seq for _id, seq, _t in rows] == [1, 2], rows
    (_r1, _s1, first), (_r2, _s2, second) = rows
    assert _model_path(class_lesson) in first
    assert _model_path(loginuid_lesson) not in first, "loop 2 had not opened loginuid yet"
    assert _model_path(loginuid_lesson) in second, (
        "boundary 2 re-used boundary 1's block — the lesson loop 2 opened never reached MAIN")
    assert second.count(FOLD_HEADER) == 1
    assert (rd / "investigation.md").read_text(encoding="utf-8").endswith(SECOND_LOOP), (
        "control: the append that closes loop 2 was refused")
    assert Counter(r["lesson_name"] for r in _rows(rd)) == Counter(
        {CLASS_LESSON: 2, LOGINUID_LESSON: 1}), _rows(rd)
    assert all(r["kind"] == "push" for r in _rows(rd))
    # the closing write's return is OFF every path after fold 2 (`_append_returns` cannot see
    # it — which is the point), so it is read straight out of the file
    returns = [
        part["content"] for (payload,) in sql(store, "SELECT payload FROM message_payload")
        for part in json.loads(payload).get("parts", [])
        if part.get("part_kind") == "tool-return" and part.get("tool_name") == "append_block"
    ]
    assert len(returns) == 1, returns
    assert WRITE_RETURN_HEADER not in str(returns[0]), (
        "the loop-closing write's return carried a block the fold displaced before MAIN read it")


def test_a_fold_that_matches_no_lesson_mints_the_row_and_records_nothing(tmp_path, monkeypatch):
    """O6 negative control, paired with the test above"""
    tree = _planted_defender(tmp_path)
    corpus = tree[1] / "lessons"
    _write_lesson(corpus, "ident-open-936", nodes=IDENT_SELECTOR)
    assert _expected_hits(FOLDING_DOC, corpus) == [], "the control must match nothing"
    rd, _replay, store, result = _fold_run(
        tmp_path, monkeypatch, tree=tree, turns=lambda rd: _reads(rd, 2) + [Turn(text="done")])

    assert result["exit_reason"] is None, result
    (_rid, _seq, text), = _frontier_rows(store)
    assert FOLD_HEADER not in text
    assert "ident-open-936" not in text
    assert _rows(rd) == []


# O4 — fail-open at the fold

def test_a_missing_corpus_fails_open_at_the_fold_and_says_so(tmp_path, monkeypatch, capsys):
    """O4 / M1: with no `lessons/` under the tree the run reads, the fold still mints its row and the run completes"""
    tree = _planted_defender(tmp_path, corpus=False)
    assert not (tree[1] / "lessons").exists()
    rd, _replay, store, result = _fold_run(
        tmp_path, monkeypatch, tree=tree, turns=lambda rd: _reads(rd, 2) + [Turn(text="done")])

    assert result["exit_reason"] is None, result
    (_rid, seq, text), = _frontier_rows(store)
    assert seq == 1
    assert FOLD_HEADER not in text
    assert _rows(rd) == []
    err = capsys.readouterr().err
    assert "no lessons corpus" in err, f"the fold disabled its lessons lane silently:\n{err[-2000:]}"
    # The corpus it looked for is the run's tenant agent root's (#1108 P4, O2), not the tree's.
    assert re.search(r"no lessons corpus at \S*/agent/lessons\b", err), (
        "the stderr line does not name the corpus it looked for")
    # M2: composed ONLY at mint. Three renders on this boundary, one corpus lookup — a fold
    # that derived on every render and gated only the rows would print this line per render.
    assert _replay.calls == 3
    assert err.count("no lessons corpus") == 1, (
        f"the fold looked for the corpus {err.count('no lessons corpus')} times on one boundary")


def test_a_malformed_lesson_beside_a_good_one_does_not_stop_the_mint(tmp_path, monkeypatch):
    """O4: a corpus-CONTENT fault — a lesson whose selector list is a scalar — at mint."""
    tree = _planted_defender(tmp_path)
    corpus = tree[1] / "lessons"
    good = _write_lesson(corpus, CLASS_LESSON, nodes=CLASS_SELECTOR)
    _write_lesson(corpus, "malformed-936", raw_nodes="not-a-list")
    rd, _replay, store, result = _fold_run(
        tmp_path, monkeypatch, tree=tree, turns=lambda rd: _reads(rd, 2) + [Turn(text="done")])

    assert result["exit_reason"] is None, result
    (_rid, _seq, text), = _frontier_rows(store)
    assert _model_path(good) in text
    assert "malformed-936" not in text
    assert [(r["lesson_name"], r["kind"]) for r in _rows(rd)] == [(CLASS_LESSON, "push")]


# O1 (second half) / O2 / C19 — the write-return lane after the fold

def test_the_write_return_lane_keeps_pushing_after_the_fold_only_when_the_top_three_move(
    tmp_path, monkeypatch,
):
    """O1 / O2 / C19, at the intersection of the two lanes."""
    tree = _planted_defender(tmp_path)
    corpus = tree[1] / "lessons"
    class_lesson = _write_lesson(corpus, CLASS_LESSON, nodes=CLASS_SELECTOR)
    loginuid_lesson = _write_lesson(corpus, LOGINUID_LESSON, nodes=LOGINUID_SELECTOR)
    rd, replay, store, result = _fold_run(
        tmp_path, monkeypatch, tree=tree,
        turns=lambda rd: _reads(rd, 2) + [
            Turn(tool_calls=[("append_block", {"text": LEAD_ONLY_BLOCK})]),
            Turn(tool_calls=[("append_block", {"text": OPEN_LOGINUID_BLOCK})]),
            Turn(text="done"),
        ])

    assert result["exit_reason"] is None, result
    assert replay.calls == 5
    non_moving, moving = _append_returns(store)
    assert non_moving.startswith("appended ")
    assert CLASS_LESSON not in non_moving, (
        f"a write that moved nothing re-pushed after the fold:\n{non_moving}")
    assert WRITE_RETURN_HEADER in moving, f"the post-fold moving write returned no block:\n{moving}"
    assert _model_path(class_lesson) in moving
    assert _model_path(loginuid_lesson) in moving
    assert str(tmp_path) not in moving, "the write-return block names a host path"
    assert "run-knowledge" not in moving, "the write-return block names the run copy's host path"
    assert FOLD_HEADER not in moving, "the write return borrowed the fold header"
    # still one frontier row: the appends are inside boundary 1's loop 2
    assert [seq for _id, seq, _t in _frontier_rows(store)] == [1]
    rows = _rows(rd)
    assert all(r["kind"] == "push" and r["role"] == "main" for r in rows), rows
    assert Counter(r["lesson_name"] for r in rows) == Counter(
        {CLASS_LESSON: 2, LOGINUID_LESSON: 1}), (
        f"rows should be: fold(class) + write(class, loginuid); got {rows}")


# M3 — a mint that fails records nothing

def test_a_mint_that_fails_records_nothing(tmp_path, monkeypatch):
    """M3 / O6: the store's file is really corrupted right before the SECOND append — which, under compaction on a closing document, is the frontier mint..."""
    tree = _planted_defender(tmp_path)
    corpus = tree[1] / "lessons"
    _write_lesson(corpus, CLASS_LESSON, nodes=CLASS_SELECTOR)
    rd, replay, handle, result = _fold_run(
        tmp_path, monkeypatch, tree=tree, turns=lambda rd: _reads(rd, 2) + [Turn(text="done")],
        fault=StoreFault(on="append", after=1, mode="corrupt"))

    assert result["exit_reason"] == "StoreAppendError", result
    assert replay.calls == 0, "the model was asked a question after the mint failed"
    broken = handle.appends[-1]
    assert (broken.get("reason"), broken.get("seq")) == ("fold", 1), (
        f"the fault did not land on the frontier mint: {broken}")
    assert not (rd / "lessons_loaded.jsonl").exists(), (
        f"a mint that never landed recorded rows: {_rows(rd)}")
