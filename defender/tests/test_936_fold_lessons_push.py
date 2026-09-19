"""#936 — the frontier-keyed lessons block survives the compaction fold, and the record says
which push (or read) put a lesson in front of which agent.

The live fold is the store-backed one: `driver._fold_decision` computes the invlang record and
`selection.render(fold=True, text=…)` mints ONE synthesized frontier row per boundary, parented
on the session's root. The send path collapses to `[root, frontier]`, so every displaced turn —
including the `append_block` return that carried #919's lessons block — is unreachable, and the
stateless suppression gate in `_frontier_recall` never re-pushes what the model no longer holds.
The record made it worse: the push had written `lessons_loaded.jsonl` rows, so `trace_lesson`
reported the lesson in context for a run whose model could not see it.

What this file pins (the design's obligations, by name in each docstring):

  * O1/O2/O3 — the frontier row carries a lessons block derived from the FULL document at
    mint, under a fold-specific header, after the record, once per boundary.
  * O4 — a missing corpus or a corpus-content fault never stops the mint; the missing corpus
    is loud on stderr.
  * O5/O8 — every `lessons_loaded.jsonl` row carries `kind` (`read` | `push`) and `role`; the
    legacy `{lesson_name, ts}` row still reads.
  * O6 — the fold records one `push` row per matched lesson, once per mint, none on a reuse
    round, none when the mint failed.
  * O7/O9 — `trace_lesson` prints an `evidence` column from the closed vocabulary
    `{read, push, indirect, unknown}` and a fourth index column counting MAIN reads.
  * M4 — `lessons_frontier.render(hits, *, lead=…)`; the CLI's default header is untouched.

The end-to-end scenarios drive the real `run_investigation` loop through the replay harness
under `DEFENDER_COMPACTION=1` with a planted defender tree (the #1003 seam) whose `lessons/`
corpus is this file's own, so every lesson path in a rendered row is one the test wrote. The
fixture document's open slot sits AFTER the loop-2 lead row on purpose: `_frontier_through`
cuts the record there, so a block derived from the RECORD finds nothing and only a block
derived from the whole document names the lesson.

RED AGAINST HEAD IS THE EXPECTED STATE: the fold mints a record with no block, rows carry no
`kind`/`role`, `render` takes no `lead`, and `trace_lesson` prints three columns.
"""
from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import ToolReturnPart  # noqa: E402

from defender.tests._fold_936 import (  # noqa: E402
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
from defender.tests._lessons_corpus import _write_lesson  # noqa: E402
from defender.tests._session_store_705 import StoreFault, sql, store_factory  # noqa: E402
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
    ".venv", "__pycache__", "tests", "fixtures-e2e", "run-visualizations", "lessons",
})


def _planted_defender(root: Path, *, corpus: bool = True) -> Path:
    """A defender tree the run reads (the #1003 `defender_dir` seam): every top-level entry of
    this checkout symlinked EXCEPT `lessons/`, which is created empty here — or not at all,
    for the missing-corpus arm — so the only lessons a run can match are the ones a test
    wrote. `<root>/repo/defender`, because `record_lesson_load.lesson_name` keys on the
    grandparent being `defender` and a row is the observable half of this spec."""
    tree = root / "repo" / "defender"
    tree.mkdir(parents=True)
    for entry in DEFENDER.iterdir():
        if entry.name in _NOT_MIRRORED:
            continue
        (tree / entry.name).symlink_to(entry)
    if corpus:
        (tree / "lessons").mkdir()
    return tree


def _reads(run_dir: Path, n: int) -> list[Turn]:
    return [Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})])
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


def _fold_run(tmp_path: Path, monkeypatch, *, tree: Path,
              turns: Callable[[Path], list[Turn]], fault: StoreFault | None = None,
              doc: str = FOLDING_DOC):
    """One driven run under compaction on a document that folds on its first render.
    `turns` is called with the materialized run dir so a script can name its own alert."""
    monkeypatch.setenv("DEFENDER_COMPACTION", "1")
    rd = materialize(tmp_path, GOLDEN)
    (rd / "investigation.md").write_text(doc, encoding="utf-8")
    opened: list = []
    replay = ReplayFn(turns(rd))
    result = drive(rd, run_id="fold-936", main=replay, defender_dir=tree,
                   store_factory=store_factory(tmp_path, sink=opened, fault=fault))
    return rd, replay, opened[0], result


def _expected_hits(doc: str, corpus: Path) -> list[str]:
    """The lesson names the shared derivation must produce for `doc` — the same two calls
    `_frontier_recall` makes, over the same corpus."""
    from defender.scripts.lessons.lessons_frontier import match_lessons
    from defender.skills.invlang.frontier import frontier_from_text

    return [h.name for h in match_lessons(frontier_from_text(doc), corpus)]


# O1 / O2 / O3 — the fold row carries the block

def test_the_fixture_folds_and_matches_only_over_the_whole_document(tmp_path):
    """Positive control for everything below, executed rather than assumed: the document
    folds through loop 1, the corpus lesson matches the WHOLE document, and the RECORD the
    fold builds matches nothing — which is what makes "derived over the full document"
    (M1) a different observable from "derived over the record"."""
    from defender.runtime import compaction

    corpus = _planted_defender(tmp_path) / "lessons"
    _write_lesson(corpus, CLASS_LESSON, nodes=CLASS_SELECTOR)

    assert compaction.fold_boundary(FOLDING_DOC) == 1
    assert _expected_hits(FOLDING_DOC, corpus) == [CLASS_LESSON]
    record = compaction.frontier_text(FOLDING_DOC, 1)
    assert "v-006|process|??" not in record, "the record cut did not fall before the open slot"
    assert _expected_hits(record, corpus) == [], "the record alone must match nothing"
    assert FOLD_HEADER not in record, (
        "the fold-header substring this file pins already occurs in the record head — it "
        "would not discriminate the block from the record")


def test_the_fold_row_carries_the_block_the_whole_document_matched(tmp_path, monkeypatch):
    """O1 / O3 / M1 / M2: the synthesized frontier row is `record + "\\n\\n" + block`, where the
    block names the lesson the FULL document matched at mint — the one the record cut
    excludes — under the fold's own header and not the write-return one. Asserted on the
    stored row and on the request MAIN actually received, because O1 is about what is in
    the model's rendered history, not what a helper returned."""
    from defender.runtime import compaction

    tree = _planted_defender(tmp_path)
    lesson = _write_lesson(tree / "lessons", CLASS_LESSON, nodes=CLASS_SELECTOR)
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
    assert str(lesson.resolve()) in block, (
        f"the frontier row carries no path for the lesson the document matched:\n{text}")
    assert FOLD_HEADER in block.strip().splitlines()[0], (
        f"the block's first line is not the fold header:\n{block.strip().splitlines()[0]}")
    assert WRITE_RETURN_HEADER not in text, (
        "the fold row carries the write-return header — the model is told a write moved "
        "the record when no write did")
    # the row is what MAIN sees, on every round after the fold
    assert replay.calls >= 2
    assert str(lesson.resolve()) in replay.seen[-1], (
        "the lesson path is in the store but not in the request MAIN received")


def test_the_fold_block_is_the_shared_derivation_top_three_and_lead_included(
    tmp_path, monkeypatch,
):
    """M1 / M4: with TWO slots open at mint against a corpus of three lessons (two match),
    the frontier row's block is byte-for-byte `render(match_lessons(frontier_from_text(doc),
    corpus), lead=FOLD_LEAD)` — the same top-k, the same ranking, the same lead the fold
    is documented to use. A fold that derived with its own `top_k`, or its own corpus, or a
    lead that does not tell the model its history was folded and this is what the record
    matches NOW (not a re-show of what it was shown — the block is derived fresh and can name
    a lesson it never saw), differs here and nowhere else in this file: every other scenario
    matches at most one lesson at mint."""
    from defender.scripts.lessons.lessons_frontier import FOLD_LEAD, match_lessons, render
    from defender.skills.invlang.frontier import frontier_from_text

    tree = _planted_defender(tmp_path)
    corpus = tree / "lessons"
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
    assert text.endswith("\n\n" + expected), (
        f"the fold block is not the shared derivation:\n{text[-len(expected) - 200:]}")
    assert sorted(r["lesson_name"] for r in _rows(rd)) == sorted([CLASS_LESSON, LOGINUID_LESSON])


def test_a_second_boundary_re_derives_its_own_block_and_records_again(tmp_path, monkeypatch):
    """N3 / key flow 4 / O1 for every fold after the first: boundary 2 mints a FRESH row
    from the document as it stands then — naming the lesson loop 2 opened, which boundary
    1's row could not — and records a fresh set of push rows. A fold that cached boundary
    1's block in the processor would show the loop-2 lesson to no one and record nothing
    at the second mint."""
    from defender.runtime import compaction

    tree = _planted_defender(tmp_path)
    class_lesson = _write_lesson(tree / "lessons", CLASS_LESSON, nodes=CLASS_SELECTOR)
    loginuid_lesson = _write_lesson(tree / "lessons", LOGINUID_LESSON, nodes=LOGINUID_SELECTOR)
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
    assert str(class_lesson.resolve()) in first
    assert str(loginuid_lesson.resolve()) not in first, "loop 2 had not opened loginuid yet"
    assert str(loginuid_lesson.resolve()) in second, (
        "boundary 2 re-used boundary 1's block — the lesson loop 2 opened never reached MAIN")
    assert second.count(FOLD_HEADER) == 1
    assert (rd / "investigation.md").read_text(encoding="utf-8").endswith(SECOND_LOOP), (
        "control: the append that closes loop 2 was refused")
    # fold 1 (class) + fold 2 (class, loginuid). NOT the write that closed loop 2 and opened
    # loginuid: under compaction its return is displaced by fold 2 at the very next render,
    # before MAIN reads it, so the lane withholds its block and records nothing — a row there
    # would say loginuid was in front of MAIN one round before it was, off a return it never
    # saw. Every push row here is one the model was actually shown.
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


def test_one_frontier_row_and_one_push_row_per_lesson_across_the_rounds_on_a_boundary(
    tmp_path, monkeypatch,
):
    """O2 / O6 / M3: several rounds render on boundary 1, and the boundary has exactly ONE
    frontier row and exactly ONE `push` row per matched lesson — the reuse rounds neither
    re-mint nor re-record. Rows carry `kind == "push"` and `role == "main"` (O5)."""
    tree = _planted_defender(tmp_path)
    _write_lesson(tree / "lessons", CLASS_LESSON, nodes=CLASS_SELECTOR)
    rd, replay, store, _ = _fold_run(
        tmp_path, monkeypatch, tree=tree, turns=lambda rd: _reads(rd, 5) + [Turn(text="done")])

    assert replay.calls == 6, "the control needs several rounds after the fold"
    assert [seq for _id, seq, _t in _frontier_rows(store)] == [1], (
        "boundary 1 was minted more than once (or not at all)")
    rows = _rows(rd)
    assert [r["lesson_name"] for r in rows] == [CLASS_LESSON], (
        f"expected exactly one push row for the one matched lesson, got {rows}")
    assert rows[0]["kind"] == "push"
    assert rows[0]["role"] == "main"
    # the block appears ONCE in the last request — one row, not one block per round
    assert replay.seen[-1].count(FOLD_HEADER) == 1


def test_a_fold_that_matches_no_lesson_mints_the_row_and_records_nothing(tmp_path, monkeypatch):
    """O6 negative control, paired with the test above: the same closing document against a
    corpus whose one lesson keys on a slot nothing here opens. The frontier row still mints
    (the fold is not conditional on lessons), it carries no block, and no row is written —
    a `push` row with no block behind it is the lie the issue is about."""
    tree = _planted_defender(tmp_path)
    _write_lesson(tree / "lessons", "ident-open-936", nodes=IDENT_SELECTOR)
    assert _expected_hits(FOLDING_DOC, tree / "lessons") == [], "the control must match nothing"
    rd, _replay, store, result = _fold_run(
        tmp_path, monkeypatch, tree=tree, turns=lambda rd: _reads(rd, 2) + [Turn(text="done")])

    assert result["exit_reason"] is None, result
    (_rid, _seq, text), = _frontier_rows(store)
    assert FOLD_HEADER not in text
    assert "ident-open-936" not in text
    assert _rows(rd) == []


# O4 — fail-open at the fold

def test_a_missing_corpus_fails_open_at_the_fold_and_says_so(tmp_path, monkeypatch, capsys):
    """O4 / M1: with no `lessons/` under the tree the run reads, the fold still mints its row
    and the run completes; the row has no block, no row is recorded, and stderr carries the
    "no lessons corpus" line the write-return lane already prints — the shared derivation
    brings the loud-empty along by construction. Positive control on the same address: the
    corpus-present tests above, whose row carries the block."""
    tree = _planted_defender(tmp_path, corpus=False)
    assert not (tree / "lessons").exists()
    rd, _replay, store, result = _fold_run(
        tmp_path, monkeypatch, tree=tree, turns=lambda rd: _reads(rd, 2) + [Turn(text="done")])

    assert result["exit_reason"] is None, result
    (_rid, seq, text), = _frontier_rows(store)
    assert seq == 1
    assert FOLD_HEADER not in text
    assert _rows(rd) == []
    err = capsys.readouterr().err
    assert "no lessons corpus" in err, f"the fold disabled its lessons lane silently:\n{err[-2000:]}"
    assert str(tree / "lessons") in err, "the stderr line does not name the corpus it looked for"
    # M2: composed ONLY at mint. Three renders on this boundary, one corpus lookup — a fold
    # that derived on every render and gated only the rows would print this line per render.
    assert _replay.calls == 3
    assert err.count("no lessons corpus") == 1, (
        f"the fold looked for the corpus {err.count('no lessons corpus')} times on one boundary")


def test_a_malformed_lesson_beside_a_good_one_does_not_stop_the_mint(tmp_path, monkeypatch):
    """O4: a corpus-CONTENT fault — a lesson whose selector list is a scalar — at mint. The
    row mints, the good lesson is in the block, the bad one is not, and only the good one is
    recorded. No REAL fault reaches the derivation's `except` on this box: `iter_lessons`
    warn-skips an undecodable file or a directory, `match_loaded` drops a mis-shaped
    selector, `frontier_from_text` never raises, and the process runs as root so an
    unreadable directory cannot be induced — so the raise arm is pinned by the corpus-missing
    case above and this content fault only."""
    tree = _planted_defender(tmp_path)
    good = _write_lesson(tree / "lessons", CLASS_LESSON, nodes=CLASS_SELECTOR)
    _write_lesson(tree / "lessons", "malformed-936", raw_nodes="not-a-list")
    rd, _replay, store, result = _fold_run(
        tmp_path, monkeypatch, tree=tree, turns=lambda rd: _reads(rd, 2) + [Turn(text="done")])

    assert result["exit_reason"] is None, result
    (_rid, _seq, text), = _frontier_rows(store)
    assert str(good.resolve()) in text
    assert "malformed-936" not in text
    assert [(r["lesson_name"], r["kind"]) for r in _rows(rd)] == [(CLASS_LESSON, "push")]


# O1 (second half) / O2 / C19 — the write-return lane after the fold

def test_the_write_return_lane_keeps_pushing_after_the_fold_only_when_the_top_three_move(
    tmp_path, monkeypatch,
):
    """O1 / O2 / C19, at the intersection of the two lanes. After the fold MAIN appends a
    fenced lead row (moves nothing — the frontier-equality limb, not the fence shortcut)
    and then a vertex with an open `attrs.loginuid` (moves the top three). The first return
    carries no block and records nothing; the second carries the write-return block naming
    both lessons and records both. Together with the fold's own mint the file holds exactly
    two `push` rows for the class lesson and one for the loginuid lesson — the fold and the
    write derive from the same document, so the write's "was" shape IS what the fold showed."""
    tree = _planted_defender(tmp_path)
    class_lesson = _write_lesson(tree / "lessons", CLASS_LESSON, nodes=CLASS_SELECTOR)
    loginuid_lesson = _write_lesson(tree / "lessons", LOGINUID_LESSON, nodes=LOGINUID_SELECTOR)
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
    assert str(class_lesson.resolve()) in moving
    assert str(loginuid_lesson.resolve()) in moving
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
    """M3 / O6: the store's file is really corrupted right before the SECOND append — which,
    under compaction on a closing document, is the frontier mint itself (the first append is
    the root row; the fake's log proves the broken append carried `reason="fold"`). The run
    stops through the handled `StoreAppendError` exit and no `push` row exists: the record is
    the composer's after-commit action (`selection.Composer`), which the mint runs only once
    the row has landed. Positive control: the reuse test above, where the same corpus and
    document DO record."""
    tree = _planted_defender(tmp_path)
    _write_lesson(tree / "lessons", CLASS_LESSON, nodes=CLASS_SELECTOR)
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
