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

from defender.tests._by_path import load_trace_lesson  # noqa: E402
from defender.tests._lessons_corpus import _main_deps, _write_lesson  # noqa: E402
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

# documents

#: `test_store_driver_705._CLOSED_LOOP_INVLANG`, transcribed rather than imported (importing
#: a collected module loads it twice in one session — `_lessons_corpus` explains). Loop 1 is
#: CLOSED with a resolved lead and loop 2 is open, so `compaction.fold_boundary` reads 1 and
#: `driver._fold_decision` authorizes a fold on the first render.
CLOSED_LOOP = """```invlang
:L findings [id|loop|name|target|tests|system|window]
l-001|1|raw-auth|v-001||elastic|w

:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-003|v-001|2026-05-01T10:11:00Z|siem-event:wazuh|outcome=success
```

```invlang
:T close
loop 1
```

```invlang
:L findings [id|loop|name|target|tests|system|window]
l-005|2|cmdb-ip|v-006||cmdb|w
```
"""

#: A `process` vertex whose class is the bare open marker — the slot `CLASS_LESSON` keys on.
#: Appended AFTER the loop-2 lead, so it lies past the record cut (see the module docstring).
OPEN_CLASS_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-006|process|??|nc[pid=4242]|image=/usr/bin/nc
```
"""

#: A second `process` vertex with an open `attrs.loginuid` — the append that MOVES the top
#: three after the fold (a new slot, a new lesson).
OPEN_LOGINUID_BLOCK = """
```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-007|process|nc|nc[pid=4243]|loginuid=??;image=/usr/bin/nc
```
"""

#: A fenced block that moves NOTHING on the frontier: a lead row opens no slot and no
#: contract. Fenced on purpose — prose never reaches the frontier-equality limb of the gate,
#: a fence does, so this is the non-moving write C19 is actually about.
LEAD_ONLY_BLOCK = """
```invlang
:L findings [id|loop|name|target|tests|system|window]
l-006|2|cmdb-host|v-001||cmdb|w
```
"""

FOLDING_DOC = CLOSED_LOOP + OPEN_CLASS_BLOCK

CLASS_LESSON = "class-open-936"
LOGINUID_LESSON = "loginuid-open-936"
CLASS_SELECTOR = ("type: process, slot: class",)
LOGINUID_SELECTOR = ("type: process, slot: attrs.loginuid",)
#: A selector NO document in this file opens — the "matches nothing" corpus.
IDENT_SELECTOR = ("type: identity, slot: ident",)

#: The write-return header, verbatim from `lessons_frontier.render`'s default lead — the one
#: the fold row must NOT carry (O3).
WRITE_RETURN_HEADER = "pushed because this write moved it"
#: A substring of the fold lead (design M4). Chosen so it is ABSENT from the record head
#: (`RESUME_RESTART_SHAPED` already says "no longer in the history"); the first test checks
#: that discrimination rather than assuming it.
FOLD_HEADER = "as it stands"

EVIDENCE_VOCABULARY = frozenset({"read", "push", "indirect", "unknown"})


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


def _rows(run_dir: Path) -> list[dict]:
    p = run_dir / "lessons_loaded.jsonl"
    if not p.is_file():
        return []
    return [json.loads(ln) for ln in p.read_text(encoding="utf-8").splitlines() if ln.strip()]


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
    stops through the handled `StoreAppendError` exit and no `push` row exists: rows are
    written after `selection.render` returns, never before. Positive control: the reuse test
    above, where the same corpus and document DO record."""
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


# O5 / O8 — `kind` and `role` on every row

def test_a_read_row_names_the_kind_and_the_role_of_the_reader(tmp_path):
    """O5: a lesson opened through the real `_gated_read` (MAIN's `read_file`) leaves a row
    with `kind == "read"` and the reader's role; the same read through GATHER deps says
    `gather`. Without the role a row cannot say WHICH agent opened the lesson, and without
    the kind a runtime push and a model's choice read the same."""
    from defender.agents import GATHER_DEF
    from defender.runtime.agent_definition import bind
    from defender.runtime.tools import _tool_read_file

    main, run, dfn = _main_deps(tmp_path)
    corpus = dfn / "lessons"
    corpus.mkdir()
    lesson = _write_lesson(corpus, "read-936", nodes=CLASS_SELECTOR)
    gather = bind(GATHER_DEF, run, defender_dir=dfn)

    assert "lesson body" in _tool_read_file(main, str(lesson.resolve()))
    assert "lesson body" in _tool_read_file(gather, str(lesson.resolve()))
    rows = _rows(run)
    assert [(r["lesson_name"], r.get("kind"), r.get("role")) for r in rows] == [
        ("read-936", "read", "main"),
        ("read-936", "read", "gather"),
    ], rows
    assert [r["role"] for r in rows] == [main.role.value, gather.role.value]


def test_a_push_row_names_the_push_and_the_main_role(tmp_path):
    """O5: the write-return push (`_tool_append_block` → `_frontier_recall`) records
    `kind == "push"`, `role == "main"` — distinguishable from the read row on the same file
    by `kind`, which is the difference the issue asked for."""
    from defender.runtime.tools import _tool_append_block

    deps, run, dfn = _main_deps(tmp_path)
    corpus = dfn / "lessons"
    corpus.mkdir()
    _write_lesson(corpus, "pushed-936", nodes=CLASS_SELECTOR)

    out = _tool_append_block(deps, FOLDING_DOC)
    assert "pushed-936" in out, "positive control: the append should push the lesson"
    rows = _rows(run)
    assert [(r["lesson_name"], r.get("kind"), r.get("role")) for r in rows] == [
        ("pushed-936", "push", "main")], rows
    assert "ts" in rows[0]


# M4 — a header per push

def test_render_takes_a_lead_and_the_default_is_the_write_return_header(tmp_path):
    """M4: `render(hits)` still leads with the write-return sentence (the CLI and #919's pins
    are untouched); `render(hits, lead=…)` puts the given lead on line 1 and leaves the hit
    lines byte-identical; `render([], lead=…)` is still empty, since the fold gates "no
    block" on that falsiness exactly as `_frontier_recall` does."""
    from defender.scripts.lessons.lessons_frontier import match_lessons, render
    from defender.skills.invlang.frontier import frontier_from_text

    corpus = tmp_path / "defender" / "lessons"
    corpus.mkdir(parents=True)
    _write_lesson(corpus, CLASS_LESSON, nodes=CLASS_SELECTOR)
    hits = match_lessons(frontier_from_text(FOLDING_DOC), corpus)
    assert hits, "positive control: the fixture should match the lesson"

    default = render(hits)
    assert WRITE_RETURN_HEADER in default.splitlines()[0]
    custom = render(hits, lead="### Lessons — custom lead 936")
    assert custom.splitlines()[0] == "### Lessons — custom lead 936"
    assert custom.splitlines()[1:] == default.splitlines()[1:]
    assert WRITE_RETURN_HEADER not in custom
    assert render([], lead="### Lessons — custom lead 936") == ""


# O7 / O8 / O9 — `trace_lesson` reads the difference

def _tl():
    return load_trace_lesson("trace_lesson_936")


def _mk_lesson(lessons: Path, stem: str, *, created_at: str | None = None) -> Path:
    lessons.mkdir(parents=True, exist_ok=True)
    fm = f"name: {stem}\ndescription: d\n" + (f"created_at: {created_at}\n" if created_at else "")
    p = lessons / f"{stem}.md"
    p.write_text(f"---\n{fm}---\nbody\n", encoding="utf-8")
    return p


def _mk_run(runs: Path, name: str, rows: list[dict], *, disposition: str = "benign") -> Path:
    rd = runs / name
    rd.mkdir(parents=True)
    (rd / "report.md").write_text(f"---\ndisposition: {disposition}\n---\nbody\n", encoding="utf-8")
    (rd / "lessons_loaded.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return rd


def _row(lesson: str, ts: str = "2026-06-05T00:00:00+00:00", **extra) -> dict:
    return {"lesson_name": lesson, "ts": ts, **extra}


def _named(tmp_path: Path, capsys, lesson: str = "L") -> dict[str, list[str]]:
    """`trace_lesson <lesson>` over `<tmp>/lessons` and `<tmp>/runs`, as `{case_id: cells}`."""
    tl = _tl()
    rc = tl.main([lesson, "--lessons-dir", str(tmp_path / "lessons"),
                  "--runs-dir", str(tmp_path / "runs")])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    lines = cap.out.splitlines()
    assert [ln.startswith("#") for ln in lines] == [True] + [False] * (len(lines) - 1), lines
    return {ln.split("\t")[0]: ln.split("\t") for ln in lines[1:]}


def test_trace_names_the_evidence_class_behind_each_case(tmp_path, capsys):
    """O7 / O8: the per-case line gains a fourth column, `evidence`, that says what "in
    context" rests on — a MAIN `read`, a runtime `push`, a read by another role
    (`indirect`), or a legacy row that cannot say (`unknown`). A MAIN-read-only case and a
    push-only case must not render identically; a legacy `{lesson_name, ts}` row still
    counts (O8), it just says so."""
    _mk_lesson(tmp_path / "lessons", "L")
    runs = tmp_path / "runs"
    _mk_run(runs, "case-read", [_row("L", kind="read", role="main")])
    _mk_run(runs, "case-push", [_row("L", kind="push", role="main")])
    _mk_run(runs, "case-gather", [_row("L", kind="read", role="gather")])
    _mk_run(runs, "case-legacy", [_row("L")])

    cells = _named(tmp_path, capsys)
    assert set(cells) == {"case-read", "case-push", "case-gather", "case-legacy"}
    assert all(len(c) == 4 for c in cells.values()), cells
    assert [c[3] for c in (cells["case-read"], cells["case-push"],
                           cells["case-gather"], cells["case-legacy"])] == [
        "read", "push", "indirect", "unknown"]
    assert cells["case-read"][1:3] == cells["case-push"][1:3] == ["benign", "2026-06-05T00:00:00+00:00"], (
        "the control rows must differ in the evidence column ONLY")


def test_evidence_precedence_is_read_over_push_over_indirect_over_unknown(tmp_path, capsys):
    """O7: a case with mixed rows reports the strongest evidence it has, and only QUALIFYING
    rows count — a MAIN read from before the lesson's `created_at` is outside the window and
    cannot lift a push-only case to `read`."""
    _mk_lesson(tmp_path / "lessons", "L", created_at="2026-06-04")
    runs = tmp_path / "runs"
    legacy, gather = _row("L"), _row("L", kind="read", role="gather")
    push, main_read = _row("L", kind="push", role="main"), _row("L", kind="read", role="main")
    _mk_run(runs, "all-four", [legacy, gather, push, main_read])
    _mk_run(runs, "no-main-read", [legacy, gather, push])
    _mk_run(runs, "gather-only", [legacy, gather])
    _mk_run(runs, "stale-read", [
        _row("L", ts="2026-06-01T00:00:00+00:00", kind="read", role="main"), push])

    cells = _named(tmp_path, capsys)
    assert all(len(c) == 4 for c in cells.values()), cells
    assert {k: v[3] for k, v in cells.items()} == {
        "all-four": "read", "no-main-read": "push", "gather-only": "indirect",
        "stale-read": "push",
    }


def test_the_index_counts_cases_with_a_main_read_in_a_fourth_column(tmp_path, capsys):
    """O7: `--all` no longer folds every class into one count — the fourth column is the
    number of cases with a MAIN read, so a lesson that only ever reached models through
    pushes reads `N\\t0`. Legacy rows are `unknown`, not assumed reads."""
    _mk_lesson(tmp_path / "lessons", "L", created_at="2026-06-04")
    _mk_lesson(tmp_path / "lessons", "M", created_at="2026-06-04")
    runs = tmp_path / "runs"
    _mk_run(runs, "case-read", [_row("L", kind="read", role="main"), _row("M", kind="push", role="main")])
    _mk_run(runs, "case-push", [_row("L", kind="push", role="main"), _row("M", kind="read", role="gather")])
    _mk_run(runs, "case-legacy", [_row("L"), _row("M")])

    tl = _tl()
    rc = tl.main(["--all", "--lessons-dir", str(tmp_path / "lessons"), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    assert sorted(cap.out.splitlines()) == ["L\td\t3\t1", "M\td\t3\t0"]


def test_the_evidence_column_is_a_closed_vocabulary_whatever_the_row_carries(tmp_path, capsys):
    """O9: `lessons_loaded.jsonl` is a #1047 forgery universal, so a `kind` or `role` carrying
    a tab, a newline, or a word outside the vocabulary must reach the TSV as one of the four
    closed values — never its own bytes, never an extra column or row. Positive control on
    the same column: a clean `kind: read` row renders `read`."""
    _mk_lesson(tmp_path / "lessons", "L")
    runs = tmp_path / "runs"
    _mk_run(runs, "clean", [_row("L", kind="read", role="main")])
    _mk_run(runs, "tab-kind", [_row("L", kind="read\tFORGED", role="main")])
    _mk_run(runs, "newline-kind", [_row("L", kind="push\nforged\trow", role="main")])
    _mk_run(runs, "word-kind", [_row("L", kind="decisive", role="main")])
    _mk_run(runs, "tab-role", [_row("L", kind="read", role="main\tFORGED")])
    _mk_run(runs, "newline-role", [_row("L", kind="read", role="main\nforged")])
    _mk_run(runs, "int-kind", [_row("L", kind=7, role=["main"])])

    tl = _tl()
    rc = tl.main(["L", "--lessons-dir", str(tmp_path / "lessons"), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0
    lines = cap.out.splitlines()
    assert len(lines) == 8, f"a row was forged or lost:\n{cap.out}"
    for echoed in ("FORGED", "forged", "decisive"):
        assert echoed not in cap.out, f"the row's own bytes reached the TSV: {echoed!r}"
    cells = {ln.split("\t")[0]: ln.split("\t") for ln in lines[1:]}
    assert all(len(c) == 4 for c in cells.values()), cells
    assert cells["clean"][3] == "read"
    for case in ("tab-kind", "newline-kind", "word-kind", "int-kind"):
        assert cells[case][3] == "unknown", (case, cells[case])
    for case in ("tab-role", "newline-role"):
        # a read by a role that is not MAIN's spelling: either "not MAIN" or "cannot say" is
        # honest, echoing the role is not
        assert cells[case][3] in {"indirect", "unknown"}, (case, cells[case])
    assert set(c[3] for c in cells.values()) <= EVIDENCE_VOCABULARY


# O3 — the prose contract

def test_skill_md_names_the_fold_push_and_what_no_block_means_after_it():
    """O3 / M4: SKILL.md §Lessons tells the model what the fold block is — a third push,
    keyed on the record, re-showing the current top three because the turns that carried
    them are gone — and that "no block" after a fold means unchanged since the fold showed
    it. Pinned on distinctive substrings, not the sentence: the old "Two pushes" framing must
    be gone and the fold must be named where the pushes are enumerated."""
    text = (DEFENDER / "SKILL.md").read_text(encoding="utf-8")
    start = text.index("**Lessons.**")
    end = text.index("### GATHER", start)
    section = text[start:end]
    assert "Two pushes" not in section, "SKILL.md still describes two pushes"
    assert "fold" in section.lower(), "SKILL.md §Lessons does not name the fold push"
    assert "since the fold" in section.lower(), (
        "SKILL.md does not tell the model what \"no block\" means after a fold")
