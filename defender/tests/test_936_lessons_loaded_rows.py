"""#936, the unit half — every `lessons_loaded.jsonl` row says `kind` and `role`, `render`
takes a lead, `trace_lesson` reads the closed evidence vocabulary, and SKILL.md names the
fold push. No driver and no runtime extra: these run on every box, including one that skips
`e2e`. The fold itself — the frontier row carrying the block, the record written after the
mint — is `test_936_fold_lessons_push.py`. Obligations by name in each docstring
(O5/O7/O8/O9, M4, O3); the fixtures are `_fold_936`.
"""
from __future__ import annotations

import json
from pathlib import Path

from defender.tests._by_path import load_trace_lesson
from defender.tests._fold_936 import (
    CLASS_LESSON,
    CLASS_SELECTOR,
    EVIDENCE_VOCABULARY,
    FOLDING_DOC,
    WRITE_RETURN_HEADER,
    _rows,
)
from defender.tests._lessons_corpus import _main_deps, _write_lesson

DEFENDER = Path(__file__).resolve().parents[1]


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


def test_a_curator_read_carries_its_own_role_not_a_two_way_guess(tmp_path):
    """O5: the row's `role` is the deps' `AgentRole` value for EVERY role, not "gather or
    else main". The curator's `lesson_read` (CORPUS_AUTHOR deps, the wider corpora) is the
    third reader of `_gated_read`, and a two-way guess records it as MAIN — which
    `trace_lesson` would then lift to `read`."""
    from defender.learning.author.lesson_read import _tool_lesson_read
    from defender.runtime.agent_role import AgentRole
    from defender.tests._curator_scene import curator_deps, curator_scene

    scene = curator_scene(tmp_path)
    (scene.corpus / "curated-936.md").write_text(
        "---\nname: curated-936\n---\nlesson body\n", encoding="utf-8")
    deps = curator_deps(scene, run_verify=lambda *a, **kw: "")
    assert deps.role is AgentRole.CORPUS_AUTHOR, "control: the deps are the curator's"

    assert "lesson body" in _tool_lesson_read(deps, "defender/lessons/curated-936.md")
    rows = _rows(deps.run_dir)
    assert [(r["lesson_name"], r["kind"], r["role"]) for r in rows] == [
        ("curated-936", "read", "corpus_author")], rows


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
    # in context through a push; its only MAIN read predates `created_at` and must not count
    _mk_run(runs, "case-stale-read", [
        _row("L", ts="2026-06-01T00:00:00+00:00", kind="read", role="main"),
        _row("L", kind="push", role="main"), _row("M", kind="push", role="main")])

    tl = _tl()
    rc = tl.main(["--all", "--lessons-dir", str(tmp_path / "lessons"), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    assert sorted(cap.out.splitlines()) == ["L\td\t4\t1", "M\td\t4\t0"], (
        "the fourth column counts MAIN reads among QUALIFYING rows, not any MAIN read ever")


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
    # UNHASHABLE, each on its own so neither masks the other: the natural `x in {...}`
    # membership test raises `TypeError` on a list, and a traceback loses the whole walk
    _mk_run(runs, "list-kind", [_row("L", kind=["read"], role="main")])
    _mk_run(runs, "list-role", [_row("L", kind="read", role=["main"])])

    tl = _tl()
    rc = tl.main(["L", "--lessons-dir", str(tmp_path / "lessons"), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    lines = cap.out.splitlines()
    assert len(lines) == 10, f"a row was forged or lost:\n{cap.out}"
    for echoed in ("FORGED", "forged", "decisive"):
        assert echoed not in cap.out, f"the row's own bytes reached the TSV: {echoed!r}"
    cells = {ln.split("\t")[0]: ln.split("\t") for ln in lines[1:]}
    assert all(len(c) == 4 for c in cells.values()), cells
    assert cells["clean"][3] == "read"
    for case in ("tab-kind", "newline-kind", "word-kind", "int-kind", "list-kind"):
        assert cells[case][3] == "unknown", (case, cells[case])
    for case in ("tab-role", "newline-role", "list-role"):
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
    section = " ".join(text[start:end].split())  # the paragraphs are hard-wrapped
    assert "Two pushes" not in section, "SKILL.md still describes two pushes"
    assert "fold" in section.lower(), "SKILL.md §Lessons does not name the fold push"
    assert "keyed on the record" in section.lower(), (
        "SKILL.md does not say the fold push is keyed on the record (like push 2, not the alert)")
    assert "unchanged since the fold" in section.lower(), (
        "SKILL.md does not tell the model \"no block\" after a fold means unchanged since it")
