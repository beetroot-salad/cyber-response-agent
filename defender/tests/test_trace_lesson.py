"""Tests for defender/learning/trace_lesson.py — in-context-outcome traceability."""
from __future__ import annotations

import importlib.util
import json
import sys
from datetime import date, datetime, UTC
from pathlib import Path

TL_PATH = Path(__file__).resolve().parents[1] / "learning" / "ops" / "trace_lesson.py"


def _load():
    spec = importlib.util.spec_from_file_location("trace_lesson", TL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _mk_run(runs: Path, name: str, *, disposition: str, loads: list[dict]):
    rd = runs / name
    rd.mkdir(parents=True)
    (rd / "report.md").write_text(f"---\ndisposition: {disposition}\n---\nbody\n")
    (rd / "lessons_loaded.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in loads)
    )
    return rd


def test_in_context_cases_windows_on_created_at(tmp_path):
    tl = _load()
    runs = tmp_path / "runs"
    runs.mkdir()
    created = datetime(2026, 6, 4, tzinfo=UTC)
    _mk_run(runs, "caseA", disposition="benign",
            loads=[{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}])
    _mk_run(runs, "caseB", disposition="malicious",
            loads=[{"lesson_name": "L", "ts": "2026-06-01T00:00:00+00:00"}])
    _mk_run(runs, "caseC", disposition="benign",
            loads=[{"lesson_name": "OTHER", "ts": "2026-06-06T00:00:00+00:00"}])
    hits = tl.in_context_cases("L", created, runs)
    assert [(h.case_id, h.disposition) for h in hits] == [("caseA", "benign")]


def test_in_context_cases_dedups_per_case_keeps_earliest(tmp_path):
    tl = _load()
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="benign", loads=[
        {"lesson_name": "L", "ts": "2026-06-05T01:00:00+00:00"},
        {"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"},
    ])
    hits = tl.in_context_cases("L", None, runs)
    assert len(hits) == 1
    assert hits[0].loaded_at == "2026-06-05T00:00:00+00:00"


def test_earliest_load_is_chronological_not_lexicographic(tmp_path):
    """The earliest qualifying load is picked by parsed instant, not string order: a
    ``+09:00`` spelling of an earlier instant sorts lexicographically AFTER the canonical
    ``+00:00`` row that is chronologically later. Latent while both production writers go
    through ``now_iso()``'s canonical UTC; wrong the day a migration or hand-edit doesn't."""
    tl = _load()
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="benign", loads=[
        {"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"},
        {"lesson_name": "L", "ts": "2026-06-05T08:00:00+09:00"},
    ])
    hits = tl.in_context_cases("L", None, runs)
    assert [h.loaded_at for h in hits] == ["2026-06-05T08:00:00+09:00"]


def test_all_flattens_tab_and_newline_in_description(tmp_path, capsys):
    """The description column is LLM-authored; a tab or newline in it would forge a column
    or split the row, so the TSV flattens both (the ``lessons_fm._emit_match`` idiom)."""
    tl = _load()
    _mk_lesson(tmp_path / "lessons", "L",
               body_frontmatter='name: L\ndescription: "a\\tb\\nc"\ncreated_at: 2026-06-04')
    runs = tmp_path / "runs"
    runs.mkdir()

    rc = tl.main(["--all", "--lessons-dir", str(tmp_path / "lessons"), "--runs-dir", str(runs)])
    assert rc == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines == ["L\ta b c\t0"]


def test_in_context_cases_missing_runs_dir_is_empty(tmp_path):
    tl = _load()
    assert tl.in_context_cases("L", None, tmp_path / "nope") == []


def _mk_lesson(lessons: Path, stem: str, *, body_frontmatter: str) -> Path:
    lessons.mkdir(exist_ok=True)
    p = lessons / f"{stem}.md"
    p.write_text(f"---\n{body_frontmatter}\n---\nbody\n")
    return p


def test_parse_dt_normalizes_to_aware():
    tl = _load()
    naive = tl._parse_dt("2026-06-04T00:00:00")
    assert naive is not None
    assert naive.tzinfo is not None
    assert tl._parse_dt(date(2026, 6, 4)) == datetime(2026, 6, 4, tzinfo=UTC)
    assert tl._parse_dt("2026-06-04T00:00:00Z").tzinfo is not None
    assert tl._parse_dt(datetime(2026, 6, 4)).tzinfo is not None
    assert tl._parse_dt(123) is None


def _case_ids(out: str) -> list[str]:
    """The case-id column of ``trace_lesson <name>``'s per-hit TSV lines (the ``#`` header aside)."""
    return [ln.split("\t")[0] for ln in out.splitlines() if ln.strip() and not ln.startswith("#")]


def test_naive_created_at_does_not_crash_trace(tmp_path, capsys):
    """A tz-less created_at (LLM-authored, no offset → PyYAML naive datetime) must not
    raise TypeError against the always-aware hook timestamps.

    #584 SUPERSEDES the ``lesson_meta()`` call this used to make: the fold deletes that helper
    (``--all`` walks ``iter_lessons``; the single-lesson path keeps its own guarded read), so the
    property is re-pinned END TO END through ``main()`` — the seam a user actually drives — via the
    new ``--lessons-dir``. The windowing behavior is unchanged."""
    tl = _load()
    _mk_lesson(
        tmp_path / "lessons", "L",
        body_frontmatter="name: L\ndescription: d\ncreated_at: 2026-06-04T00:00:00",
    )
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="benign",
            loads=[{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}])

    rc = tl.main(["L", "--lessons-dir", str(tmp_path / "lessons"), "--runs-dir", str(runs)])
    out = capsys.readouterr().out
    assert rc == 0
    assert _case_ids(out) == ["caseA"]
    assert "caseA\tbenign" in out


def test_bare_date_created_at_windows_correctly(tmp_path, capsys):
    """`created_at: 2026-06-04` (PyYAML → date) is promoted to UTC midnight, not
    silently dropped — loads before it stay excluded.

    #584 SUPERSEDES the ``lesson_meta()`` call site (see the note on
    ``test_naive_created_at_does_not_crash_trace``); the windowing property is unchanged."""
    tl = _load()
    _mk_lesson(
        tmp_path / "lessons", "L",
        body_frontmatter="name: L\ndescription: d\ncreated_at: 2026-06-04",
    )
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "before", disposition="benign",
            loads=[{"lesson_name": "L", "ts": "2026-06-01T00:00:00+00:00"}])
    _mk_run(runs, "after", disposition="benign",
            loads=[{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}])

    rc = tl.main(["L", "--lessons-dir", str(tmp_path / "lessons"), "--runs-dir", str(runs)])
    assert rc == 0
    assert _case_ids(capsys.readouterr().out) == ["after"]


def test_lesson_identity_is_stem_not_frontmatter_name(tmp_path, capsys):
    """The hook records the file stem; matching must key on the stem even when the
    frontmatter name differs, else every recorded load is silently missed.

    #584 SUPERSEDES the ``lesson_meta()`` call site. The fold makes this test MORE load-bearing, not
    less: a ``Lesson(path, fm, raw, body)`` carries no ``.name``, so the obvious reach at the new
    loop header is ``lesson.fm.get("name")`` — which returns ``foo_bar`` here and misses every
    recorded load, silently reporting zero cases forever. Re-pinned through ``main()``, and pinned
    cross-module against ``record_lesson_load.lesson_name`` (the co-writer of the key) in
    ``test_corpus_fold_584.py::test_d23``."""
    tl = _load()
    _mk_lesson(
        tmp_path / "lessons", "foo-bar",
        body_frontmatter="name: foo_bar\ndescription: d",
    )
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="malicious",
            loads=[{"lesson_name": "foo-bar", "ts": "2026-06-05T00:00:00+00:00"}])

    rc = tl.main(["foo-bar", "--lessons-dir", str(tmp_path / "lessons"), "--runs-dir", str(runs)])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("# foo-bar")
    assert _case_ids(out) == ["caseA"]




def test_undecodable_report_degrades_to_unknown_disposition(tmp_path, capsys):
    """``report.md`` is model-authored and read once per hit in the whole-runs-dir walk; an
    undecodable byte in ONE historical report must degrade that row to ``"?"`` with a stderr
    warning, not kill the walk with a UnicodeDecodeError traceback (#595 — the walk's last
    unguarded read; UnicodeDecodeError is a ValueError, not an OSError)."""
    tl = _load()
    runs = tmp_path / "runs"
    runs.mkdir()
    broken = _mk_run(runs, "caseA", disposition="benign",
                     loads=[{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}])
    (broken / "report.md").write_bytes(b"---\ndisposition: benign\n---\n\xff")
    _mk_run(runs, "caseB", disposition="malicious",
            loads=[{"lesson_name": "L", "ts": "2026-06-06T00:00:00+00:00"}])

    hits = tl.in_context_cases("L", None, runs)
    err = capsys.readouterr().err
    assert [(h.case_id, h.disposition) for h in hits] == [("caseA", "?"), ("caseB", "malicious")]
    assert "caseA/report.md" in err


def test_all_survives_undecodable_report(tmp_path, capsys):
    """The same property at the seam a user drives: ``--all`` over a runs dir containing an
    undecodable report exits 0 and still prints every lesson's row."""
    tl = _load()
    _mk_lesson(tmp_path / "lessons", "L",
               body_frontmatter="name: L\ndescription: d\ncreated_at: 2026-06-04")
    runs = tmp_path / "runs"
    runs.mkdir()
    rd = _mk_run(runs, "caseA", disposition="benign",
                 loads=[{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}])
    (rd / "report.md").write_bytes(b"---\ndisposition: benign\n---\n\xff")

    rc = tl.main(["--all", "--lessons-dir", str(tmp_path / "lessons"), "--runs-dir", str(runs)])
    assert rc == 0
    assert "L\td\t1" in capsys.readouterr().out.splitlines()




def test_all_marks_malformed_lesson_instead_of_dropping_it(tmp_path, capsys):
    """A lesson the ``iter_lessons`` walk warn-skips (e.g. a curator edit broke its YAML) must
    still get a row in the ``--all`` audit table — losing it silently hides exactly the lesson
    a human is most likely investigating, while the named path still traces it (#590). The
    marker's count is unwindowed (no parseable ``created_at``), and the row says so."""
    tl = _load()
    lessons = tmp_path / "lessons"
    _mk_lesson(lessons, "ok", body_frontmatter="name: ok\ndescription: fine\ncreated_at: 2026-06-04")
    (lessons / "broken.md").write_text("---\ndescription: [unclosed\n---\nbody\n")
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="malicious",
            loads=[{"lesson_name": "broken", "ts": "2026-06-05T00:00:00+00:00"}])
    _mk_run(runs, "caseB", disposition="benign",
            loads=[{"lesson_name": "ok", "ts": "2026-06-05T00:00:00+00:00"}])

    rc = tl.main(["--all", "--lessons-dir", str(lessons), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0
    lines = cap.out.splitlines()
    assert "ok\tfine\t1" in lines
    assert "broken\t(malformed lesson — unwindowed count)\t1" in lines
    assert "skipping broken.md" in cap.err


def test_all_marker_pass_inherits_the_discovery_rule(tmp_path, capsys):
    """The marker pass diffs against ``iter_lesson_paths`` (the shared discovery rule), so an
    ``_``-prefixed draft is not a "skipped lesson" and gets no marker row."""
    tl = _load()
    lessons = tmp_path / "lessons"
    _mk_lesson(lessons, "ok", body_frontmatter="name: ok\ndescription: fine\ncreated_at: 2026-06-04")
    (lessons / "_draft.md").write_text("not a lesson\n")
    runs = tmp_path / "runs"
    runs.mkdir()

    rc = tl.main(["--all", "--lessons-dir", str(lessons), "--runs-dir", str(runs)])
    assert rc == 0
    assert capsys.readouterr().out.splitlines() == ["ok\tfine\t0"]


def test_named_path_traces_malformed_lesson_and_warns_unwindowed(tmp_path, capsys):
    """Naming a malformed-but-readable lesson still traces it (an audit of a broken lesson is
    the tool's most likely use), but warns that the trace is unwindowed — silently printing
    ``since None`` hid that the window never engaged (#590's named-path half)."""
    tl = _load()
    lessons = tmp_path / "lessons"
    lessons.mkdir()
    (lessons / "broken.md").write_text("---\ndescription: [unclosed\n---\nbody\n")
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="malicious",
            loads=[{"lesson_name": "broken", "ts": "2026-06-05T00:00:00+00:00"}])

    rc = tl.main(["broken", "--lessons-dir", str(lessons), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0
    assert _case_ids(cap.out) == ["caseA"]
    assert "trace is unwindowed" in cap.err


def test_named_path_warns_unwindowed_on_unparseable_created_at(tmp_path, capsys):
    """Valid frontmatter whose LLM-authored ``created_at`` doesn't parse (or is absent) is just
    as unwindowed as malformed frontmatter — the warning keys on "no created_at to window on",
    so ``since None`` never prints silently (#596's named-path half; the ``--all`` row shape and
    the value echo are pinned by ``test_hardening_596_609.py``)."""
    tl = _load()
    _mk_lesson(tmp_path / "lessons", "L",
               body_frontmatter="name: L\ndescription: d\ncreated_at: not-a-date")
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="benign",
            loads=[{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}])

    rc = tl.main(["L", "--lessons-dir", str(tmp_path / "lessons"), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0
    assert _case_ids(cap.out) == ["caseA"]
    assert "trace is unwindowed" in cap.err


def test_all_with_lesson_name_is_a_usage_error(tmp_path, capsys):
    """``--all`` and a positional <lesson_name> answer different questions; silently preferring
    one (the old behavior ran ``--all`` and dropped the name) hands the operator the wrong
    report under a stray extra argument. Both together is a usage error."""
    tl = _load()
    _mk_lesson(tmp_path / "lessons", "L", body_frontmatter="name: L\ndescription: d")
    runs = tmp_path / "runs"
    runs.mkdir()

    rc = tl.main(["L", "--all",
                  "--lessons-dir", str(tmp_path / "lessons"), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 1
    assert cap.out == ""
    assert "not both" in cap.err


def test_named_path_unreadable_lesson_is_still_an_error(tmp_path, capsys):
    """An UNREADABLE named lesson stays an ERROR (exit 1): printing "0 case(s)" for a file
    that was never read is worse than failing. Pins the tri-state posture's hard edge so the
    malformed-lesson tolerance above cannot creep into the unreadable case."""
    tl = _load()
    lessons = tmp_path / "lessons"
    lessons.mkdir()
    (lessons / "undecodable.md").write_bytes(b"---\nname: u\n---\n\xff")
    runs = tmp_path / "runs"
    runs.mkdir()

    rc = tl.main(["undecodable", "--lessons-dir", str(lessons), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 1
    assert "cannot read undecodable.md" in cap.err
