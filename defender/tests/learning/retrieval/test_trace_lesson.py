"""Tests for defender/learning/trace_lesson.py — in-context-outcome traceability."""
from __future__ import annotations

import json
from datetime import date, datetime, UTC
from pathlib import Path

import pytest

from defender.tests.support.shared.contracts._by_path import load_trace_lesson
from defender.tests.support.storage._alert_plant import plant_alert
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H1105
from defender.tests.support.shared._fixture_uuid import fixture_uuid as C
from defender.tests.support.learning.retrieval._lessons_corpus import accepted_trace_tenant, trace_main

#: The tenant whose runs the tracer walks (`--tenant` is required; its runs are
#: `<data root>/<T>/runs`, opened through the repository).
TID = H1105.T_ID


@pytest.fixture(autouse=True)
def _data_root(tmp_path, monkeypatch):
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    H1105.tenant(root, TID)
    return root


def _load():
    return load_trace_lesson("trace_lesson")


def _tenant_runs_dir(tmp_path: Path) -> Path:
    """The tenant's runs folder as run setup makes it: run folders and their sidecars only."""
    runs = tmp_path / "data" / TID / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    return runs


def _opened(tl) -> list:
    """The tenant's runs as the tracer opens them (`tenant_runs`: the listing rule, then
    `runs.open` for each id)."""
    return tl.tenant_runs(accepted_trace_tenant(TID))  # C1: the tracer's helpers take the accepted tenant


def _mk_run(runs: Path, name: str, *, disposition: str, loads: list[dict], closed: bool = True, fault: str | None = None):
    """A finished run of case `name` (a label). Its folder, and so its case id, is
    `fixture_uuid(name)`: the tracer refuses any entry in `<T>/runs` that is not a UUID.
    Assertions spell the id as `C(<label>)`."""
    rd = runs / C(name)
    rd.mkdir(parents=True)
    plant_alert(rd)
    from defender.tests.support.storage import _readers1534 as R

    R.plant_run(rd, R.valid_fields(disposition) if closed else None, fault=fault)  # #1534: its closing record, not a report.md
    (rd / "lessons_loaded.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in loads)
    )
    return rd


def test_in_context_cases_windows_on_created_at(tmp_path):
    tl = _load()
    runs = _tenant_runs_dir(tmp_path)
    created = datetime(2026, 6, 4, tzinfo=UTC)
    _mk_run(runs, "case-a", disposition="benign",
            loads=[{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}])
    _mk_run(runs, "case-b", disposition="malicious",
            loads=[{"lesson_name": "L", "ts": "2026-06-01T00:00:00+00:00"}])
    _mk_run(runs, "case-c", disposition="benign",
            loads=[{"lesson_name": "OTHER", "ts": "2026-06-06T00:00:00+00:00"}])
    hits = tl.in_context_cases("L", created, _opened(tl))
    assert [(h.case_id, h.disposition) for h in hits] == [(C("case-a"), "benign")]


def test_in_context_cases_dedups_per_case_keeps_earliest(tmp_path):
    tl = _load()
    runs = _tenant_runs_dir(tmp_path)
    _mk_run(runs, "case-a", disposition="benign", loads=[
        {"lesson_name": "L", "ts": "2026-06-05T01:00:00+00:00"},
        {"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"},
    ])
    hits = tl.in_context_cases("L", None, _opened(tl))
    assert len(hits) == 1
    assert hits[0].loaded_at == "2026-06-05T00:00:00+00:00"


def test_earliest_load_is_chronological_not_lexicographic(tmp_path):
    tl = _load()
    runs = _tenant_runs_dir(tmp_path)
    _mk_run(runs, "case-a", disposition="benign", loads=[
        {"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"},
        {"lesson_name": "L", "ts": "2026-06-05T08:00:00+09:00"},
    ])
    hits = tl.in_context_cases("L", None, _opened(tl))
    assert [h.loaded_at for h in hits] == ["2026-06-05T08:00:00+09:00"]


def test_all_flattens_tab_and_newline_in_description(tmp_path, capsys):
    """The description column is LLM-authored; a tab or newline in it would forge a column
    or split the row, so the TSV flattens both (the ``lessons_fm._emit_match`` idiom)."""
    tl = _load()
    _mk_lesson(tmp_path / "lessons", "L",
               body_frontmatter='name: L\ndescription: "a\\tb\\nc"\ncreated_at: 2026-06-04')
    _tenant_runs_dir(tmp_path)

    rc = trace_main(tl, ["--all", "--lessons-dir", str(tmp_path / "lessons"), "--tenant", TID])
    assert rc == 0, capsys.readouterr().err
    lines = capsys.readouterr().out.splitlines()
    assert lines == ["L\ta b c\t0\t0"]


def test_all_drops_terminal_controls_from_the_description(tmp_path, capsys):
    tl = _load()
    _mk_lesson(tmp_path / "lessons", "L",
               body_frontmatter='name: L\ndescription: "a\\e[2Kb\\x1fc"\ncreated_at: 2026-06-04')
    _tenant_runs_dir(tmp_path)

    rc = trace_main(tl, ["--all", "--lessons-dir", str(tmp_path / "lessons"), "--tenant", TID])
    assert rc == 0, capsys.readouterr().err
    assert capsys.readouterr().out.splitlines() == ["L\ta[2Kbc\t0\t0"]


def test_in_context_cases_missing_runs_dir_is_empty(tmp_path):
    tl = _load()
    assert not (tmp_path / "data" / TID / "runs").exists()
    assert tl.in_context_cases("L", None, _opened(tl)) == []


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


@pytest.mark.parametrize(
    ("case", "stem", "frontmatter", "runs", "expected", "expect"), [
        # A tz-less created_at (LLM-authored, no offset → PyYAML naive datetime) must not raise
        # TypeError against the always-aware hook timestamps.
        ("naive-created-at-does-not-crash",
         "L", "name: L\ndescription: d\ncreated_at: 2026-06-04T00:00:00",
         [("case-a", "benign", "2026-06-05T00:00:00+00:00")],
         ["case-a"], (None, ("case-a", "benign"))),

        # `created_at: 2026-06-04` (PyYAML → date) is promoted to UTC midnight, not silently
        # dropped — so a load BEFORE it stays excluded and one after it is kept.
        ("bare-date-created-at-windows-correctly",
         "L", "name: L\ndescription: d\ncreated_at: 2026-06-04",
         [("before", "benign", "2026-06-01T00:00:00+00:00"),
          ("after", "benign", "2026-06-05T00:00:00+00:00")],
         ["after"], (None, None)),

        ("identity-is-the-stem-not-the-frontmatter-name",
         "foo-bar", "name: foo_bar\ndescription: d",
         [("case-a", "malicious", "2026-06-05T00:00:00+00:00")],
         ["case-a"], ("# foo-bar", None)),
    ], ids=lambda v: v if isinstance(v, str) and len(v) < 60 and "\n" not in v else "")
def test_trace_reports_the_cases_a_lesson_was_loaded_into(
    tmp_path, capsys, case, stem, frontmatter, runs, expected, expect
):
    tl = _load()
    _mk_lesson(tmp_path / "lessons", stem, body_frontmatter=frontmatter)
    runs_dir = _tenant_runs_dir(tmp_path)
    for name, disposition, ts in runs:
        _mk_run(runs_dir, name, disposition=disposition,
                loads=[{"lesson_name": stem, "ts": ts}])

    rc = trace_main(tl, [stem, "--lessons-dir", str(tmp_path / "lessons"),
                  "--tenant", TID])
    cap = capsys.readouterr()
    out = cap.out
    assert rc == 0, cap.err
    assert _case_ids(out) == [C(label) for label in expected]
    expect_header, expect_row = expect
    if expect_header is not None:
        assert out.startswith(expect_header)
    if expect_row is not None:
        label, disposition = expect_row
        assert f"{C(label)}\t{disposition}" in out


def _rows(out: str) -> dict[str, str]:
    """The trace table's rows by case id: `{case id: the rest of the line}`."""
    return {line.split("\t")[0]: line for line in out.splitlines() if "\t" in line}


@pytest.mark.parametrize("fault", ["database-missing", "row-invalid", "recorded-before-1534"])
def test_1534_a_run_whose_record_cannot_be_looked_up_is_a_fault_row_naming_the_kind(tmp_path, capsys, fault):
    """`CouldNotLook` is that run's row carrying the kind's wording, never a disposition or "unknown"; the other runs'
    rows are untouched. (V-READERS, trace CLI; OD10)"""
    from defender._vocab import UNKNOWN_DISPOSITION
    from defender.tests.support.storage import _readers1534 as R

    tl = _load()
    _mk_lesson(tmp_path / "lessons", "L", body_frontmatter="name: L\ndescription: d\ncreated_at: 2026-06-04")
    runs = _tenant_runs_dir(tmp_path)
    load = [{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}]
    _mk_run(runs, "case-a", disposition="benign", loads=load, fault=fault)
    _mk_run(runs, "case-b", disposition="malicious", loads=load)

    rc = trace_main(tl, ["L", "--lessons-dir", str(tmp_path / "lessons"), "--tenant", TID])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    rows = _rows(cap.out)
    assert R.names_only(fault, rows[C("case-a")]), rows[C("case-a")]
    assert UNKNOWN_DISPOSITION not in rows[C("case-a")].split("\t")[1:2]
    assert f"{C('case-b')}\tmalicious" in cap.out, "positive control: the other run's row reads"
    assert str(tmp_path) not in cap.out + cap.err, "the lookup's detail (a path) reached the output"


def test_1534_a_run_that_never_closed_is_unknown_and_a_record_beside_a_contrary_report_is_its_disposition(tmp_path, capsys):
    """`NeverClosed` is the unknown disposition, as an absent report was; a `report.md` beside a record changes nothing. (V-READERS, trace CLI)"""
    from defender._vocab import UNKNOWN_DISPOSITION

    tl = _load()
    _mk_lesson(tmp_path / "lessons", "L", body_frontmatter="name: L\ndescription: d\ncreated_at: 2026-06-04")
    runs = _tenant_runs_dir(tmp_path)
    load = [{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}]
    _mk_run(runs, "case-a", disposition="benign", loads=load, closed=False)
    never_pointed = _mk_run(runs, "case-b", disposition="benign", loads=load, fault="no-pointer")
    both = _mk_run(runs, "case-c", disposition="benign", loads=load)
    (both / "report.md").write_text("---\ndisposition: malicious\n---\nDECOY\n", encoding="utf-8")  # lint-run-records: ok — a decoy the tracer must not read
    assert never_pointed.is_dir()

    hits = tl.in_context_cases("L", None, _opened(tl))
    assert sorted((h.case_id, h.disposition) for h in hits) == sorted([
        (C("case-a"), UNKNOWN_DISPOSITION), (C("case-b"), UNKNOWN_DISPOSITION), (C("case-c"), "benign")])


def test_1534_all_survives_a_run_whose_record_cannot_be_looked_up(tmp_path, capsys):
    """``--all`` over a run with an unreadable record exits 0 and still prints every lesson's row. (V-READERS, trace CLI)"""
    tl = _load()
    _mk_lesson(tmp_path / "lessons", "L",
               body_frontmatter="name: L\ndescription: d\ncreated_at: 2026-06-04")
    runs = _tenant_runs_dir(tmp_path)
    _mk_run(runs, "case-a", disposition="benign", fault="row-invalid",
            loads=[{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}])

    rc = trace_main(tl, ["--all", "--lessons-dir", str(tmp_path / "lessons"), "--tenant", TID])
    assert rc == 0, capsys.readouterr().err
    assert "L\td\t1\t0" in capsys.readouterr().out.splitlines()


def test_all_marks_malformed_lesson_instead_of_dropping_it(tmp_path, capsys):
    tl = _load()
    lessons = tmp_path / "lessons"
    _mk_lesson(lessons, "ok", body_frontmatter="name: ok\ndescription: fine\ncreated_at: 2026-06-04")
    (lessons / "broken.md").write_text("---\ndescription: [unclosed\n---\nbody\n")
    runs = _tenant_runs_dir(tmp_path)
    _mk_run(runs, "case-a", disposition="malicious",
            loads=[{"lesson_name": "broken", "ts": "2026-06-05T00:00:00+00:00"}])
    _mk_run(runs, "case-b", disposition="benign",
            loads=[{"lesson_name": "ok", "ts": "2026-06-05T00:00:00+00:00"}])

    rc = trace_main(tl, ["--all", "--lessons-dir", str(lessons), "--tenant", TID])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    lines = cap.out.splitlines()
    assert "ok\tfine\t1\t0" in lines
    assert "broken\t(malformed lesson — unwindowed count)\t1\t0" in lines
    assert "skipping broken.md" in cap.err


def test_all_marker_pass_inherits_the_discovery_rule(tmp_path, capsys):
    """The marker pass diffs against ``iter_lesson_paths`` (the shared discovery rule), so an
    ``_``-prefixed draft is not a "skipped lesson" and gets no marker row."""
    tl = _load()
    lessons = tmp_path / "lessons"
    _mk_lesson(lessons, "ok", body_frontmatter="name: ok\ndescription: fine\ncreated_at: 2026-06-04")
    (lessons / "_draft.md").write_text("not a lesson\n")
    _tenant_runs_dir(tmp_path)

    rc = trace_main(tl, ["--all", "--lessons-dir", str(lessons), "--tenant", TID])
    assert rc == 0, capsys.readouterr().err
    assert capsys.readouterr().out.splitlines() == ["ok\tfine\t0\t0"]


def test_named_path_traces_malformed_lesson_and_warns_unwindowed(tmp_path, capsys):
    tl = _load()
    lessons = tmp_path / "lessons"
    lessons.mkdir()
    (lessons / "broken.md").write_text("---\ndescription: [unclosed\n---\nbody\n")
    runs = _tenant_runs_dir(tmp_path)
    _mk_run(runs, "case-a", disposition="malicious",
            loads=[{"lesson_name": "broken", "ts": "2026-06-05T00:00:00+00:00"}])

    rc = trace_main(tl, ["broken", "--lessons-dir", str(lessons), "--tenant", TID])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    assert _case_ids(cap.out) == [C("case-a")]
    assert "trace is unwindowed" in cap.err


def test_named_path_warns_unwindowed_on_unparseable_created_at(tmp_path, capsys):
    tl = _load()
    _mk_lesson(tmp_path / "lessons", "L",
               body_frontmatter="name: L\ndescription: d\ncreated_at: not-a-date")
    runs = _tenant_runs_dir(tmp_path)
    _mk_run(runs, "case-a", disposition="benign",
            loads=[{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}])

    rc = trace_main(tl, ["L", "--lessons-dir", str(tmp_path / "lessons"), "--tenant", TID])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    assert _case_ids(cap.out) == [C("case-a")]
    assert "trace is unwindowed" in cap.err


def test_all_with_lesson_name_is_a_usage_error(tmp_path, capsys):
    tl = _load()
    _mk_lesson(tmp_path / "lessons", "L", body_frontmatter="name: L\ndescription: d")
    _tenant_runs_dir(tmp_path)

    rc = trace_main(tl, ["L", "--all",
                  "--lessons-dir", str(tmp_path / "lessons"), "--tenant", TID])
    cap = capsys.readouterr()
    assert rc == 1
    assert cap.out == ""
    assert "not both" in cap.err


def test_named_path_unreadable_lesson_is_still_an_error(tmp_path, capsys):
    tl = _load()
    lessons = tmp_path / "lessons"
    lessons.mkdir()
    (lessons / "undecodable.md").write_bytes(b"---\nname: u\n---\n\xff")
    _tenant_runs_dir(tmp_path)

    rc = trace_main(tl, ["undecodable", "--lessons-dir", str(lessons), "--tenant", TID])
    cap = capsys.readouterr()
    assert rc == 1
    assert "cannot read undecodable.md" in cap.err


def test_1534_a_data_root_moved_after_a_run_fails_its_page_rerender_and_shows_a_fault_row_in_the_trace(
        tmp_path, capsys, caplog):
    """The pointer's stored path is stale after the move: the CLI re-render exits 1 naming `database-missing`, and the trace has a
    fault row for that run beside the readable one. (V-LOOK residual, V-PAGE, trace CLI)"""
    import shutil

    from defender.presentation import visualize_run
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root
    from defender.tests.support.storage import _readers1534 as R
    from defender.tests.support.tenancy._active1214 import active_directory

    tl = _load()
    _mk_lesson(tmp_path / "lessons", "L", body_frontmatter="name: L\ndescription: d\ncreated_at: 2026-06-04")
    load = [{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}]
    old = tmp_path / "old-root" / TID
    _mk_run(old / "runs", "case-a", disposition="benign", loads=load)
    runs = _tenant_runs_dir(tmp_path)
    for entry in (old / "runs").iterdir():
        shutil.move(str(entry), runs / entry.name)
    shutil.copytree(old / "sessions", tmp_path / "data" / TID / "sessions", dirs_exist_ok=True)
    shutil.rmtree(tmp_path / "old-root")
    _mk_run(runs, "case-b", disposition="malicious", loads=load)

    caplog.set_level("ERROR")
    rc = visualize_run.main(["visualize_run.py", "--tenant", TID, C("case-a")],
                            directory=active_directory(current_data_root(), TID))
    assert rc == 1
    assert R.names(R.KINDS_BY_FAULT[0], caplog.text), caplog.text

    assert trace_main(tl, ["L", "--lessons-dir", str(tmp_path / "lessons"), "--tenant", TID]) == 0
    rows = _rows(capsys.readouterr().out)
    assert R.names_only("database-missing", rows[C("case-a")]), rows[C("case-a")]
    assert f"{C('case-b')}\tmalicious" in "\n".join(rows.values()), "positive control: a run whose database is where its pointer says"
