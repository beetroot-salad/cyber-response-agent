"""Hardening: deeply nested YAML (RecursionError) degrades to a typed FrontmatterError instead of killing an audit walk; trace_lesson self-marks, echoes and sanitizes a missing/unparseable `created_at` on every surface."""
from __future__ import annotations

import json
from pathlib import Path
from defender.tests.support.shared._fixture_uuid import fixture_uuid as C

from defender.tests.support.shared.contracts._by_path import load_trace_lesson
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H1105
import itertools
import os

import pytest

from defender.knowledge._corpus import iter_lessons
from defender._frontmatter import (
    parse_frontmatter_or_none,
)
from defender.learning.core.config import RunUnprocessable
from defender.learning.core.validate import normalize_disposition
from defender.tests.support.storage._alert_plant import plant_alert


def _load_tl():
    return load_trace_lesson("trace_lesson_hardening")


@pytest.fixture(autouse=True)
def _data_root(tmp_path, monkeypatch):
    """The tracer walks a tenant's natural runs (#1105 PR 2, J8: `--tenant` is required and
    `--runs-dir` is gone), so every scenario's runs live under a data root."""
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    return root


_TENANTS = itertools.count(1)


def _tenant_runs(_scenario: Path) -> Path:
    root = Path(os.environ["DEFENDER_DATA_ROOT"])
    tid = C(f"tenant:t{next(_TENANTS)}")
    H1105.tenant(root, tid)
    runs = root / tid / "runs"
    runs.mkdir()
    return runs



def _opened(tl, runs: Path) -> list:
    """`runs`' tenant's runs as the tracer opens them (the listing rule, then `runs.open`)."""
    return tl.tenant_runs(runs.parent.name)


def _flow_flood(depth: int = 3000) -> str:
    """YAML whose parse blows the default recursion limit (flow nesting)."""
    return "a: " + "[" * depth


def _block_flood(depth: int = 3000) -> str:
    """The block-mapping form of the same fault — also a RecursionError, not only flow."""
    return "\n".join(" " * i + f"k{i}:" for i in range(depth))


def _flood_doc(yaml_text: str) -> str:
    return f"---\n{yaml_text}\n---\nbody\n"


def _mk_lesson(lessons: Path, stem: str, *, body_frontmatter: str) -> Path:
    lessons.mkdir(exist_ok=True)
    p = lessons / f"{stem}.md"
    p.write_text(f"---\n{body_frontmatter}\n---\nbody\n", encoding="utf-8")
    return p


def _mk_run(runs: Path, name: str, *, disposition: str, loads: list[dict],
            raw: bool = False) -> Path:
    rd = runs / (name if raw else C(name))
    rd.mkdir(parents=True)
    plant_alert(rd)
    (rd / "report.md").write_text(
        f"---\ndisposition: {disposition}\n---\nbody\n", encoding="utf-8"
    )
    (rd / "lessons_loaded.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in loads), encoding="utf-8"
    )
    return rd



def _std_runs(tmp_path: Path, stem: str = "L") -> Path:
    """Two loads of ``stem``: one before any plausible created_at, one after — so a
    windowed count is 1 (vs created_at 2026-06-04) and an unwindowed count is 2."""
    runs = _tenant_runs(tmp_path)
    _mk_run(runs, "case-a", disposition="benign",
            loads=[{"lesson_name": stem, "ts": "2026-01-01T00:00:00+00:00"}])
    _mk_run(runs, "case-b", disposition="malicious",
            loads=[{"lesson_name": stem, "ts": "2026-06-05T00:00:00+00:00"}])
    return runs


def _all_row(tmp_path: Path, body_frontmatter: str, capsys, stem: str = "L"):
    tl = _load_tl()
    base = tmp_path / stem
    base.mkdir()
    lessons = base / "lessons"
    _mk_lesson(lessons, stem, body_frontmatter=body_frontmatter)
    runs = _std_runs(base, stem)
    rc = tl.main(["--all", "--lessons-dir", str(lessons), "--tenant", runs.parent.name])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    [row] = [ln for ln in cap.out.splitlines() if ln.split("\t")[0] == stem]
    return row, cap



def _case_ids(out: str) -> list[str]:
    return [ln.split("\t")[0] for ln in out.splitlines() if ln.strip() and not ln.startswith("#")]


def test_d_b1_or_none_tolerates_flood_and_recovers():
    assert parse_frontmatter_or_none(_flood_doc(_flow_flood())) is None
    assert parse_frontmatter_or_none(_flood_doc(_block_flood())) is None
    assert parse_frontmatter_or_none("---\nname: ok\n---\nbody") == {"name": "ok"}


def test_d_b5_iter_lessons_warn_skips_flood_lesson(tmp_path, capsys):
    """d: b5 — a flooded lesson is one warn-skip (with its ``on_skip`` marker), not the
    end of the corpus walk; the healthy sibling is still yielded."""
    lessons = tmp_path / "lessons"
    lessons.mkdir()
    (lessons / "flood.md").write_text(_flood_doc(_flow_flood()), encoding="utf-8")
    (lessons / "good.md").write_text(
        "---\nname: good\ndescription: d\n---\nbody\n", encoding="utf-8"
    )
    skipped: list[Path] = []
    got = [lesson.path.stem for lesson in iter_lessons(lessons, on_skip=skipped.append)]
    assert got == ["good"]
    assert [p.stem for p in skipped] == ["flood"]
    assert "skipping flood.md" in capsys.readouterr().err


def test_d_b8_all_survives_flood_lesson_with_marker_row(tmp_path, capsys):
    tl = _load_tl()
    lessons = tmp_path / "lessons"
    _mk_lesson(lessons, "ok", body_frontmatter="name: ok\ndescription: fine\ncreated_at: 2026-06-04")
    (lessons / "flood.md").write_text(_flood_doc(_flow_flood()), encoding="utf-8")
    runs = _tenant_runs(tmp_path)
    _mk_run(runs, "case-a", disposition="benign",
            loads=[{"lesson_name": "ok", "ts": "2026-06-05T00:00:00+00:00"},
                   {"lesson_name": "flood", "ts": "2026-06-05T00:00:00+00:00"}])
    rc = tl.main(["--all", "--lessons-dir", str(lessons), "--tenant", runs.parent.name])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    lines = cap.out.splitlines()
    assert "ok\tfine\t1\t0" in lines
    assert "flood\t(malformed lesson — unwindowed count)\t1\t0" in lines
    assert "skipping flood.md" in cap.err



def test_d_b9_named_flood_lesson_still_traces(tmp_path, capsys):
    tl = _load_tl()
    lessons = tmp_path / "lessons"
    lessons.mkdir()
    (lessons / "flood.md").write_text(_flood_doc(_flow_flood()), encoding="utf-8")
    runs = _tenant_runs(tmp_path)
    _mk_run(runs, "case-a", disposition="benign",
            loads=[{"lesson_name": "flood", "ts": "2026-06-05T00:00:00+00:00"}])
    rc = tl.main(["flood", "--lessons-dir", str(lessons), "--tenant", runs.parent.name])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    assert _case_ids(cap.out) == [C("case-a")]
    assert "malformed or missing frontmatter" in cap.err



def test_d_b10_learn_normalize_disposition_flood_is_run_unprocessable(tmp_path):
    rp = tmp_path / "report.md"
    rp.write_text("---\ndescription: [unclosed\n---\nbody\n", encoding="utf-8")
    with pytest.raises(RunUnprocessable):
        normalize_disposition(rp)
    rp.write_text(_flood_doc(_flow_flood()), encoding="utf-8")
    with pytest.raises(RunUnprocessable):
        normalize_disposition(rp)


def test_d_a1_all_marks_unparseable_created_at_row(tmp_path, capsys):
    row, _ = _all_row(tmp_path, "name: L\ndescription: real desc\ncreated_at: not-a-date", capsys)
    cols = row.split("\t")
    assert len(cols) == 4
    assert cols[2] == "2"
    assert cols[1].startswith("real desc")
    assert "unwindowed" in cols[1]
    assert '"not-a-date"' in cols[1]
    assert "malformed" not in cols[1]


def test_d_a2_all_marks_absent_created_at_distinctly(tmp_path, capsys):
    """d: a2 — an ABSENT created_at (never stamped) is a different fix for the curator
    than a garbage one; the marker says "no created_at" instead of echoing a value."""
    row, _ = _all_row(tmp_path, "name: L\ndescription: real desc", capsys)
    cols = row.split("\t")
    assert len(cols) == 4
    assert cols[2] == "2"
    assert cols[1].startswith("real desc")
    assert "unwindowed" in cols[1]
    assert "no created_at" in cols[1]
    assert "malformed" not in cols[1]


def _named(tmp_path, body_frontmatter: str, capsys, stem: str = "L"):
    tl = _load_tl()
    base = tmp_path / f"named-{stem}"
    base.mkdir()
    lessons = base / "lessons"
    _mk_lesson(lessons, stem, body_frontmatter=body_frontmatter)
    runs = _std_runs(base, stem)
    rc = tl.main([stem, "--lessons-dir", str(lessons), "--tenant", runs.parent.name])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    return cap



def test_d_a6_named_warn_echoes_offending_value(tmp_path, capsys):
    cap = _named(tmp_path, "name: L\ndescription: d\ncreated_at: not-a-date", capsys)
    assert len(cap.err.splitlines()) == 1
    assert "trace is unwindowed" in cap.err
    assert '"not-a-date"' in cap.err


def test_d_a8_header_never_prints_since_none(tmp_path, capsys):
    cap = _named(tmp_path, "name: L\ndescription: d\ncreated_at: not-a-date", capsys)
    lines = cap.out.splitlines()
    header = lines[0]
    assert header.startswith("# L")
    assert "since None" not in cap.out
    assert '"not-a-date"' in header
    assert sum(ln.startswith("#") for ln in lines) == 1
    assert _case_ids(cap.out) == sorted([C("case-a"), C("case-b")])



_HOSTILE_VALUE = '"a\\tb\\nc\\rd\\x0Be\\x0Cf\\x85g\\u2028h\\u2029i"'
_HOSTILE_CREATED_AT = f"created_at: {_HOSTILE_VALUE}"


def test_d_a9_all_echo_survives_every_line_breaker(tmp_path, capsys):
    row, cap = _all_row(tmp_path, f"name: L\ndescription: d\n{_HOSTILE_CREATED_AT}", capsys)
    assert len(cap.out.splitlines()) == 1
    assert row.count("\t") == 3
    assert "a b c d e f g h i" in row.split("\t")[1]


def test_d_a10_echo_is_clamped_to_80_chars(tmp_path, capsys):
    """d: a10 — a huge value cannot bloat the row: the echo shows the first 80 chars of
    the flattened value and an ``…`` continuation, never the full payload."""
    row, _ = _all_row(tmp_path, f'name: L\ndescription: d\ncreated_at: "{"x" * 500}"', capsys)
    desc_col = row.split("\t")[1]
    assert "x" * 80 in desc_col
    assert "x" * 81 not in desc_col
    assert "…" in desc_col


def test_d_a13_named_rows_flatten_disposition_and_ts(tmp_path, capsys):
    tl = _load_tl()
    lessons = tmp_path / "lessons"
    _mk_lesson(lessons, "L", body_frontmatter="name: L\ndescription: d")
    runs = _tenant_runs(tmp_path)
    _mk_run(runs, "case-a", disposition='"ben\\tign\\nX"',
            loads=[{"lesson_name": "L", "ts": "2026-06-05\t00:00:00+00:00"}])
    rc = tl.main(["L", "--lessons-dir", str(lessons), "--tenant", runs.parent.name])
    cap = capsys.readouterr()
    assert rc == 0, cap.err
    lines = cap.out.splitlines()
    assert len(lines) == 2
    row = lines[1]
    assert row.count("\t") == 3
    assert row.split("\t") == [C("case-a"), "?", "2026-06-05 00:00:00+00:00", "unknown"]
    # Positive control on the SAME column: a well-formed disposition still renders, so the
    # `?` above is the hostile value being refused, not the column having gone dead.
    _mk_run(runs, "case-b", disposition="benign",
            loads=[{"lesson_name": "L", "ts": "2026-06-06T00:00:00+00:00"}])
    assert tl.main(["L", "--lessons-dir", str(lessons), "--tenant", runs.parent.name]) == 0
    assert f"{C('case-b')}\tbenign\t" in capsys.readouterr().out



def test_d_a14_all_description_survives_every_line_breaker(tmp_path, capsys):
    row, cap = _all_row(
        tmp_path, f"name: L\ndescription: {_HOSTILE_VALUE}\ncreated_at: 2026-06-04", capsys
    )
    assert len(cap.out.splitlines()) == 1
    assert row.count("\t") == 3
    assert row.split("\t")[1] == "a b c d e f g h i"
