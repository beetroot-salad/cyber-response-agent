"""Executable spec for #596 (remainder) + #609 — the trace_lesson/frontmatter hardening pair.

#609: ``yaml.safe_load`` raises ``RecursionError`` (not a ``YAMLError``) on deeply nested
YAML, so it escapes ``split_frontmatter``'s wrap and ``parse_frontmatter_or_none``'s
tolerance — one flooded LLM-authored file kills a whole audit walk. The fix folds
``RecursionError`` into ``FrontmatterError`` at the one ``safe_load`` under
``defender/_frontmatter.py``, and joins it to the existing ``yaml.YAMLError`` degrade
path at the four in-scope direct ``safe_load`` sites (curator held-out check, lessons
author ``disposition_for``, ticket enrichment's two verdict readers).

#596 (remainder): a VALID lesson whose LLM-authored ``created_at`` is absent or
unparseable currently prints a normal-looking ``--all`` row with a silently unwindowed
count, and the named path prints ``since None``. The fix self-marks the row (real
description kept, marker appended), echoes the offending value — quoted, sanitized
against every line/column breaker, clamped to 80 chars + ``…`` — on all three surfaces
(``--all`` row, named-path stderr warn, header), distinguishes absent from
present-but-unparseable, and flattens the named path's ``disposition``/``loaded_at``
columns (same LLM/hook-authored-value-in-TSV class).

The demand list + coverage graph live in ``spec_graph_596_609.yaml`` beside this file;
each test names its demand id. New-behavior demands are RED at the spec's base commit
by design; every paired control is green there.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from defender._corpus import iter_lessons, iter_query_templates
from defender._frontmatter import (
    FrontmatterError,
    parse_frontmatter,
    parse_frontmatter_or_none,
    split_frontmatter,
)
from defender.learning.author.curator import is_held_out_source
from defender.learning.author.lessons.run import AuthorConfig, disposition_for
from defender.learning.core.config import RunUnprocessable
from defender.learning.core.directions import ADVERSARIAL
from defender.learning.core.validate import normalize_disposition
from defender.learning.tickets.ticket_enrichment import (
    _read_adversarial_outcome,
    _read_resolution_method,
)

TL_PATH = Path(__file__).resolve().parents[1] / "learning" / "ops" / "trace_lesson.py"


def _load_tl():
    # Distinct module name from test_trace_lesson._load so the two files' loads
    # can't clobber each other in sys.modules within one pytest session.
    spec = importlib.util.spec_from_file_location("trace_lesson_hardening", TL_PATH)
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


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


def _mk_run(runs: Path, name: str, *, disposition: str, loads: list[dict]) -> Path:
    rd = runs / name
    rd.mkdir(parents=True)
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
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="benign",
            loads=[{"lesson_name": stem, "ts": "2026-01-01T00:00:00+00:00"}])
    _mk_run(runs, "caseB", disposition="malicious",
            loads=[{"lesson_name": stem, "ts": "2026-06-05T00:00:00+00:00"}])
    return runs


def _all_row(tmp_path: Path, body_frontmatter: str, capsys, stem: str = "L"):
    """Run ``--all`` over one lesson + the standard runs; return (its row, captured).

    Sandboxed under ``tmp_path / stem`` so one test can drive several scenarios."""
    tl = _load_tl()
    base = tmp_path / stem
    base.mkdir()
    lessons = base / "lessons"
    _mk_lesson(lessons, stem, body_frontmatter=body_frontmatter)
    runs = _std_runs(base, stem)
    rc = tl.main(["--all", "--lessons-dir", str(lessons), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0
    [row] = [ln for ln in cap.out.splitlines() if ln.split("\t")[0] == stem]
    return row, cap


def _case_ids(out: str) -> list[str]:
    return [ln.split("\t")[0] for ln in out.splitlines() if ln.strip() and not ln.startswith("#")]


# ---------------------------------------------------------------------------
# #609 — the parser seam (demands b1–b3)
# ---------------------------------------------------------------------------


def test_d_b1_or_none_tolerates_flood_and_recovers():
    """d: b1 — flow AND block floods → None (a RecursionError from ``safe_load`` is a
    malformed-frontmatter outcome, not a crash), and a healthy doc still parses in the
    same process afterwards: the caught error leaves no parser state behind."""
    assert parse_frontmatter_or_none(_flood_doc(_flow_flood())) is None
    assert parse_frontmatter_or_none(_flood_doc(_block_flood())) is None
    assert parse_frontmatter_or_none("---\nname: ok\n---\nbody") == {"name": "ok"}


def test_d_b2_strict_flood_is_typed():
    """d: b2 — the strict parsers raise ``FrontmatterError`` (a ValueError) on a flood,
    so every existing ``except FrontmatterError`` catcher inherits the guard."""
    with pytest.raises(FrontmatterError):
        parse_frontmatter(_flood_doc(_flow_flood()))
    with pytest.raises(FrontmatterError):
        split_frontmatter(_flood_doc(_flow_flood()))


def test_d_b3_flood_error_message_is_bounded():
    """d: b3 — the raised message must not embed the multi-KB raw YAML: it lands in
    stderr warn lines and RunUnprocessable dead-letters."""
    with pytest.raises(FrontmatterError) as ei:
        parse_frontmatter(_flood_doc(_flow_flood()))
    assert len(str(ei.value)) < 500


# ---------------------------------------------------------------------------
# #609 — the tolerant walks inherit the fold (demands b5–b9)
# ---------------------------------------------------------------------------


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


def test_d_b6_iter_query_templates_warn_skips_flood_template(tmp_path, capsys):
    """d: b6 — same contract one corpus over: this walk runs on EVERY gather dispatch,
    so a flooded template must cost one skip, not the dispatch."""
    catalog = tmp_path / "queries"
    (catalog / "elastic").mkdir(parents=True)
    (catalog / "elastic" / "flood.md").write_text(_flood_doc(_flow_flood()), encoding="utf-8")
    (catalog / "elastic" / "good.md").write_text(
        "---\nid: elastic.good\n---\n## Goal\ng\n\n## Query\nq\n", encoding="utf-8"
    )
    got = [t.id for t in iter_query_templates(catalog)]
    assert got == ["elastic.good"]
    assert "skipping flood.md" in capsys.readouterr().err


def test_d_b7_flood_report_costs_one_disposition_not_the_walk(tmp_path):
    """d: b7 — one flooded report.md degrades that case's disposition to "?" and the
    walk completes with the healthy sibling intact (the #595 class, one exception over)."""
    tl = _load_tl()
    runs = tmp_path / "runs"
    runs.mkdir()
    bad = _mk_run(runs, "caseA", disposition="benign",
                  loads=[{"lesson_name": "L", "ts": "2026-06-05T00:00:00+00:00"}])
    (bad / "report.md").write_text(_flood_doc(_flow_flood()), encoding="utf-8")
    _mk_run(runs, "caseB", disposition="malicious",
            loads=[{"lesson_name": "L", "ts": "2026-06-06T00:00:00+00:00"}])
    hits = tl.in_context_cases("L", None, runs)
    assert [(h.case_id, h.disposition) for h in hits] == [("caseA", "?"), ("caseB", "malicious")]
    # rejected: a stderr warn for the flood report — an unparseable-frontmatter report
    # already degrades to "?" silently; the flood is the same disposition-unknowable class.


def test_d_b8_all_survives_flood_lesson_with_marker_row(tmp_path, capsys):
    """d: b8 — ``--all`` over a corpus containing a flooded lesson exits 0 and gives the
    flood the existing skipped-lesson marker row (it IS malformed), sibling row intact."""
    tl = _load_tl()
    lessons = tmp_path / "lessons"
    _mk_lesson(lessons, "ok", body_frontmatter="name: ok\ndescription: fine\ncreated_at: 2026-06-04")
    (lessons / "flood.md").write_text(_flood_doc(_flow_flood()), encoding="utf-8")
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="benign",
            loads=[{"lesson_name": "ok", "ts": "2026-06-05T00:00:00+00:00"},
                   {"lesson_name": "flood", "ts": "2026-06-05T00:00:00+00:00"}])
    rc = tl.main(["--all", "--lessons-dir", str(lessons), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0
    lines = cap.out.splitlines()
    assert "ok\tfine\t1" in lines
    assert "flood\t(malformed lesson — unwindowed count)\t1" in lines
    assert "skipping flood.md" in cap.err


def test_d_b9_named_flood_lesson_still_traces(tmp_path, capsys):
    """d: b9 — naming a flooded lesson keeps the #608 tri-state posture: readable but
    malformed → warn + unwindowed trace + rc 0 (an audit of a broken lesson is the
    tool's most likely use), never a RecursionError traceback."""
    tl = _load_tl()
    lessons = tmp_path / "lessons"
    lessons.mkdir()
    (lessons / "flood.md").write_text(_flood_doc(_flow_flood()), encoding="utf-8")
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="benign",
            loads=[{"lesson_name": "flood", "ts": "2026-06-05T00:00:00+00:00"}])
    rc = tl.main(["flood", "--lessons-dir", str(lessons), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0
    assert _case_ids(cap.out) == ["caseA"]
    assert "malformed or missing frontmatter" in cap.err


# ---------------------------------------------------------------------------
# #609 — the strict/learn-loop context and the four direct safe_load sites (b10–b14)
# ---------------------------------------------------------------------------


def test_d_b10_learn_normalize_disposition_flood_is_run_unprocessable(tmp_path):
    """d: b10 — the LEARN gate stays fail-loud but TYPED: a flooded report.md raises
    ``RunUnprocessable`` (dead-letterable by the drain), not RecursionError through the
    worker. Control: plain invalid YAML already takes that path."""
    rp = tmp_path / "report.md"
    rp.write_text("---\ndescription: [unclosed\n---\nbody\n", encoding="utf-8")
    with pytest.raises(RunUnprocessable):
        normalize_disposition(rp)
    rp.write_text(_flood_doc(_flow_flood()), encoding="utf-8")
    with pytest.raises(RunUnprocessable):
        normalize_disposition(rp)


def test_d_b11_held_out_flood_ground_truth_reads_not_held_out(tmp_path):
    """d: b11 — a flooded ground_truth.yaml joins the site's existing YAMLError degrade
    (→ False, "genuinely not held out"), instead of crashing the author drain. Controls:
    a declared hold-out is True; plain invalid YAML is already False."""
    # rejected: fail-closed True on unparseable — the pinned YAMLError posture is False;
    # the flood joins the same malformed class rather than inventing a third posture.
    runs = tmp_path / "runs"
    bundle = runs / "l-1"
    bundle.mkdir(parents=True)
    gt = bundle / "ground_truth.yaml"
    gt.write_text("held_out: true\n", encoding="utf-8")
    assert is_held_out_source(runs, "l-1") is True
    gt.write_text("a: [unclosed\n", encoding="utf-8")
    assert is_held_out_source(runs, "l-1") is False
    gt.write_text("[" * 3000, encoding="utf-8")
    assert is_held_out_source(runs, "l-1") is False


def test_d_b12_disposition_for_flood_source_refs_is_held(tmp_path):
    """d: b12 — a flooded source_refs.yaml reads as "no ground truth" (None → the case
    is held), joining the site's YAMLError degrade. Control: a healthy file resolves."""
    runs = tmp_path / "runs"
    (runs / "r1").mkdir(parents=True)
    refs = runs / "r1" / "source_refs.yaml"
    # Only ``cfg.runs_dir`` is read on this path; the full AuthorConfig is a batch
    # wiring object far beyond this seam's needs.
    cfg = cast(AuthorConfig, SimpleNamespace(runs_dir=runs))
    refs.write_text("normalized_disposition: benign\n", encoding="utf-8")
    assert disposition_for(cfg, "r1") == "benign"
    refs.write_text("[" * 3000, encoding="utf-8")
    assert disposition_for(cfg, "r1") is None


def test_d_b13_ticket_outcome_flood_verdict_skips(tmp_path):
    """d: b13 — ticket enrichment is non-fatal by construction: a flooded verdict is
    "unusable → skip" (None), like any unusable verdict. Control: a healthy verdict
    resolves its outcome keyword."""
    lrd = tmp_path / "lrd"
    lrd.mkdir()
    verdict = lrd / ADVERSARIAL.judge_name
    verdict.write_text("outcome: survived\n", encoding="utf-8")
    assert _read_adversarial_outcome(lrd) == "survived"
    verdict.write_text("[" * 3000, encoding="utf-8")
    assert _read_adversarial_outcome(lrd) is None


def test_d_b14_ticket_resolution_method_flood_verdict_skips(tmp_path):
    """d: b14 — the second verdict reader has its own except tuple; the flood joins it
    the same way (None → skip), with the healthy control alongside."""
    lrd = tmp_path / "lrd"
    lrd.mkdir()
    verdict = lrd / ADVERSARIAL.judge_name
    verdict.write_text("resolution_method: policy-check\n", encoding="utf-8")
    assert _read_resolution_method(lrd) == "policy-check"
    verdict.write_text("[" * 3000, encoding="utf-8")
    assert _read_resolution_method(lrd) is None


# ---------------------------------------------------------------------------
# #596 — the --all row self-marks and echoes the offending value (a1–a5)
# ---------------------------------------------------------------------------


def test_d_a1_all_marks_unparseable_created_at_row(tmp_path, capsys):
    """d: a1 — a VALID lesson whose created_at doesn't parse gets a self-marking row:
    real description kept, marker names the quoted offending value, count is the
    unwindowed count (still traces — never 0), and the row does not claim "malformed"."""
    row, _ = _all_row(tmp_path, "name: L\ndescription: real desc\ncreated_at: not-a-date", capsys)
    cols = row.split("\t")
    assert len(cols) == 3
    assert cols[2] == "2"                    # unwindowed: both loads qualify
    assert cols[1].startswith("real desc")   # the description survives, marker appended
    assert "unwindowed" in cols[1]
    assert '"not-a-date"' in cols[1]         # the offending value, quoted
    assert "malformed" not in cols[1]        # a valid lesson is not labeled broken


def test_d_a2_all_marks_absent_created_at_distinctly(tmp_path, capsys):
    """d: a2 — an ABSENT created_at (never stamped) is a different fix for the curator
    than a garbage one; the marker says "no created_at" instead of echoing a value."""
    row, _ = _all_row(tmp_path, "name: L\ndescription: real desc", capsys)
    cols = row.split("\t")
    assert len(cols) == 3
    assert cols[2] == "2"
    assert cols[1].startswith("real desc")
    assert "unwindowed" in cols[1]
    assert "no created_at" in cols[1]
    assert "malformed" not in cols[1]


def test_d_a3_explicit_null_created_at_reads_as_absent(tmp_path, capsys):
    """d: a3 — ``created_at: null`` is a never-stamped field, not a garbage value: the
    absent flavor, with no bogus quoted "None" echo."""
    # rejected: the unparseable flavor echoing '"None"' — YAML null carries no value
    # worth quoting, and "None" would read as a literal string the curator should fix.
    row, _ = _all_row(tmp_path, "name: L\ndescription: d\ncreated_at: null", capsys)
    cols = row.split("\t")
    assert "no created_at" in cols[1]
    assert '"None"' not in cols[1]


def test_d_a4_empty_string_created_at_is_visibly_empty(tmp_path, capsys):
    """d: a4 — ``created_at: ""`` is present-but-unparseable, and the quoting is what
    makes the emptiness visible instead of a marker that names nothing."""
    row, _ = _all_row(tmp_path, 'name: L\ndescription: d\ncreated_at: ""', capsys)
    cols = row.split("\t")
    assert "unwindowed" in cols[1]
    assert '""' in cols[1]


def test_d_a5_nonstring_created_at_is_echoed(tmp_path, capsys):
    """d: a5 — a non-string, non-date value (here a YAML list) is unparseable too; the
    echo stringifies it so the curator sees what the field actually holds."""
    row, _ = _all_row(tmp_path, "name: L\ndescription: d\ncreated_at: [1, 2]", capsys)
    cols = row.split("\t")
    assert cols[2] == "2"
    assert "unwindowed" in cols[1]
    assert "1, 2" in cols[1]


# ---------------------------------------------------------------------------
# #596 — the named path: warn echo, honest header (a6–a8)
# ---------------------------------------------------------------------------


def _named(tmp_path, body_frontmatter: str, capsys, stem: str = "L"):
    tl = _load_tl()
    base = tmp_path / f"named-{stem}"
    base.mkdir()
    lessons = base / "lessons"
    _mk_lesson(lessons, stem, body_frontmatter=body_frontmatter)
    runs = _std_runs(base, stem)
    rc = tl.main([stem, "--lessons-dir", str(lessons), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0
    return cap


def test_d_a6_named_warn_echoes_offending_value(tmp_path, capsys):
    """d: a6 — the named-path stderr warn tells the human what to fix without opening
    the file: one line, quoted value, and it keeps the #608-pinned "trace is unwindowed"
    phrase so existing consumers of that warn stay true."""
    cap = _named(tmp_path, "name: L\ndescription: d\ncreated_at: not-a-date", capsys)
    assert len(cap.err.splitlines()) == 1
    assert "trace is unwindowed" in cap.err
    assert '"not-a-date"' in cap.err


def test_d_a7_named_warn_distinguishes_absent(tmp_path, capsys):
    """d: a7 — absent created_at warns "no created_at" (a different curator fix than a
    garbage value), still one line, still unwindowed."""
    cap = _named(tmp_path, "name: L\ndescription: d", capsys)
    assert len(cap.err.splitlines()) == 1
    assert "trace is unwindowed" in cap.err
    assert "no created_at" in cap.err


def test_d_a8_header_never_prints_since_none(tmp_path, capsys):
    """d: a8 — the header renders an honest unwindowed form carrying the quoted value,
    never the Python ``None`` sentinel; it stays exactly one ``#``-prefixed line so
    ``_case_ids``-style consumers can't mistake it for a case row."""
    cap = _named(tmp_path, "name: L\ndescription: d\ncreated_at: not-a-date", capsys)
    lines = cap.out.splitlines()
    header = lines[0]
    assert header.startswith("# L")
    assert "since None" not in cap.out
    assert '"not-a-date"' in header
    assert sum(ln.startswith("#") for ln in lines) == 1
    assert _case_ids(cap.out) == ["caseA", "caseB"]  # unwindowed: both cases trace


def test_d_a8b_header_honest_when_absent(tmp_path, capsys):
    """d: a8 — the absent half: no ``since None``, and the header says there is no
    created_at to window on."""
    cap = _named(tmp_path, "name: L\ndescription: d", capsys)
    header = cap.out.splitlines()[0]
    assert "since None" not in cap.out
    assert "no created_at" in header


# ---------------------------------------------------------------------------
# #596 — echo sanitization: line/column breakers and the clamp (a9–a10)
# ---------------------------------------------------------------------------

# Every char ``str.splitlines`` treats as a line boundary, plus tab: the \t/\n-only
# flatten idiom is provably insufficient for a value that lands in a TSV consumed via
# splitlines() (\r, \x0b, \x0c, \x85,  ,   all split there).
_HOSTILE_VALUE = '"a\\tb\\nc\\rd\\x0Be\\x0Cf\\x85g\\u2028h\\u2029i"'
_HOSTILE_CREATED_AT = f"created_at: {_HOSTILE_VALUE}"


def test_d_a9_all_echo_survives_every_line_breaker(tmp_path, capsys):
    """d: a9 (negative + control) — a value carrying every splitlines breaker and a tab
    forges no extra row and no fourth column in ``--all``; the control is the flattened
    value visible in the marker (each breaker → one space), proving the echo happened."""
    row, cap = _all_row(tmp_path, f"name: L\ndescription: d\n{_HOSTILE_CREATED_AT}", capsys)
    assert len(cap.out.splitlines()) == 1
    assert row.count("\t") == 2
    assert "a b c d e f g h i" in row.split("\t")[1]


def test_d_a9b_named_surfaces_survive_every_line_breaker(tmp_path, capsys):
    """d: a9 — the same value on the named path: the stderr warn stays one line and the
    stdout stays one header + the case rows, nothing forged on either stream."""
    cap = _named(tmp_path, f"name: L\ndescription: d\n{_HOSTILE_CREATED_AT}", capsys)
    assert len(cap.err.splitlines()) == 1
    lines = cap.out.splitlines()
    assert len(lines) == 3  # header + caseA + caseB, no forged line
    assert sum(ln.startswith("#") for ln in lines) == 1
    assert "a b c d e f g h i" in lines[0]


def test_d_a10_echo_is_clamped_to_80_chars(tmp_path, capsys):
    """d: a10 — a huge value cannot bloat the row: the echo shows the first 80 chars of
    the flattened value and an ``…`` continuation, never the full payload."""
    row, _ = _all_row(tmp_path, f'name: L\ndescription: d\ncreated_at: "{"x" * 500}"', capsys)
    desc_col = row.split("\t")[1]
    assert "x" * 80 in desc_col
    assert "x" * 81 not in desc_col
    assert "…" in desc_col


# ---------------------------------------------------------------------------
# #596 — positive control, row uniqueness, sibling columns (a11–a13)
# ---------------------------------------------------------------------------


def test_d_a11_windowed_lesson_is_unmarked_everywhere(tmp_path, capsys):
    """d: a11 (positive control) — a parseable created_at gets exactly the old behavior:
    a plain 3-column row with the WINDOWED count, no marker, no warn, and a header that
    prints the real window start."""
    row, cap = _all_row(tmp_path, "name: L\ndescription: d\ncreated_at: 2026-06-04", capsys)
    assert row == "L\td\t1"  # only the post-created_at load counts
    assert cap.err == ""

    named = _named(tmp_path, "name: M\ndescription: d\ncreated_at: 2026-06-04", capsys, stem="M")
    assert named.err == ""
    assert "since 2026-06-04" in named.out.splitlines()[0]
    assert _case_ids(named.out) == ["caseB"]


def test_d_a12_every_discovered_lesson_appears_exactly_once(tmp_path, capsys):
    """d: a12 (uniqueness + marker vocabulary) — a flooded lesson, an unparseable-window
    lesson, and a healthy lesson land as one row each, in distinct vocabularies: the
    flood row says "malformed lesson", the valid-but-unwindowed row says "unwindowed"
    and must NOT say "malformed", the healthy row is plain."""
    tl = _load_tl()
    lessons = tmp_path / "lessons"
    _mk_lesson(lessons, "badts", body_frontmatter="name: badts\ndescription: bd\ncreated_at: not-a-date")
    _mk_lesson(lessons, "good", body_frontmatter="name: good\ndescription: g\ncreated_at: 2026-06-04")
    (lessons / "flood.md").write_text(_flood_doc(_flow_flood()), encoding="utf-8")
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition="benign",
            loads=[{"lesson_name": s, "ts": "2026-06-05T00:00:00+00:00"}
                   for s in ("badts", "good", "flood")])
    rc = tl.main(["--all", "--lessons-dir", str(lessons), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0
    lines = cap.out.splitlines()
    stems = [ln.split("\t")[0] for ln in lines]
    assert sorted(stems) == ["badts", "flood", "good"]  # each exactly once
    by_stem = {ln.split("\t")[0]: ln for ln in lines}
    assert "malformed lesson" in by_stem["flood"]
    assert "unwindowed" in by_stem["badts"]
    assert "malformed" not in by_stem["badts"]
    assert by_stem["good"] == "good\tg\t1"


def test_d_a13_named_rows_flatten_disposition_and_ts(tmp_path, capsys):
    """d: a13 — the named path's other two columns are LLM/hook-authored too: a tab or
    newline in report.md's disposition or a lessons_loaded ts must not forge a column
    or a row (the created_at bug class, one field over)."""
    tl = _load_tl()
    lessons = tmp_path / "lessons"
    _mk_lesson(lessons, "L", body_frontmatter="name: L\ndescription: d")  # unwindowed → hostile ts qualifies
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "caseA", disposition='"ben\\tign\\nX"',
            loads=[{"lesson_name": "L", "ts": "2026-06-05\t00:00:00+00:00"}])
    rc = tl.main(["L", "--lessons-dir", str(lessons), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0
    lines = cap.out.splitlines()
    assert len(lines) == 2  # header + exactly one case row
    row = lines[1]
    assert row.count("\t") == 2
    assert row.split("\t") == ["caseA", "ben ign X", "2026-06-05 00:00:00+00:00"]


def test_d_a14_all_description_survives_every_line_breaker(tmp_path, capsys):
    """d: a14 — the ``--all`` description column is the same LLM-authored value-in-TSV
    class as the echo: every splitlines breaker + tab in it forges no row and no column
    (the \\t/\\n-only flatten this column used to get is provably insufficient)."""
    row, cap = _all_row(
        tmp_path, f"name: L\ndescription: {_HOSTILE_VALUE}\ncreated_at: 2026-06-04", capsys
    )
    assert len(cap.out.splitlines()) == 1
    assert row.count("\t") == 2
    assert row.split("\t")[1] == "a b c d e f g h i"


def test_d_a14b_filename_id_columns_survive_breakers(tmp_path, capsys):
    """d: a14 — the id columns are filenames (lesson stem, run-dir case_id), and Unix
    filenames legally carry tab/newline: neither forges a row or a column, on either
    path, and the named header stays one ``#`` line."""
    tl = _load_tl()
    lessons = tmp_path / "lessons"
    _mk_lesson(lessons, "st\tem", body_frontmatter="name: L\ndescription: d\ncreated_at: 2026-06-04")
    runs = tmp_path / "runs"
    runs.mkdir()
    _mk_run(runs, "case\nA", disposition="benign",
            loads=[{"lesson_name": "st\tem", "ts": "2026-06-05T00:00:00+00:00"}])

    rc = tl.main(["--all", "--lessons-dir", str(lessons), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0
    [row] = cap.out.splitlines()
    assert row.split("\t") == ["st em", "d", "1"]

    rc = tl.main(["st\tem", "--lessons-dir", str(lessons), "--runs-dir", str(runs)])
    cap = capsys.readouterr()
    assert rc == 0
    lines = cap.out.splitlines()
    assert len(lines) == 2  # one header + one case row, nothing forged
    assert lines[0].startswith("# st em — ")
    assert lines[1].split("\t") == ["case A", "benign", "2026-06-05T00:00:00+00:00"]
