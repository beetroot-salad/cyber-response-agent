"""#1347 r6.4 P6/O9/A8/O11: a run scores only through a row bound to its case's current binding.

The fixtures dir holds `<slug>/{alert.json, ground_truth.yaml, case.yaml}` and
`freezes/<freeze-id>/freeze.yaml`. An index row is `{slug, run_id, binding, knowledge, verdict,
reason, verified_at}`; `binding` is the canonical-JSON sha256 of `[freeze digest, case digest]`
(sorted keys, compact separators, bare lowercase hex) over the parsed YAML, `confirmed` included.
The test-side oracle is `_frozen_cases`. Entry point:
`evaluations.held_out.main([runs, "--index", F, "--fixtures-dir", D])`.
"""
from __future__ import annotations

import io
import random
import re
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
import yaml

from evaluations.tests import _frozen_cases as F
from evaluations.tests._frozen_cases import FREEZE, FREEZE_ID, case_doc, row
from test_held_out_scoring import _fixture_set, _run

GOOD, OTHER = "m05-off-hours-sudo", "m07-cron-persistence"


def case_file(root: Path, slug: str) -> Path:
    return root / slug / "case.yaml"


def freeze_file(root: Path) -> Path:
    return root / "freezes" / FREEZE_ID / "freeze.yaml"


def fixtures(tmp_path: Path) -> Path:
    return _fixture_set(tmp_path / "held_out", {GOOD: "benign", OTHER: "malicious"})


def scored(tmp_path: Path, runs: Path, root: Path, *rows: object) -> tuple[int, dict[str, str], str]:
    """(exit code, {slug: OK|WRONG}, everything printed)."""
    from evaluations import held_out

    index = F.write_index(tmp_path / "ops" / "held-out-index.jsonl", *rows)
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = held_out.main([str(runs), "--index", str(index), "--fixtures-dir", str(root)])
    except SystemExit as exit_:
        rc = exit_.code
    text = out.getvalue()
    verdicts = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("OK", "WRONG") and parts[1].endswith(":"):
            verdicts[parts[1][:-1]] = parts[0]
    return rc, verdicts, f"{text}\n{err.getvalue()}"


def why(said: str, slug: str) -> str:
    """The lowercased listing lines naming `slug` that are not a score line."""
    return " ".join(ln.lower() for ln in said.splitlines()
                    if slug in ln and ln.split()[:1] not in (["OK"], ["WRONG"]))


def pair(runs: Path) -> tuple[str, str]:
    """Run ids of a right answer for GOOD and for OTHER."""
    return _run(runs, says="benign").name, _run(runs, says="malicious").name


def rows_for(root: Path, runs: Path) -> list[dict]:
    good, other = pair(runs)
    return [row(root, GOOD, good), row(root, OTHER, other)]


def test_rows_bound_to_each_cases_current_binding_score_and_a_complete_set_exits_zero(tmp_path):
    """O9/O11 positive control: every case has a row matching its binding; the set scores,
    exits 0 and is not called incomplete."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    good, other = pair(runs)

    rc, verdicts, said = scored(tmp_path, runs, root, row(root, GOOD, good), row(root, OTHER, other))

    assert (rc, verdicts) == (0, {GOOD: "OK", OTHER: "OK"}), said
    assert "incomplete" not in said.lower(), said


def test_a_row_for_another_binding_does_not_count_and_the_set_is_incomplete(tmp_path):
    """P6/O11: after the case file changes (here: re-confirmed), its older row's binding no
    longer matches; the case is listed with a reason, the rest scores, the report says incomplete
    and exits non-zero (not the refusal code 2)."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    old = row(root, GOOD, _run(runs, says="benign").name)
    case_file(root, GOOD).write_text(yaml.safe_dump(case_doc(
        GOOD, confirmed={"by": "op2", "at": "2026-11-01T10:00:00Z", "reference_run": "ref-2"})))
    other = row(root, OTHER, _run(runs, says="malicious").name)

    rc, verdicts, said = scored(tmp_path, runs, root, old, other)

    assert verdicts == {OTHER: "OK"}, said
    assert GOOD in said, said
    assert GOOD not in verdicts, said
    assert "incomplete" in said.lower(), said
    assert rc not in (0, 2), said


def test_a_run_whose_queries_use_now_still_scores(tmp_path):
    """Withdrawn: the scorer's "now" scan. The frozen cluster's clock is T (D15), so `now()` in
    a bound run's queries means the freeze moment; the run scores like any other."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    good = _run(runs, says="benign")
    (good / "executed_queries.jsonl").write_text(json.dumps(
        {"lead_id": "l-001", "seq": 0, "system": "elastic", "verb": "esql", "query_id": "elastic.esql",
         "params": {"query": "FROM logs-* | WHERE @timestamp > now() - 1 hour | LIMIT 5"}}) + "\n")
    other = _run(runs, says="malicious").name

    rc, verdicts, said = scored(tmp_path, runs, root, row(root, GOOD, good.name), row(root, OTHER, other))

    assert (rc, verdicts) == (0, {GOOD: "OK", OTHER: "OK"}), said


def test_the_scorer_module_owns_the_binding_function(tmp_path):
    """A8: `held_out.binding(freeze, case)` over the parsed docs is the one owner (the lab
    imports it); it equals the oracle and is bare lowercase hex."""
    from evaluations import held_out

    bound = held_out.binding(FREEZE, case_doc(GOOD))

    assert bound == F.digest([F.digest(FREEZE), F.digest(case_doc(GOOD))])
    assert len(bound) == 64
    assert bound == bound.lower()
    assert set(bound) <= set("0123456789abcdef")


def test_a_changed_freeze_file_unbinds_every_older_row(tmp_path):
    """P6/A8: the freeze digest is half the binding; editing freeze.yaml leaves both cases
    listed unscored and the set incomplete."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    rows = rows_for(root, runs)
    freeze_file(root).write_text(yaml.safe_dump({**FREEZE, "captured_by": "someone-else"}))

    rc, verdicts, said = scored(tmp_path, runs, root, *rows)

    assert verdicts == {}, said
    assert GOOD in why(said, GOOD) + said, said
    assert OTHER in said, said
    assert "incomplete" in said.lower(), said
    assert rc not in (0, 2), said


def test_comments_key_order_and_line_endings_do_not_change_which_rows_count(tmp_path):
    """A8: a case.yaml re-saved with comments, reversed keys and CRLF is the same case (its row
    scores); a changed value is another case (its row does not)."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    rows = rows_for(root, runs)
    doc = case_doc(GOOD)
    text = "# re-saved by hand\n" + yaml.safe_dump(dict(reversed(list(doc.items()))), sort_keys=False)
    case_file(root, GOOD).write_bytes(text.replace("\n", "\r\n").encode())

    rc, verdicts, said = scored(tmp_path, runs, root, *rows)
    assert (rc, verdicts) == (0, {GOOD: "OK", OTHER: "OK"}), said

    case_file(root, GOOD).write_text(yaml.safe_dump(case_doc(GOOD, age=3001)))
    _rc, changed, said = scored(tmp_path, runs, root, *rows)
    assert changed == {OTHER: "OK"}, said


@pytest.mark.parametrize("unicode_text", [False, True], ids=["escaped", "raw-utf8"])
def test_non_ascii_values_hash_in_json_dumps_default_form(tmp_path, unicode_text):
    """A8: non-ASCII values hash as `json.dumps`' default ASCII-escaped form however the YAML
    spells them."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    case_file(root, GOOD).write_text(yaml.safe_dump(case_doc(GOOD, confirmed={
        "by": "opérateur ☃", "at": "2026-10-21T10:00:00Z", "reference_run": "r"}),
        allow_unicode=unicode_text), encoding="utf-8")

    rc, verdicts, said = scored(tmp_path, runs, root, *rows_for(root, runs))

    assert (rc, verdicts) == (0, {GOOD: "OK", OTHER: "OK"}), said


@pytest.mark.parametrize("variant", ["uppercase", "tail", "prefix", "case-digest-only", "freeze-digest-only"])
def test_only_the_whole_lowercase_binding_binds(tmp_path, variant):
    """A8: uppercase hex, a binding off in its last character, a truncated one, or one built from
    only half of the pair does not bind; the case is listed unscored."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    real = F.binding(root, GOOD)
    case = yaml.safe_load(case_file(root, GOOD).read_text())
    forged = {"uppercase": real.upper(), "tail": real[:-1] + ("0" if real[-1] != "0" else "1"),
              "prefix": real[:32], "case-digest-only": F.digest(case),
              "freeze-digest-only": F.digest(FREEZE)}[variant]
    good, other = pair(runs)

    rc, verdicts, said = scored(tmp_path, runs, root, row(root, GOOD, good, binding=forged),
                                row(root, OTHER, other))

    assert verdicts == {OTHER: "OK"}, said
    assert GOOD in said, said
    assert "incomplete" in said.lower(), said
    assert rc not in (0, 2), said


def test_a_row_with_the_old_freeze_key_and_no_binding_never_counts_and_is_not_refused(tmp_path):
    """O9/A8: a pre-r6.4 `{slug, run_id, freeze, ...}` row has no binding; it scores nothing,
    the case is listed, the set is incomplete, and the index is not refused."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    good, other = pair(runs)
    legacy = {"slug": GOOD, "run_id": good, "freeze": F.digest(FREEZE), "verdict": "valid",
              "reason": "", "verified_at": "2026-11-08T12:30:00Z"}

    rc, verdicts, said = scored(tmp_path, runs, root, legacy, row(root, OTHER, other))

    assert verdicts == {OTHER: "OK"}, said
    assert GOOD in said, said
    assert "incomplete" in said.lower(), said
    assert rc not in (0, 2), said


def test_a_stale_newest_row_is_not_scored_and_the_case_needs_reconfirmation(tmp_path):
    """A2/O11: a stale row is not scored; the case is listed as needing re-confirmation with the
    row's own reason, the rest scores, incomplete, non-zero."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    good, other = pair(runs)
    reason = "counts differ in logs-system.auth-2026.10"
    stale = row(root, OTHER, other, verdict="stale", reason=reason)

    rc, verdicts, said = scored(tmp_path, runs, root, row(root, GOOD, good), stale)

    assert verdicts == {GOOD: "OK"}, said
    assert "re-confirm" in why(said, OTHER), said
    assert reason in why(said, OTHER), said
    assert "Aggregate accuracy: 1/1" in said, said
    assert "incomplete" in said.lower(), said
    assert rc not in (0, 2), said


def test_the_newest_matching_row_decides_between_stale_and_valid(tmp_path):
    """A2: a later stale row un-scores the case despite an earlier valid one; a later valid row
    after a stale one scores; a later row of another binding changes neither."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    valid, stale = row(root, GOOD, pair(runs)[0]), row(root, GOOD, pair(runs)[0], verdict="stale")
    other = row(root, OTHER, pair(runs)[1])
    foreign = row(root, GOOD, pair(runs)[1], binding="0" * 64, verdict="stale")

    _rc, went_stale, said = scored(tmp_path, runs, root, valid, stale, other)
    assert GOOD not in went_stale, said
    assert "re-confirm" in why(said, GOOD), said
    rc, recovered, said = scored(tmp_path, runs, root, stale, valid, foreign, other)
    assert (rc, recovered) == (0, {GOOD: "OK", OTHER: "OK"}), said


def test_every_case_not_scored_is_listed_with_its_reason_and_the_set_is_incomplete(tmp_path):
    """O11/A2: scored, no row, stale and old-binding cases are each listed with a reason; only the
    first scores; incomplete, non-zero."""
    root = _fixture_set(tmp_path / "held_out", {
        "a-scored": "benign", "b-no-row": "benign", "c-stale": "benign", "d-old": "malicious"})
    runs = tmp_path / "runs"
    old = row(root, "d-old", _run(runs, says="malicious").name)
    case_file(root, "d-old").write_text(yaml.safe_dump(case_doc("d-old", age=1)))

    rc, verdicts, said = scored(
        tmp_path, runs, root, row(root, "a-scored", _run(runs, says="benign").name),
        row(root, "c-stale", _run(runs, says="benign").name, verdict="stale"), old)

    assert verdicts == {"a-scored": "OK"}, said
    assert "not run" in why(said, "b-no-row"), said
    assert "re-confirm" in why(said, "c-stale"), said
    assert why(said, "d-old"), said
    assert "Aggregate accuracy: 1/1" in said, said
    assert "incomplete" in said.lower(), said
    assert rc not in (0, 2), said


def test_a_reference_run_without_a_row_leaves_its_case_unscored(tmp_path):
    """O9: reference mode writes no row, so a run folder (the case's `confirmed.reference_run`)
    that no row names scores nothing; the case is listed, the set incomplete."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    reference = _run(runs, says="benign")
    case_file(root, GOOD).write_text(yaml.safe_dump(case_doc(
        GOOD, confirmed={"by": "op", "at": "2026-10-21T10:00:00Z", "reference_run": reference.name})))

    rc, verdicts, said = scored(tmp_path, runs, root, row(root, OTHER, pair(runs)[1]))

    assert verdicts == {OTHER: "OK"}, said
    assert "not run" in why(said, GOOD), said
    assert "incomplete" in said.lower(), said
    assert rc not in (0, 2), said


def test_a_fixture_labelled_held_out_without_a_case_file_refuses_the_whole_set(tmp_path):
    """r6.4.3 finding 8 (supersedes A2's "a fixture with no case.yaml is neither scored nor listed"): a
    fixture labelled `held_out: true` with no case.yaml would shrink the denominator silently; the set is
    refused like any case that cannot be bound (exit 2, the fixture named), nothing scored."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    rows = rows_for(root, runs)
    legacy = root / "z-legacy"
    legacy.mkdir()
    (legacy / "alert.json").write_text("{}")
    (legacy / "ground_truth.yaml").write_text("held_out: true\ndisposition: benign\n")

    rc, verdicts, said = scored(tmp_path, runs, root, *rows)

    assert rc == 2, said
    assert verdicts == {}, said
    assert "z-legacy" in said and "refused" in said, said


def test_a_fixture_not_labelled_held_out_needs_no_case_file(tmp_path):
    """r6.4.3 finding 8, control: a fixture without `held_out: true` is not part of the set; with no
    case.yaml it is ignored and the set scores and exits 0."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    rows = rows_for(root, runs)
    other = root / "z-not-held-out"
    other.mkdir()
    (other / "alert.json").write_text("{}")
    (other / "ground_truth.yaml").write_text("disposition: benign\n")

    rc, verdicts, said = scored(tmp_path, runs, root, *rows)

    assert (rc, verdicts) == (0, {GOOD: "OK", OTHER: "OK"}), said
    assert "incomplete" not in said.lower(), said


def test_a_case_naming_a_missing_freeze_refuses_the_whole_set(tmp_path):
    """A2: a case whose freeze file is absent has no binding; the set is refused (exit 2, case
    named), nothing scored."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    case_file(root, OTHER).write_text(yaml.safe_dump(case_doc(OTHER, freeze="f-nowhere")))

    rc, verdicts, said = scored(tmp_path, runs, root, row(root, GOOD, pair(runs)[0]))

    assert rc == 2, said
    assert verdicts == {}, said
    assert OTHER in said, said
    assert "refused" in said, said


def test_a_case_value_canonical_json_cannot_carry_refuses_the_whole_set(tmp_path):
    """A8: an unquoted YAML timestamp parses to a datetime that canonical JSON cannot carry:
    exit 2, the case named, nothing scored."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    text = case_file(root, OTHER).read_text()
    unquoted = text.replace("at: '2026-10-21T10:00:00Z'", "at: 2026-10-21T10:00:00Z")
    assert unquoted != text
    case_file(root, OTHER).write_text(unquoted)

    rc, verdicts, said = scored(tmp_path, runs, root, row(root, GOOD, pair(runs)[0]))

    assert rc == 2, said
    assert verdicts == {}, said
    assert OTHER in said, said
    assert "refused" in said, said


MALFORMED = {
    "not-json": "not json",
    "not-an-object": "[1, 2]",
    "binding-number": {"binding": 123},
    "binding-list": {"binding": ["a"]},
    "verdict-missing": {"verdict": None},
    "verdict-ok": {"verdict": "ok"},
    "verdict-uppercase": {"verdict": "VALID"},
    "verdict-number": {"verdict": 1},
    "knowledge-number": {"knowledge": 7},
    "knowledge-list": {"knowledge": ["k"]},
    "run-id-missing": {"run_id": None},
    "run-id-not-an-id": {"run_id": "../escape"},
    "slug-number": {"slug": 5},
}


@pytest.mark.parametrize("kind", MALFORMED)
def test_a_malformed_index_row_refuses_the_whole_index(tmp_path, kind):
    """A2/O9: any malformed row refuses the index (exit 2), nothing scored, even beside
    well-formed rows."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    good, other = pair(runs)
    spec = MALFORMED[kind]
    bad = spec if isinstance(spec, str) else row(root, OTHER, other, **spec)

    rc, verdicts, said = scored(tmp_path, runs, root, row(root, GOOD, good), bad)

    assert rc == 2, said
    assert verdicts == {}, said


@pytest.mark.parametrize("pinless", [None, ""], ids=["null", "empty"])
def test_a_row_with_no_knowledge_pin_scores_normally(tmp_path, pinless):
    """A2/O9 (FR7): a null or "" `knowledge` (a pinless launch) does not refuse the index."""
    root, runs = fixtures(tmp_path), tmp_path / "runs"
    good, other = pair(runs)
    index = F.write_index(tmp_path / "ops" / "held-out-index.jsonl", row(root, GOOD, good),
                          {**row(root, OTHER, other), "knowledge": pinless})

    rc, verdicts, said = scored(tmp_path, runs, root, *[json.loads(ln) for ln in index.read_text().splitlines()])

    assert (rc, verdicts) == (0, {GOOD: "OK", OTHER: "OK"}), said


def test_the_report_gives_each_cases_age_band_at_t(tmp_path):
    """A2 note (G1): under 1 h, 1-3 h and 3-6 h each appear on the line naming the case."""
    slugs = {"a-young": (1800, r"(under|<)\s*1\s*h"), "b-mid": (7200, r"1\s*[-\u2013]\s*3\s*h"),
             "c-old": (14400, r"3\s*[-\u2013]\s*6\s*h")}
    root = _fixture_set(tmp_path / "held_out", {s: "benign" for s in slugs})
    runs = tmp_path / "runs"
    for slug, (age, _) in slugs.items():
        case_file(root, slug).write_text(yaml.safe_dump(case_doc(slug, age=age)))

    rc, verdicts, said = scored(tmp_path, runs, root,
                                *[row(root, s, _run(runs, says="benign").name) for s in slugs])

    for slug, (_, band) in slugs.items():
        lines = [ln.lower() for ln in said.splitlines() if slug in ln]
        assert any(re.search(band, ln) for ln in lines), f"{slug} has no age band {band}:\n{said}"
        for other, (_, wrong) in slugs.items():
            if other != slug:
                assert not any(re.search(wrong, ln) for ln in lines), f"{slug} shows {other}'s band:\n{said}"


HOUR = 3600
BANDS = {"under 1 h": r"(under|<)\s*1\s*h", "1-3 h": r"1\s*[-\u2013]\s*3\s*h", "3-6 h": r"3\s*[-\u2013]\s*6\s*h"}


def test_every_age_from_zero_to_six_hours_is_reported_in_exactly_one_age_band(tmp_path):
    """A2 note (G1): any age in [0, 6 h], both ends and each band edge included, shows one band
    (6 h itself in 3-6 h), never "over 6 h"."""
    rng = random.Random(1347)
    edges = [0, 1, HOUR - 1, HOUR, HOUR + 1, 3 * HOUR - 1, 3 * HOUR, 3 * HOUR + 1, 6 * HOUR - 1, 6 * HOUR]
    ages = sorted({*edges, *(rng.randint(0, 6 * HOUR) for _ in range(14))})
    slugs = {f"age-{a:05d}": a for a in ages}
    root = _fixture_set(tmp_path / "held_out", {s: "benign" for s in slugs})
    runs = tmp_path / "runs"
    for slug, age in slugs.items():
        case_file(root, slug).write_text(yaml.safe_dump(case_doc(slug, age=age)))

    _rc, _verdicts, said = scored(tmp_path, runs, root,
                                  *[row(root, s, _run(runs, says="benign").name) for s in slugs])

    for slug, age in slugs.items():
        line = " ".join(ln.lower() for ln in said.splitlines() if slug in ln)
        shown = {band for band, pattern in BANDS.items() if re.search(pattern, line)}
        assert len(shown) == 1, f"age {age} s shows {sorted(shown)}:\n{said}"
        assert not re.search(r"over\s*6|>\s*6", line), f"age {age} s is called over 6 h:\n{said}"
        if age not in (HOUR, 3 * HOUR):  # which band owns exactly 1 h and 3 h is not settled
            want = "under 1 h" if age < HOUR else "1-3 h" if age < 3 * HOUR else "3-6 h"
            assert shown == {want}, f"age {age} s shows {sorted(shown)}, not {want}:\n{said}"
