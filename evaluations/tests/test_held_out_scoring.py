"""Held-out scoring through an explicit fixture-to-run index."""
from __future__ import annotations

import hashlib
import io
import json
import os
import uuid
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest
import yaml

from evaluations.held_out import (
    load_held_out_fixtures,
    warn_if_outside_the_net,
)
from defender.records import RunPaths
from defender.run_common import HELD_OUT_FIXTURES, _alert_label
from defender.tests.support.storage._alert_plant import plant_alert

SLUG = "m05-lsass-access"
GOOD_UNTIL = "2026-10-20T09:00:00Z"


def freeze_doc(**override) -> dict:
    """A #1347 r6 `freeze.yaml` document, confirmed; `override` replaces top-level keys (a
    value of `None` drops the key)."""
    doc = {
        "alert_at": "2026-10-20T08:00:00Z", "as_of": GOOD_UNTIL,
        "window": ["2026-09-19T08:00:00Z", GOOD_UNTIL],
        "captured_at": "2026-10-20T09:03:17Z",
        "fingerprint": {"logs-system.auth-2026.10.20|2026-10-20T08": [1200, 1200]},
        "parts": {}, "chaos": None,
        "confirmed": {"by": "operator", "at": "2026-10-20T10:00:00Z",
                      "reference_run": "11111111-1111-4111-8111-111111111111"},
    }
    doc.update(override)
    return {k: v for k, v in doc.items() if v is not None or k == "chaos"}


def write_freeze(member: Path, **override) -> None:
    (member / "freeze.yaml").write_text(
        yaml.safe_dump(freeze_doc(**override), sort_keys=False), encoding="utf-8")


def freeze_digest(member: Path) -> str:
    """The freeze digest D13/O9 define: sha256 of the parsed freeze.yaml as sorted-key compact
    JSON (bare hex; the design does not fix a `sha256:` prefix — see the design-gap note)."""
    doc = yaml.safe_load((member / "freeze.yaml").read_text(encoding="utf-8"))
    return hashlib.sha256(
        json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _fixture_set(root: Path, truths: dict[str, str], *, frozen: bool = True) -> Path:
    """Held-out fixtures; each carries a confirmed `freeze.yaml` (O9) unless `frozen=False`."""
    for slug, disposition in truths.items():
        member = root / slug
        member.mkdir(parents=True)
        (member / "alert.json").write_text("{}", encoding="utf-8")
        (member / "ground_truth.yaml").write_text(
            f"held_out: true\ndisposition: {disposition}\n", encoding="utf-8")
        if frozen:
            write_freeze(member)
    return root


def _run(runs: Path, name: str | None = None, *, says: str | None = None,
         queries: list[dict] | None = None) -> Path:
    """A recorded run folder `<runs>/<name>` (a fresh UUID by default), with a `report.md`
    carrying `says` when given and an `executed_queries.jsonl` of `queries` when given."""
    run_dir = runs / (name or str(uuid.uuid4()))
    run_dir.mkdir(parents=True)
    plant_alert(run_dir)
    if says is not None:
        (run_dir / "report.md").write_text(
            f"---\ndisposition: {says}\noutcome: stands\n---\nbody\n", encoding="utf-8")
    if queries is not None:
        RunPaths(run_dir).executed_queries.write_text(
            "".join(json.dumps(q) + "\n" for q in queries), encoding="utf-8")
    return run_dir


def _row(fixtures: Path, slug: str, run_id: str, **override) -> dict:
    """An r6 index row for `run_id` bound to the case's CURRENT freeze, verdict valid;
    `override` replaces fields (a value of `None` drops the field)."""
    row = {"slug": slug, "run_id": run_id, "freeze": freeze_digest(fixtures / slug),
           "verdict": "valid", "reason": "", "verified_at": "2026-10-20T11:00:00Z"}
    row.update(override)
    return {k: v for k, v in row.items() if v is not None}


def _scored_rc(tmp_path: Path, runs: Path, fixtures: Path, *rows) -> tuple[int, str]:
    """`held_out.main` over an index of `rows`, oldest first: a `(slug, run_id)` pair becomes a
    `_row` for the case's current freeze; a dict is written verbatim. Returns (exit code,
    stdout + stderr)."""
    from evaluations import held_out

    index = tmp_path / "ops" / "held-out-index.jsonl"
    index.parent.mkdir(parents=True, exist_ok=True)
    lines = [r if isinstance(r, dict) else _row(fixtures, *r) for r in rows]
    index.write_text("".join(json.dumps(r) + "\n" for r in lines), encoding="utf-8")
    out, err = io.StringIO(), io.StringIO()
    rc = 0
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = held_out.main([str(runs), "--index", str(index), "--fixtures-dir", str(fixtures)])
    except SystemExit as e:
        rc = e.code if isinstance(e.code, int) else 1
    return rc, f"{out.getvalue()}\n{err.getvalue()}"


def _verdicts(text: str) -> dict[str, str]:
    verdicts: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("OK", "WRONG") and parts[1].endswith(":"):
            verdicts[parts[1][:-1]] = parts[0]
    return verdicts


def unscored(text: str, slugs) -> dict[str, str]:
    """`{slug: lowercased heading + line}` for each slug the report lists outside a verdict line
    and outside the failure bucket (O11: not scored, with its reason). Either a per-reason
    heading or a reason on the line satisfies a caller's keyword check."""
    listed: dict[str, str] = {}
    heading = None
    for line in text.splitlines():
        if line.startswith("## "):
            heading = line.lower()
            continue
        if heading is None or "class=" in heading or "failure" in heading:
            continue
        token = line.split()[0].rstrip(":") if line.split() else ""
        if token in slugs:
            listed[token] = f"{heading} {line}".lower()
    return listed


def _scored(tmp_path: Path, runs: Path, fixtures: Path,
            *rows) -> tuple[dict[str, str], list[str], str]:
    """Score `runs` through `held_out.main` (see `_scored_rc`). Returns `({slug: "OK" |
    "WRONG"}, slugs listed as not run, stdout + stderr)`."""
    _rc, text = _scored_rc(tmp_path, runs, fixtures, *rows)
    slugs = {p.name for p in fixtures.iterdir()}
    not_run = [s for s, why in unscored(text, slugs).items() if "not run" in why]
    return _verdicts(text), not_run, text


def test_secondary_harness_run_dirs_are_not_claimed_by_the_primary_metric(tmp_path: Path):
    """Folders named `<slug>`, `sec-eval-gen7-<slug>-<x>` and its `-replay` twin (the retired
    secondary metric's names, under the same runs base), each saying the wrong answer, claim
    nothing: the fixture is scored only from the run its index row names, by id (#1187)."""
    runs = tmp_path / "runs"
    for name in (SLUG, f"sec-eval-gen7-{SLUG}-ab12cd34", f"sec-eval-gen7-{SLUG}-ab12cd34-replay"):
        _run(runs, name, says="malicious")
    indexed = _run(runs, says="benign")
    fixtures = _fixture_set(tmp_path / "held-out", {SLUG: "benign"})
    verdicts, _, said = _scored(tmp_path, runs, fixtures, (SLUG, indexed.name))
    assert verdicts == {SLUG: "OK"}, f"a folder was claimed by its name:\n{said}"


def test_no_run_id_convention_claims_a_fixture(tmp_path: Path):
    """With no index row for the slug, a recorded, reported folder named `<slug>`,
    `<slug>-<attempt>` or `{utc_timestamp}-<slug>` leaves the slug `not_run`, out of the
    accuracy (#1187)."""
    for name in (SLUG, f"{SLUG}-attempt2", f"20260718t101500z-{SLUG}"):
        runs = tmp_path / name / "runs"
        _run(runs, name, says="benign")
        fixtures = _fixture_set(tmp_path / name / "held-out", {SLUG: "benign"})
        verdicts, not_run, said = _scored(tmp_path / name, runs, fixtures)
        assert verdicts == {}, f"{name}: a folder was claimed by its name:\n{said}"
        assert not_run == [SLUG], f"{name}: the slug with no row is not reported not run:\n{said}"


def test_the_alert_label_comes_from_the_fixture_folder_not_the_stem():
    """Every fixture is `{slug}/alert.json`, so the label comes from the parent dir, never the
    constant stem "alert"."""
    assert _alert_label(HELD_OUT_FIXTURES / SLUG / "alert.json") == SLUG
    assert _alert_label(Path("/x/y/wazuh-5710.json")) == "wazuh-5710"


def test_a_slug_that_prefixes_another_takes_nothing_from_its_row(tmp_path: Path):
    """A row names its slug exactly: `m05-lsass-access-v2`'s row scores its own run, and
    `m05-lsass-access`, with no row, is `not_run` despite a `<slug>-v2-attempt1` folder."""
    runs = tmp_path / "runs"
    _run(runs, f"{SLUG}-v2-attempt1", says="benign")
    v2 = _run(runs, says="benign")
    fixtures = _fixture_set(tmp_path / "held-out", {SLUG: "benign", f"{SLUG}-v2": "benign"})
    verdicts, not_run, said = _scored(tmp_path, runs, fixtures, (f"{SLUG}-v2", v2.name))
    assert verdicts == {f"{SLUG}-v2": "OK"}, said
    assert not_run == [SLUG], said


def test_the_newest_row_wins_not_the_newest_folder(tmp_path: Path):
    """The newest index row of a slug (the last appended) wins and folder age decides nothing:
    the run the newer row names is the OLDER folder."""
    runs = tmp_path / "runs"
    older_row = _run(runs, says="malicious")
    newer_row = _run(runs, says="benign")
    os.utime(newer_row, (1, 1))
    os.utime(older_row, (2, 2))
    fixtures = _fixture_set(tmp_path / "held-out", {SLUG: "benign"})
    verdicts, _, said = _scored(tmp_path, runs, fixtures,
                                (SLUG, older_row.name), (SLUG, newer_row.name))
    assert verdicts == {SLUG: "OK"}, f"the newest row's run was not the one scored:\n{said}"


def test_rows_naming_unresolvable_entries_score_wrong_and_cost_only_their_slug(tmp_path: Path):
    """A row naming a dangling link or a regular file names no run: that slug scores WRONG
    (launched, no run record) instead of vanishing from the denominator, and the rest of the
    eval goes on."""
    runs = tmp_path / "runs"
    fine = _run(runs, says="benign")
    dangling, a_file = str(uuid.uuid4()), str(uuid.uuid4())
    (runs / dangling).symlink_to(tmp_path / "nowhere")
    (runs / a_file).write_text("not a run dir", encoding="utf-8")
    fixtures = _fixture_set(tmp_path / "held-out",
                            {SLUG: "benign", "dangling-case": "benign", "file-case": "benign"})
    verdicts, not_run, said = _scored(tmp_path, runs, fixtures, (SLUG, fine.name),
                                      ("dangling-case", dangling), ("file-case", a_file))
    assert verdicts == {SLUG: "OK", "dangling-case": "WRONG", "file-case": "WRONG"}, said
    assert not_run == [], said


def test_labeled_fixture_with_no_alert_is_excluded_loudly(tmp_path: Path, capsys):
    """A labeled fixture that cannot be run must not vanish from the denominator in
    silence — a shrinking denominator is how a stable-looking score hides a lost case."""
    (tmp_path / "m01").mkdir()
    (tmp_path / "m01" / "ground_truth.yaml").write_text(
        "held_out: true\ndisposition: malicious\n", encoding="utf-8"
    )
    assert load_held_out_fixtures(tmp_path) == []
    err = capsys.readouterr().err
    assert "m01" in err
    assert "alert.json" in err


def test_un_run_fixtures_are_surfaced_not_scored_and_make_the_set_incomplete(tmp_path: Path):
    """The denominator counts only what was investigated (O11): un-run cases are listed as not
    run, the report says incomplete and exits non-zero. CONFLICT-UPDATED: was exit 0 / `score()`."""
    fixtures = _fixture_set(tmp_path / "held-out", {"b01-case": "benign", "m01-case": "malicious"})
    runs = tmp_path / "empty-runs"
    runs.mkdir()
    verdicts, not_run, said = _scored(tmp_path, runs, fixtures)
    assert verdicts == {}
    assert sorted(not_run) == ["b01-case", "m01-case"], said
    assert "incomplete" in said.lower(), said
    assert _scored_rc(tmp_path, runs, fixtures)[0] != 0


def test_divergent_fixture_set_warns_that_it_was_never_netted(tmp_path: Path, capsys):
    """The contamination net refuses runs from exactly one directory: scoring a different set
    means those runs were never refused, so the number may already be contaminated."""
    assert warn_if_outside_the_net(tmp_path) is True
    assert "NOT held out of learning" in capsys.readouterr().err
    assert warn_if_outside_the_net(HELD_OUT_FIXTURES) is False
    assert capsys.readouterr().err == ""


def test_every_authorable_disposition_is_a_label_and_scores_as_its_own_class(tmp_path: Path):
    """A fixture may be labelled with any disposition the agent can author — `false-positive`
    included — and a run that says exactly that label is scored right."""
    from evaluations.held_out import LABELS

    assert set(LABELS) == {"benign", "false-positive", "inconclusive", "malicious"}
    runs = tmp_path / "runs"
    fixtures = _fixture_set(tmp_path / "fixtures", {f"case-{d}": d for d in LABELS})
    rows = [(f"case-{d}", _run(runs, says=d).name) for d in LABELS]
    verdicts, _, stdout = _scored(tmp_path, runs, fixtures, *rows)
    assert verdicts == {f"case-{d}": "OK" for d in LABELS}
    assert "class=false-positive" in stdout


def test_a_benign_label_is_not_met_by_a_false_positive_answer(tmp_path: Path):
    """The classes are distinct: the scorer does not fold `false-positive` into `benign`."""
    runs = tmp_path / "runs"
    fixtures = _fixture_set(tmp_path / "fixtures", {SLUG: "benign"})
    verdicts, _, _ = _scored(tmp_path, runs, fixtures,
                             (SLUG, _run(runs, says="false-positive").name))
    assert verdicts == {SLUG: "WRONG"}


def test_a_label_outside_the_authorable_dispositions_refuses_the_whole_set(tmp_path: Path):
    """`unresolved` (host-only) and a typo are both refused, naming the fixtures, and nothing is
    scored — a stray label must not become a class of its own or shrink the denominator."""
    from evaluations import held_out

    fixtures = _fixture_set(tmp_path / "fixtures", {
        "a-good-one": "malicious", "host-only": "unresolved", "typo": "begnin"})
    with pytest.raises(held_out.FixturesRefused, match="host-only.*typo"):
        load_held_out_fixtures(fixtures)

    runs = tmp_path / "runs"
    runs.mkdir()
    index = tmp_path / "ops" / "index.jsonl"
    index.parent.mkdir()
    index.write_text("", encoding="utf-8")
    err = io.StringIO()
    with redirect_stderr(err), redirect_stdout(io.StringIO()):
        rc = held_out.main([str(runs), "--index", str(index), "--fixtures-dir", str(fixtures)])
    assert rc == 2
    assert "refused" in err.getvalue()
    assert "begnin" in err.getvalue()
