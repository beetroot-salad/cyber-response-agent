"""Held-out scoring through an explicit fixture-to-run index."""
from __future__ import annotations

import io
import json
import os
import uuid
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

import pytest

from evaluations.held_out import (
    load_held_out_fixtures,
    score,
    warn_if_outside_the_net,
)
from defender.run_common import HELD_OUT_FIXTURES, _alert_label
from defender.tests.support.storage._alert_plant import plant_alert

SLUG = "m05-lsass-access"


def _fixture_set(root: Path, truths: dict[str, str]) -> Path:
    for slug, disposition in truths.items():
        member = root / slug
        member.mkdir(parents=True)
        (member / "alert.json").write_text("{}", encoding="utf-8")
        (member / "ground_truth.yaml").write_text(
            f"held_out: true\ndisposition: {disposition}\n", encoding="utf-8")
    return root


def _run(runs: Path, name: str | None = None, *, says: str | None = None) -> Path:
    """A recorded run folder `<runs>/<name>` (a fresh UUID by default), with a `report.md`
    carrying `says` when given."""
    run_dir = runs / (name or str(uuid.uuid4()))
    run_dir.mkdir(parents=True)
    plant_alert(run_dir)
    if says is not None:
        (run_dir / "report.md").write_text(
            f"---\ndisposition: {says}\noutcome: stands\n---\nbody\n", encoding="utf-8")
    return run_dir


def _scored(tmp_path: Path, runs: Path, fixtures: Path,
            *rows: tuple[str, str]) -> tuple[dict[str, str], list[str], str]:
    """Score `runs` through `held_out.main` with an index holding `rows` (`(slug, run_id)`,
    oldest first) in the operator's folder. Returns `({slug: "OK" | "WRONG"}, not-run slugs,
    stdout)`."""
    from evaluations import held_out

    index = tmp_path / "ops" / "held-out-index.jsonl"
    index.parent.mkdir(parents=True, exist_ok=True)
    index.write_text("".join(json.dumps({"slug": s, "run_id": r}) + "\n" for s, r in rows),
                     encoding="utf-8")
    out, err = io.StringIO(), io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            held_out.main([str(runs), "--index", str(index), "--fixtures-dir", str(fixtures)])
    except SystemExit:
        pass
    text = out.getvalue()
    verdicts: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("OK", "WRONG") and parts[1].endswith(":"):
            verdicts[parts[1][:-1]] = parts[0]
    lines = text.splitlines()
    not_run: list[str] = []
    for i, line in enumerate(lines):
        if line.startswith("## Not run"):
            for ln in lines[i + 1:]:
                if not ln.strip() or ln.startswith("#"):
                    break
                not_run.append(ln.strip())
    return verdicts, not_run, f"{text}\n{err.getvalue()}"


def test_secondary_harness_run_dirs_are_not_claimed_by_the_primary_metric(tmp_path: Path):
    """The regression the name rule existed for: the retired frozen-actor secondary metric
    minted `sec-eval-gen{N}-{slug}-{attempt}` plus a `-replay` staging twin under the SAME runs
    base, and a substring match claimed both.

    #1187 declared change 14: no rule over names is left to get wrong. Folders named
    `<slug>`, `sec-eval-gen7-<slug>-<x>` and its `-replay` twin, each recorded and each saying
    the wrong answer, claim nothing; the fixture is scored from the run its index row names, by
    id — and only that run says the right answer.
    """
    runs = tmp_path / "runs"
    for name in (SLUG, f"sec-eval-gen7-{SLUG}-ab12cd34", f"sec-eval-gen7-{SLUG}-ab12cd34-replay"):
        _run(runs, name, says="malicious")
    indexed = _run(runs, says="benign")
    fixtures = _fixture_set(tmp_path / "held-out", {SLUG: "benign"})
    verdicts, _, said = _scored(tmp_path, runs, fixtures, (SLUG, indexed.name))
    assert verdicts == {SLUG: "OK"}, f"a folder was claimed by its name:\n{said}"


def test_no_run_id_convention_claims_a_fixture(tmp_path: Path):
    """Was `test_run_id_conventions_that_do_claim_a_fixture`: the bare `--run-id <slug>`, a
    `<slug>-<attempt>` suffix and the old minted `{utc_timestamp}-<slug>` shape each claimed
    the fixture.

    #1187 declared change 14: none does. With no index row for the slug, a recorded, reported
    folder under any of those names leaves the slug `not_run`, out of the accuracy.
    """
    for name in (SLUG, f"{SLUG}-attempt2", f"20260718t101500z-{SLUG}"):
        runs = tmp_path / name / "runs"
        _run(runs, name, says="benign")
        fixtures = _fixture_set(tmp_path / name / "held-out", {SLUG: "benign"})
        verdicts, not_run, said = _scored(tmp_path / name, runs, fixtures)
        assert verdicts == {}, f"{name}: a folder was claimed by its name:\n{said}"
        assert not_run == [SLUG], f"{name}: the slug with no row is not reported not run:\n{said}"


def test_the_alert_label_comes_from_the_fixture_folder_not_the_stem():
    """Was `test_the_default_run_id_satisfies_the_convention`, which also pinned that the
    `{stamp}-<slug>` id minted without `--run-id` was claimed by `_claimed_slug`.

    #1187 declared change 14: `_claimed_slug` is gone and a minted id is a bare UUID carrying
    no label (declared change 2), so that half is removed. What remains is the label's own
    derivation, which this slice does not change: every fixture is `{slug}/alert.json`, so the
    label comes from the parent dir, never the constant stem "alert".
    """
    assert _alert_label(HELD_OUT_FIXTURES / SLUG / "alert.json") == SLUG
    assert _alert_label(Path("/x/y/wazuh-5710.json")) == "wazuh-5710"


def test_a_slug_that_prefixes_another_takes_nothing_from_its_row(tmp_path: Path):
    """Was `test_longest_slug_wins_when_one_fixture_slug_prefixes_another`: the name matcher
    had to survive a fixture set where one slug prefixes another.

    #1187 declared change 14: a row names its slug exactly, so the prefix case dissolves.
    `m05-lsass-access-v2`'s row scores its own run; `m05-lsass-access`, with no row, is
    `not_run` — a `<slug>-v2-attempt1` folder notwithstanding.
    """
    runs = tmp_path / "runs"
    _run(runs, f"{SLUG}-v2-attempt1", says="benign")
    v2 = _run(runs, says="benign")
    fixtures = _fixture_set(tmp_path / "held-out", {SLUG: "benign", f"{SLUG}-v2": "benign"})
    verdicts, not_run, said = _scored(tmp_path, runs, fixtures, (f"{SLUG}-v2", v2.name))
    assert verdicts == {f"{SLUG}-v2": "OK"}, said
    assert not_run == [SLUG], said


def test_the_newest_row_wins_not_the_newest_folder(tmp_path: Path):
    """Was `test_most_recent_run_wins`: the folder with the newest mtime won.

    #1187 declared change 14: the newest index row of a slug — the last appended — wins, and
    folder age decides nothing. The run the newer row names is the OLDER folder.
    """
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
    """Was `test_index_survives_unresolvable_entries`: a dangling link and a regular file in the
    runs dir, named after the slug, cost that candidate and not the eval.

    #1187 declared change 14 (recheck X2): an entry is reached only through a row. A row naming
    a dangling link, or a regular file, names no run: that slug scores WRONG (launched, no run
    record) instead of vanishing from the denominator, and the eval goes on — the slug whose row
    names a real run is scored as usual.
    """
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


def test_un_run_fixtures_are_surfaced_not_scored(tmp_path: Path):
    """A fixture with no run is surfaced as not-run, never folded into the score — the denominator counts what was actually investigated."""
    fixtures_dir = tmp_path / "held-out"
    for slug, disposition in (("b01-case", "benign"), ("m01-case", "malicious")):
        member = fixtures_dir / slug
        member.mkdir(parents=True)
        (member / "alert.json").write_text("{}", encoding="utf-8")
        (member / "ground_truth.yaml").write_text(
            f"held_out: true\ndisposition: {disposition}\n", encoding="utf-8"
        )

    fixtures = load_held_out_fixtures(fixtures_dir)
    assert len(fixtures) == 2, "both labeled members must load"
    scored = score(fixtures, tmp_path / "empty-runs", {})
    assert scored.total == 0
    assert len(scored.not_run) == len(fixtures)


def test_divergent_fixture_set_warns_that_it_was_never_netted(tmp_path: Path, capsys):
    """The retired learning-queue write refused exactly one directory. Scoring a different set means
    those runs were never refused, so the number may already be contaminated."""
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
