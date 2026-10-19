"""Held-out eval scoring: matching a fixture to its run by name, and what the denominator counts."""
from __future__ import annotations

from pathlib import Path

from evaluations.held_out import (
    index_runs,
    load_held_out_fixtures,
    score,
    warn_if_outside_the_net,
)
from defender.run_common import HELD_OUT_FIXTURES
from defender.tests.support.storage._alert_plant import plant_alert

SLUG = "m05-lsass-access"


def _runs(tmp_path: Path, *names: str) -> Path:
    runs = tmp_path / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    for n in names:
        (runs / n).mkdir()
        plant_alert(runs / n)
    return runs


def test_secondary_harness_run_dirs_are_not_claimed_by_the_primary_metric(tmp_path: Path):
    """The regression this rule exists for."""
    runs = _runs(
        tmp_path,
        SLUG,
        f"sec-eval-gen7-{SLUG}-ab12cd34",
        f"sec-eval-gen7-{SLUG}-ab12cd34-replay",
    )
    assert index_runs([SLUG], runs) == {SLUG: runs / SLUG}


def test_run_id_conventions_that_do_claim_a_fixture(tmp_path: Path):
    for name in (SLUG, f"{SLUG}-attempt2", f"20260718T101500Z-{SLUG}"):
        runs = _runs(tmp_path / name, name)
        assert index_runs([SLUG], runs) == {SLUG: runs / name}, name


def test_longest_slug_wins_when_one_fixture_slug_prefixes_another(tmp_path: Path):
    """Nothing enforces a no-prefix invariant over the fixture set, so the matcher must
    survive one: `m05-lsass-access-v2`'s run must not be scored as `m05-lsass-access`."""
    slugs = [SLUG, f"{SLUG}-v2"]
    runs = _runs(tmp_path, f"{SLUG}-v2-attempt1")
    assert index_runs(slugs, runs) == {f"{SLUG}-v2": runs / f"{SLUG}-v2-attempt1"}


def test_most_recent_run_wins(tmp_path: Path):
    import os

    runs = _runs(tmp_path, f"{SLUG}-a", f"{SLUG}-b")
    os.utime(runs / f"{SLUG}-a", (1, 1))
    os.utime(runs / f"{SLUG}-b", (2, 2))
    assert index_runs([SLUG], runs) == {SLUG: runs / f"{SLUG}-b"}


def test_index_survives_unresolvable_entries(tmp_path: Path, capsys):
    """Walk-survival (the #595 class the fixture walk already honors):"""
    runs = _runs(tmp_path, f"{SLUG}-fine")
    (runs / f"{SLUG}-dangling").symlink_to(tmp_path / "nowhere")
    (runs / f"{SLUG}-a-file").write_text("not a run dir", encoding="utf-8")

    assert index_runs([SLUG], runs) == {SLUG: runs / f"{SLUG}-fine"}
    assert capsys.readouterr().err == ""


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
    scored = score(fixtures, tmp_path / "empty-runs")
    assert scored.total == 0
    assert len(scored.not_run) == len(fixtures)


def test_divergent_fixture_set_warns_that_it_was_never_netted(tmp_path: Path, capsys):
    """The retired learning-queue write refused exactly one directory. Scoring a different set means
    those runs were never refused, so the number may already be contaminated."""
    assert warn_if_outside_the_net(tmp_path) is True
    assert "NOT held out of learning" in capsys.readouterr().err
    assert warn_if_outside_the_net(HELD_OUT_FIXTURES) is False
    assert capsys.readouterr().err == ""
