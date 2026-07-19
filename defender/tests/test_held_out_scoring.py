"""Primary metric — matching a fixture to its run, and what the denominator counts.

The run dir carries no provenance back to its fixture (no label, no pointer), so the eval
matches by NAME. That makes the matching rule load-bearing: it is the only thing standing
between a fixture and the wrong run dir, and the runs base is shared with the secondary
harness, which mints run ids containing the very same fixture slugs.
"""
from __future__ import annotations

from pathlib import Path

from defender.evals.held_out import (
    _claimed_slug,
    index_runs,
    load_held_out_fixtures,
    score,
    warn_if_outside_the_net,
)
from defender.run_common import HELD_OUT_FIXTURES, _alert_label

SLUG = "m05-lsass-access"


def _runs(tmp_path: Path, *names: str) -> Path:
    runs = tmp_path / "runs"
    runs.mkdir(parents=True, exist_ok=True)
    for n in names:
        (runs / n).mkdir()
    return runs


def test_secondary_harness_run_dirs_are_not_claimed_by_the_primary_metric(tmp_path: Path):
    """The regression this rule exists for. `secondary.py` mints
    `sec-eval-gen{N}-{slug}-{attempt}` plus a `-replay` staging twin, under the SAME runs
    base the primary metric defaults to. A substring match claims both — and the replay
    dir has no report.md, so the fixture scores WRONG off a dir that was never its run.
    """
    runs = _runs(
        tmp_path,
        SLUG,
        f"sec-eval-gen7-{SLUG}-ab12cd34",
        f"sec-eval-gen7-{SLUG}-ab12cd34-replay",
    )
    assert index_runs([SLUG], runs) == {SLUG: runs / SLUG}


def test_run_id_conventions_that_do_claim_a_fixture(tmp_path: Path):
    """Anchored at either end, on a `-` boundary: the bare `--run-id <slug>`, a
    `<slug>-<attempt>` suffix, and the `{utc_timestamp}-<slug>` shape `materialize_run_dir`
    mints when no `--run-id` is passed."""
    for name in (SLUG, f"{SLUG}-attempt2", f"20260718T101500Z-{SLUG}"):
        runs = _runs(tmp_path / name, name)
        assert index_runs([SLUG], runs) == {SLUG: runs / name}, name


def test_the_default_run_id_satisfies_the_convention():
    """The convention has to be reachable without `--run-id`. Every fixture is laid out as
    `{slug}/alert.json`, so a run id built from the file STEM is the constant "alert" for
    all of them and matches nothing — the label comes from the parent dir instead."""
    assert _alert_label(HELD_OUT_FIXTURES / SLUG / "alert.json") == SLUG
    assert _claimed_slug(f"20260718T101500Z-{SLUG}", [SLUG]) == SLUG
    # A non-generic stem still speaks for itself.
    assert _alert_label(Path("/x/y/wazuh-5710.json")) == "wazuh-5710"


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
    """Walk-survival (the #595 class the fixture walk already honors): an entry the walk
    cannot resolve costs that one candidate, not the whole eval.

    A dangling symlink is the reachable case — `is_dir()` folds its ENOENT into False,
    which is the right answer (a vanished run is not a run) and needs no noise. The
    `except OSError` in `index_runs` covers what `is_dir` re-raises instead of swallowing
    (EACCES on the `stat` the recency ordering needs); it is unreachable as root, so it is
    a guard rather than a tested branch.
    """
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
    )  # no alert.json
    assert load_held_out_fixtures(tmp_path) == []
    err = capsys.readouterr().err
    assert "m01" in err
    assert "alert.json" in err


def test_unlabeled_dir_is_excluded_quietly(tmp_path: Path, capsys):
    """Control: a dir with no label is simply not a member of the set — not a warning."""
    (tmp_path / "scratch").mkdir()
    (tmp_path / "scratch" / "alert.json").write_text("{}", encoding="utf-8")
    assert load_held_out_fixtures(tmp_path) == []
    assert capsys.readouterr().err == ""


def test_un_run_fixtures_are_surfaced_not_scored(tmp_path: Path):
    fixtures = load_held_out_fixtures(HELD_OUT_FIXTURES)
    assert fixtures, "the real held-out set must be loadable"
    scored = score(fixtures, tmp_path / "empty-runs")
    assert scored.total == 0
    assert len(scored.not_run) == len(fixtures)


def test_divergent_fixture_set_warns_that_it_was_never_netted(tmp_path: Path, capsys):
    """`enqueue_learning` refuses exactly one directory. Scoring a different set means
    those runs were never refused, so the number may already be contaminated."""
    assert warn_if_outside_the_net(tmp_path) is True
    assert "NOT held out of learning" in capsys.readouterr().err
    assert warn_if_outside_the_net(HELD_OUT_FIXTURES) is False
    assert capsys.readouterr().err == ""
