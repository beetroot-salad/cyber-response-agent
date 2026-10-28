"""Contamination boundary: a held-out fixture run is never enqueued to the learn worker (path check `run_common.is_held_out_fixture`), including via symlinks."""
from __future__ import annotations

from pathlib import Path

from defender import run_common  # type: ignore[import-not-found]


def test_held_out_fixture_is_recognised_by_path(tmp_path: Path) -> None:
    """The net is a PATH check — it opens no label file, so it cannot be defeated by a
    missing, malformed, or absent-key ground_truth.yaml."""
    real = run_common.HELD_OUT_FIXTURES / "m05-lsass-access" / "alert.json"
    assert run_common.is_held_out_fixture(real) is True
    assert run_common.is_held_out_fixture(tmp_path / "alert.json") is False


def test_held_out_fixture_recognised_without_any_label_file(tmp_path: Path) -> None:
    """Fail-closed: containment alone decides. A held-out fixture with its label
    deleted is still refused."""
    fake_set = tmp_path / "held-out"
    (fake_set / "m01").mkdir(parents=True)
    alert = fake_set / "m01" / "alert.json"
    alert.write_text("{}")
    assert run_common.is_held_out_fixture(alert, fake_set) is True


def test_symlink_cannot_walk_out_of_the_held_out_set(tmp_path: Path) -> None:
    """Containment is decided on the RESOLVED path, so a symlink pointing into the
    held-out set is still recognised as held-out."""
    fake_set = tmp_path / "held-out"
    (fake_set / "m01").mkdir(parents=True)
    real = fake_set / "m01" / "alert.json"
    real.write_text("{}")
    link = tmp_path / "innocent.json"
    link.symlink_to(real)
    assert run_common.is_held_out_fixture(link, fake_set) is True




def test_net_is_narrow(tmp_path: Path) -> None:
    """Control: the refusal is scoped to the held-out set."""
    assert run_common.is_held_out_fixture(tmp_path / "alert.json") is False
    ordinary = (run_common.REPO_ROOT / "defender" / "tests" / "fixtures" / "kibana_alerts" / "v2-sshd-success-after-failures" / "alert.json")
    assert ordinary.is_file(), "control must point at a real non-held-out fixture"
    assert run_common.is_held_out_fixture(ordinary) is False










