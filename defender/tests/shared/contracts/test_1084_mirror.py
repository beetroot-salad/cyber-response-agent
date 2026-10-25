"""#1084 — the publish root (once the run-page mirror's) lives outside `defender/`; #1279 A4 — it has one tenant-free owner, which is also where a non-`dev` deployment gets no root; #1279 rev 5 A11 — `dev` names the folder, and no folder is worked out from a checkout."""
from __future__ import annotations

import importlib
from pathlib import Path

import pytest


ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"


def _renderer():
    """The publish root's one owner (#1279 A4): tenant-free, below `presentation`. It answers the
    root, or `NoRoot` saying why (A9); the old `visualize_run.mirror_root` is retired into it."""
    return importlib.import_module("defender.configuration.publish_root")


@pytest.fixture(autouse=True)
def _dev_deployment(deployment_unset, monkeypatch):
    """Resolution is only asked of a `dev` deployment (#1279 O4): the rule lives in the owner."""
    from defender.configuration import _env

    monkeypatch.setenv(_env.DEPLOYMENT_ENV, "dev")


def _assert_no_root(vr, got, kind: str) -> None:
    """The owner answered "no root" of `kind` (A9), not a path."""
    assert isinstance(got, vr.NoRoot), f"a root was answered: {got}"
    assert got.kind == kind, got


def test_1084_the_setting_is_read_at_call_time_not_at_import(tmp_path, monkeypatch):
    """The setting is host configuration, read each call."""
    vr = _renderer()
    first, second = tmp_path / "first", tmp_path / "second"
    monkeypatch.setenv(ENV, str(first))
    assert vr.publish_root() == first
    monkeypatch.setenv(ENV, str(second))
    assert vr.publish_root() == second


@pytest.mark.parametrize("value", [None, ""], ids=["unset", "empty"])
def test_1279_a11_in_dev_an_unset_folder_is_nowhere_to_publish_naming_the_setting(monkeypatch, value):
    """A11: `dev` names its publish folder; unset (or empty, which must not become `Path("")`, the
    cwd) is "no root", saying which setting to set — no folder is worked out from a checkout."""
    vr = _renderer()
    if value is None:
        monkeypatch.delenv(ENV, raising=False)
    else:
        monkeypatch.setenv(ENV, value)
    got = vr.publish_root()
    _assert_no_root(vr, got, "unset")
    assert ENV in got.reason, got


def test_1279_a11_the_owner_reads_no_checkout():
    """A11: nothing in the owner walks a checkout or reads `.git`; the worktree lookup is gone."""
    vr = _renderer()
    assert not hasattr(vr, "main_checkout")
    assert ".git" not in Path(vr.__file__).read_text(encoding="utf-8"), (
        "the owner still reads a checkout's .git")


@pytest.mark.parametrize("deployment", [None, "production", "staging", ""],
                         ids=["unset", "production", "typo", "empty"])
def test_1279_outside_dev_there_is_no_publish_root_even_when_one_is_configured(
        tmp_path, monkeypatch, deployment):
    """O4/A4: only `dev` has a publish root; the setting does not conjure one elsewhere. The rule
    is applied first: outside `dev` the answer is "not-dev" even when the setting is unset."""
    from defender.configuration import _env

    vr = _renderer()
    pages = tmp_path / "pages"
    monkeypatch.setenv(ENV, str(pages))
    assert vr.publish_root() == pages, "positive control: dev with the setting has its root"

    if deployment is None:
        monkeypatch.delenv(_env.DEPLOYMENT_ENV)
    else:
        monkeypatch.setenv(_env.DEPLOYMENT_ENV, deployment)
    _assert_no_root(vr, vr.publish_root(), "not-dev")
    monkeypatch.delenv(ENV)
    _assert_no_root(vr, vr.publish_root(), "not-dev")
