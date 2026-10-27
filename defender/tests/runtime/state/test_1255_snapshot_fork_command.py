"""Fork-command validation requires a matching recorded snapshot."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import pytest

from defender.tests.support.learning.branch import _triplet_947 as T


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Isolate configured episode and learning roots under tmp_path."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    T.isolate_learning_state(tmp_path, monkeypatch)


def test_c2_the_fork_command_refuses_a_snapshot_less_source_before_spending_anything(
        tmp_path, capsys):
    from defender.cli.learning import branch as branch_entry

    _base, src = location_path(T.runs_base)(tmp_path, pre_snapshot=True, published=True)  # #1108 P4: a branch launch needs a published tenant (flow 7 pins its commit)
    questioner = T.FakeAgent()  # no replies: a call it should never get fails loudly
    spawn = T.FakeSpawn()
    preflights: list[tuple] = []

    def recording_preflight(model: str | None = None, *, branching: bool = False) -> int:
        preflights.append((model, branching))
        return 0

    tenant = T.current_tenant()
    episodes = location_path(tenant.data_root) / tenant.id / "episodes"
    before = set(episodes.glob("*"))
    try:
        got: object = branch_entry.main(
            ["--tenant", src.parent.parent.name, src.name, str(T.BRANCH_MESSAGE_ID),
             *T.retired_continuation_argv()],
            spawn=spawn, questioner=questioner, preflight=recording_preflight,
            live_tree=T.source_capture())
    except (SystemExit, AssertionError, *T.refusals()) as refused:
        got = refused
    text = f"{got} {capsys.readouterr().err}"

    assert questioner.calls == 0, (
        f"the questioner was called {questioner.calls} time(s) for a source with no fork "
        "snapshot — the fork command spent before refusing")
    assert preflights == [], f"the role-model preflight ran before the refusal: {preflights}"
    assert spawn.launches == [], "a sibling process was started for a snapshot-less source"
    assert set(episodes.glob("*")) == before, "the refused fork claimed an episode"
    assert isinstance(got, BaseException) or got != 0, f"the fork was not refused: {got!r}"
    assert "snapshot" in text.lower(), (
        f"the refusal does not name the missing fork snapshot: {text[-400:]!r}")

