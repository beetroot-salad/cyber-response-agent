"""#1255 slice A — the fork command refuses a source with no fork snapshot before it spends
anything (design rev 5 C2; N4).

Rev 4 N4: a source recorded before #1255 has no fork snapshot, and forking it is refused. Rev 5
C2 places that refusal at the FORK COMMAND too (`learning/branch/cli.py`): it refuses such a
source "before the questioner, pre-flight or any episode spend" (fail closed, loud, fast). The
arm launch keeps its own refusal (`tests/e2e/test_1255_snapshot_restore.py::test_n4_…`).

The source is the launcher suites' own hand-planted run (`_triplet_947.runs_base`), asked for
with `pre_snapshot=True`: whatever snapshot-planting fixture the implementer later adds to that
builder for the other launcher scenarios, this one stays a run recorded before the change.
Every seam that costs something is a recording double: the questioner (`FakeAgent`, which a
spend would CALL), the billable role-model preflight, the process seam (`FakeSpawn`). Today the
same request walks straight past the missing snapshot into the questioner — which is what makes
this red today on the spend assertions (red-c), and what shows the doubles do see a spend.
"""
from __future__ import annotations

import pytest

from defender.tests import _triplet_947 as T


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Both configured roots inside `tmp_path` (`test_947_triplet_launcher._tmp_roots`'s
    reasoning: otherwise the episode directory checked below is the developer's real one)."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    T.isolate_learning_state(tmp_path, monkeypatch)


def test_c2_the_fork_command_refuses_a_snapshot_less_source_before_spending_anything(
        tmp_path, capsys):
    """C2/N4: `branch --tenant T <run> <branch point>` over a source with no fork snapshot is
    refused, the refusal names the missing snapshot, and nothing was spent first: the
    questioner was never called (no prompt built from the source), the role-model preflight
    (which sources a billable key) never ran, no sibling process was started, and no episode
    directory exists for the derived episode id."""
    from defender._episode_handle import episode_dir
    from defender.learning.branch import cli as branch_cli

    _base, src = T.runs_base(tmp_path, pre_snapshot=True)
    questioner = T.FakeAgent()  # no replies: a call it should never get fails loudly
    spawn = T.FakeSpawn()
    preflights: list[tuple] = []

    def recording_preflight(model: str | None = None, *, branching: bool = False) -> int:
        preflights.append((model, branching))
        return 0

    episode = episode_dir(T.current_tenant().data_root, T.EPISODE_ID)
    assert not episode.exists(), "the fixture already holds the episode"
    try:
        got: object = branch_cli.main(
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
    assert not episode.exists(), f"the refused fork left an episode directory: {episode}"
    assert isinstance(got, BaseException) or got != 0, f"the fork was not refused: {got!r}"
    assert "snapshot" in text.lower(), (
        f"the refusal does not name the missing fork snapshot: {text[-400:]!r}")

