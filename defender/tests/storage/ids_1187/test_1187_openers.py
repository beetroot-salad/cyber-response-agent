"""Preflight never reads an episode through a link.

The census that episode consumers use repository walks (no production code opens an episode, or
re-binds its folder, by a path) is `tooling/lint/lint_episode_paths.py`."""
from __future__ import annotations

import os
from pathlib import Path

from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.storage.ids_1187 import _spec1187 as R
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P


def test_preflight_never_reads_an_episode_through_a_link(tmp_path, monkeypatch, data_root):
    from defender.learning.branch import cli
    from defender.tests.support.learning.branch import _triplet_947 as T

    P.roots(tmp_path, monkeypatch)
    monkeypatch.delenv(R.EPISODES_BASE_ENV, raising=False)
    est, src = P.launch_source(tmp_path, source_run_id=R.new_id())
    # Today's repository opens the source only through its container record; #1187's natural
    # container holds none (R1). The record goes once the handle is held, so pre-flight meets
    # #1187's container either way.
    source = T.open_source(src)
    (src.parent / "_tenant.json").unlink(missing_ok=True)
    rows = [S.captured(c.system, c.verb, c.params, c.payload) for c in P.source_calls()]

    def episode_at(root: Path, episode_id: str) -> Path:
        doc = S.family_v2(episode_id=episode_id, source_run_id=src.name,
                          source_run_dir=str(src))
        return S.episode_v2(tmp_path, doc=doc, root=root, episode_id=episode_id,
                            base_rows=rows)

    episodes = R.episodes_dir(data_root, P.LAUNCH_TENANT)
    linked_id = R.new_id()
    real = episode_at(tmp_path / "elsewhere", linked_id)
    episodes.mkdir(parents=True, exist_ok=True)
    os.symlink(real, episodes / linked_id, target_is_directory=True)
    oracle = S.oracle(then=S.submit(P.BASE_ANSWER, S.EMPTY_CLAIM))

    err = R.raised(cli.preflight_replay, episodes / linked_id, source=source,
                   roster=est.roster(), tenant=est.run_tenant(), oracle=oracle.model,
                   verifier=S.passing_verifier().model)
    assert not (real / "outcome.yaml").exists(), (
        f"pre-flight calibrated the episode behind a link ({err!r})")
    assert oracle.requests == 0, f"pre-flight asked its oracle through a link ({err!r})"
    assert err is not None, "pre-flight over a linked path returned as if it had run"

    walked_id = R.new_id()
    walked = episode_at(episodes, walked_id)
    control = S.oracle(then=S.submit(P.BASE_ANSWER, S.EMPTY_CLAIM))
    runs = R.tenant(data_root, P.LAUNCH_TENANT).runs_repository()
    with runs.episode(walked_id) as view:
        cli.preflight_replay(view.episode, source=source, roster=est.roster(),
                             tenant=est.run_tenant(), oracle=control.model,
                             verifier=S.passing_verifier().model)
    assert control.requests > 0, "control: pre-flight through the walk never asked its oracle"
    assert (walked / "outcome.yaml").is_file(), "control: pre-flight through the walk wrote nothing"
