"""#1007 — F-R5: an episode has ONE namespace, and the operator door that defeated it."""
from __future__ import annotations

import inspect

from pathlib import Path

import pytest

from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.learning.branch import _world_1007 as W
from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.shared.contracts._spec1077 import fixture_run
from defender.tests.learning.oracle.live_contracts import _spec1224 as S

OPERATOR_NAMED = "opnamed.token"

#: The one answer every captured call of `launch`'s source run carries, so a single scripted
#: oracle submission serves every call unchanged and every fact world calibrates.
_BASE = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon", "host": "web-1",
                   "ts": "2026-07-28T15:00:00Z"}]}


@pytest.fixture(autouse=True)
def _tmp_roots(tmp_path, monkeypatch):
    """Both CONFIGURED roots, and the learning state the judge appends to, inside `tmp_path`."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    T.isolate_learning_state(tmp_path, monkeypatch)


def launch(tmp_path: Path, *, argv_extra=()):
    """One episode through the REAL launcher over `_spec1224`'s fixture tenant (#1224)."""
    run = S.launch(
        tmp_path, S.estate(tmp_path),
        calls=[S.Call("idp", "query", S.query_params("user:alice"), _BASE),
               S.Call("edr", "query", S.query_params("host:db-1"), _BASE)],
        argv_extra=argv_extra, oracle=S.oracle(then=S.submit(_BASE, S.EMPTY_CLAIM)),
        verifier=S.passing_verifier())
    return run.rc, run.spawn, run.ep


def written_bytes(root: Path) -> str:
    """Every byte the launcher wrote under the episodes root, as one string — the manifest,
    pre-flight's records, the ledgers and the provenance record all sit here, so one sweep
    covers every file surface the operator's string could have reached."""
    return "\n".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in sorted(root.rglob("*")) if p.is_file())


def test_an_episode_is_read_under_one_namespace(tmp_path):
    """An episode's worlds are written and read back under one namespace, and it cannot be built any
    other way."""
    cli = W.mod("learning.branch.cli")
    fam = W.mod("runtime.branch._family")
    judge_family = W.mod("learning.judge.family")

    rc, spawn, ep = launch(tmp_path)

    assert rc == 0, f"the launch failed ({rc}); nothing below observes a namespace"
    family = fam.parse_family(W.read_yaml(ep / "family.yaml"))
    assert spawn.worlds, "the launch started no sibling"
    for label in spawn.worlds:
        resumed = fam.resume_world_from(family, label, ep).world_id
        assert resumed == family.world(label).world_id, (
            f"the sibling for world {label!r} resumes into {resumed!r}, not the persisted UUID "
            f"bound to its manifest label {label!r}")
        ledger = judge_family.world_ledger_name(family.world(label).world_id)
        assert ledger.rsplit("/", 1)[-1] == f"{resumed}.jsonl", (
            f"the grader reads world {label!r}'s rows from {ledger}, which is not the file "
            f"the sibling writing as {resumed!r} appends to")

    assert not hasattr(fam, "world_token_for")
    assert not hasattr(fam, "episode_token_for")
    params = inspect.signature(cli.preflight_episode).parameters
    assert "episode_token" not in params, "the operator-named token is still a parameter"
    retired = {"continuation_prompt": "go"} if "continuation_prompt" in params else {}
    with pytest.raises(TypeError, match="episode_token"):
        cli.preflight_episode(
            source=fixture_run(ep), branch_message_id=W.BRANCH_MESSAGE_ID,
            preflight=W.no_preflight, model=None, allow_dirty=False,
            live_tree=T.source_capture(), episode_token=OPERATOR_NAMED, **retired)


@pytest.mark.parametrize("length", [220, 1000])
def test_long_label_worlds_launch_and_keep_uuid_artifacts(tmp_path, length):
    label = "w" * length
    doc = S.family_v2(worlds=[S.control_world(), S.world_v2(label), S.world_v2("c", role="C")])
    run = S.launch(
        tmp_path, S.estate(tmp_path), questioner=S.questioner_for(doc), spawn=J.FakeSibling(),
        calls=[S.Call("idp", "query", S.query_params("user:alice"), _BASE)],
        oracle=S.oracle(then=S.submit(_BASE, S.EMPTY_CLAIM)), verifier=S.passing_verifier())
    assert run.rc == 0, run.message
    assert label in run.spawn.worlds
    wid = T.world_id(run.ep, label)
    assert wid != T.fixture_world_id(label), "the host trusted a test declaration's ID"
    for path in (run.ep / "served" / f"{wid}.jsonl", run.ep / "oracle" / wid,
                 run.ep / "worlds" / wid / "report.md"):
        assert path.exists(), path
    assert not any(label in str(path.relative_to(run.ep)) for path in run.ep.rglob("*"))
