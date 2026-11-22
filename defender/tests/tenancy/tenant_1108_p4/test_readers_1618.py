"""#1618 G2: every reader of Forgejo's commit, from ONE table (`knowledge_1618/_reader_table_1618.READERS`): with Forgejo down
each refuses naming the cause through the real fetch child, and the pinned kinds ask the commit by id and use that commit's content."""
from __future__ import annotations

import pytest

from defender.tests.support.jobs import _job_helper as JH
from defender.tests.support.learning.core._store1278 import (
    migrated_database,  # noqa: F401 — fixture the scenes need
    world,  # noqa: F401 — fixture
)
from defender.tests.tenancy.knowledge_1618 import _reader_table_1618 as T
from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_p4 import test_branch_replay as _BR
from defender.tests.tenancy.tenant_1108_p4 import test_judge_bodies as _JB

process_state = JH.process_state  # autouse: the helper scenes tie themselves to this process
job_scene = JH.scene
judge_scene = _JB.scene
branch_scene = _BR.scene


def _readers(only=lambda r: True):
    return [pytest.param(r, id=r.id, marks=[pytest.mark.postgres] if r.postgres else []) for r in T.READERS if only(r)]


@pytest.fixture
def env(tmp_path, data_root, capsys, caplog, monkeypatch, request):
    return T.Env(tmp_path, data_root, capsys, caplog, monkeypatch, request.getfixturevalue)


def _commits(res):
    return [a["commit"] for a in res.asks]


def _words(text: str) -> str:
    return " ".join(text.split())


@pytest.mark.parametrize("reader", _readers())
def test_1618_g2_with_forgejo_up_every_reader_is_served_through_the_real_child_and_leaves_no_copy(reader, env):
    """The positive control of the table: served, through the fetch child (or the tick's own git fetch), no copy left, no credential minted. (K4, O8)"""
    with reader.open(env) as rig:
        res = rig.run(rig.pin if reader.pinned else None)
    assert not res.refused, f"control: {res.text}"
    if reader.via == "child":
        assert res.asks, "control: the reader never asked the fetch child"
        assert all(a["line"] and a["line"].startswith("ok ") for a in res.asks), res.asks
    else:
        assert res.git_requests > 0, "control: the tick never reached Forgejo"
    if reader.spends:
        assert res.spent, "control: the reader did not go on to use its knowledge"
    assert res.left == [], res.left
    assert res.minted == 0, "the reader's own process minted a credential (O8)"


@pytest.mark.parametrize("reader", _readers())
def test_1618_g2_with_forgejo_down_every_reader_refuses_naming_the_cause_through_the_real_child_and_leaves_no_copy(reader, env):
    """With Forgejo unreachable each reader refuses in its own way (an operator tool exits non-zero; the host judge logs and the launch goes on), naming the child's cause, using no knowledge and leaving no copy. (K4)"""
    with reader.open(env) as rig:
        K.forge_down(rig.t)
        res = rig.run(rig.pin if reader.pinned else None, expect="refused")
    assert res.refused, f"{reader.id} went on with Forgejo unreachable"
    text = _words(res.text)
    assert text, "no reason was given"
    assert "stale" not in text.lower()
    if reader.refusal == "exit":
        assert res.rc not in (0, None), res.rc
    if reader.refusal in ("log", "skip"):
        assert res.rc in (0, None), f"a {reader.refusal} refusal failed the caller: {res.rc}"
    if reader.via == "child":
        assert res.asks, f"{reader.id} never went through the real fetch child"
        line = res.asks[-1]["line"]
        assert line, "the child reported nothing"
        assert line.startswith("refused transient "), line
        assert _words(" ".join(line.split()[2:]))[:40] in text, f"the refusal does not carry the child's cause: {line!r} / {res.text!r}"
    else:
        assert T.TICK_CAUSE.search(res.text), f"the refusal names no cause: {res.text!r}"
    assert not res.spent, f"{reader.id} used knowledge it could not fetch"
    assert res.left == [], f"left {res.left}"
    assert res.minted == 0, "the reader's own process minted a credential while Forgejo was down (O8)"


@pytest.mark.parametrize("reader", _readers(lambda r: r.pinned))
def test_1618_g2_a_pinned_reader_asks_the_commit_by_id_and_uses_that_commits_content_not_mains(reader, env):
    """After main moves on, a pinned reader's child is asked for the pin (by id) and what it used is the pin's, not the tip's. (K5)"""
    with reader.open(env) as rig:
        rig.later()
        res = rig.run(rig.pin)
    assert not res.refused, res.text
    commits = _commits(res)
    assert {c for c in commits if c} == {rig.pin}, f"the commit was not asked by id: {commits}"
    if not reader.also_main:
        assert None not in commits, f"the reader also fetched main: {commits}"
    assert res.seen == "pin", f"{reader.id} used {res.seen!r} content, not the pinned commit's"


@pytest.mark.parametrize("reader", _readers(lambda r: r.pinned))
def test_1618_g2_a_pin_forgejo_does_not_serve_refuses_naming_it_and_never_falls_back_to_main(reader, env):
    """The child is asked for the absent commit and the refusal names it; no fallback to main, nothing used, nothing left. (K5)"""
    with reader.open(env) as rig:
        res = rig.run(K.ABSENT_COMMIT, expect="refused")
    assert res.refused, f"{reader.id} went on with a commit Forgejo does not serve"
    assert K.ABSENT_COMMIT in res.text, res.text
    commits = _commits(res)
    assert K.ABSENT_COMMIT in commits, f"the child was not asked for the pin: {commits}"
    if not reader.also_main:
        assert None not in commits, f"the reader fell back to main: {commits}"
    assert not res.spent
    assert res.left == []
