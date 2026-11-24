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
    if reader.shows:
        assert res.out.strip(), "control: the tool printed nothing"
    assert res.left == [], res.left
    assert res.minted == 0, "the reader's own process minted a credential (O8)"


@pytest.mark.parametrize("reader", _readers())
def test_1618_g2_with_forgejo_down_every_reader_refuses_naming_the_cause_through_the_real_child_and_leaves_no_copy(reader, env):
    """With Forgejo unreachable each reader refuses in its own way (an operator tool exits non-zero; the host judge logs and the launch goes on), naming the child's cause, using no knowledge and leaving no copy. (K4)"""
    with reader.open(env) as rig:
        rig.go_down()
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
        assert len(res.asks) == 1, f"{reader.id} must ask the real fetch child exactly once, and stop: {res.asks}"
        line = res.asks[0]["line"]
        assert line, "the child reported nothing"
        assert line.startswith("refused transient "), line
        assert _words(" ".join(line.split()[2:]))[:40] in text, f"the refusal does not carry the child's cause: {line!r} / {res.text!r}"
    else:
        assert T.tick_cause(res.text), f"the refusal names no transport cause after the drains wrapper: {res.text!r}"
    assert not res.spent, f"{reader.id} used knowledge it could not fetch"
    for stale in (K.SEEDED_MARK, K.CLONE_ONLY_MARK, K.MERGED_MARK):
        assert stale not in res.out, f"{reader.id} printed knowledge it could not fetch: {stale}"
    if reader.refusal == "log":  # the pass is refused and logged; the launch goes on and nothing is inserted
        assert res.siblings > 0, "the launch did not go on past the refused pass"
        assert res.stored == 0, "a refused judge pass inserted findings"
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


@pytest.mark.parametrize("reader", _readers(lambda r: r.pinned and r.unserved_reachable))
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


@pytest.mark.parametrize("record", ["missing", "garbled"])
def test_1618_k5_the_workspace_map_of_a_run_whose_record_names_no_commit_fetches_nothing(record, tmp_path, data_root, capsys):
    """A run whose host-held knowledge record names no commit (missing, or garbled: it reads `unreadable`, K9) has no
    tenant knowledge the map could show by id: the map is drawn without it, and nothing is fetched, `main` included (no
    fallback to another commit for an object the run never named, K5, K12). Control: the same tool with the record naming a
    commit asks for that commit by id."""
    from pathlib import Path

    from defender.cli import workspace_map
    from defender.records import RunPaths
    from defender.tests.tenancy.knowledge_1618 import _readers_1618 as RD

    with K.scene(tmp_path, data_root) as t:
        argv = lambda run_id: ["workspace_map.py", "--tenant", t.tenant_id, run_id]  # noqa: E731
        control = RD.run_tool(t, tmp_path, capsys, workspace_map.main, argv(RD.plant_run(t, t.commit)))
        assert control.rc == 0, control.err
        assert [a["commit"] for a in control.fetches] == [t.commit], "control: the named commit is fetched by id"
        run_id = RD.plant_run(t, t.commit)
        source = Path(RunPaths(K.tenant_root(t) / "runs" / run_id).knowledge_source())
        if record == "missing":
            source.unlink()
        else:
            source.write_text("{not json", encoding="utf-8")
        ran = RD.run_tool(t, tmp_path, capsys, workspace_map.main, argv(run_id))
    assert ran.rc == 0, ran.err
    assert ran.out.strip(), "control: the map was drawn"
    assert ran.fetches == [], f"a run naming no commit had knowledge fetched: {ran.fetches}"
    assert ran.requests == 0, "a run naming no commit reached Forgejo"
