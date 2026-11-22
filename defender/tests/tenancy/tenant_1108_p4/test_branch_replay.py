"""#1108 P4 flow 7, branch replay: every sibling `run.py` is pinned (`--knowledge-commit <sha>`) to
the source stamp's knowledge commit, materialised first if missing, so preflight's knowledge
anchor holds across publishes; the questioner reads its corpus from that export; and the branch
CLI's live capture stamps from an export, never the clone's HEAD (O-B).

Entry: the real launcher `learning.branch.cli.main` over the fixture tenant published with the
#1224 estate's grants (so served systems and the source's captured calls agree). Siblings are
observed on `spawn=` (`FakeSpawn` records each argv), the questioner on `questioner=`;
`lessons_dir=` is not passed, so the corpus is the launcher's own choice. Every scene: the source
ran at `K1`; a later merge was published (`current` and the clone's HEAD are `K2`); the clone's
working tree was then edited; and `exports/K1/` was deleted, so the launcher must materialise it.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

from defender.tests.support.tenancy._launch_publish_p4 import directory_for_argv
from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.support.tenancy import _tenants1106 as tenants

from ._support import (
    FIXTURE_SETTINGS,
    export_dir,
    files_under,
    git,
    published_tenant,
)

QPATH = "agent/lessons-questioner/p4-branch-questioner.md"
Q_EXPORT = "FLOW7-QUESTIONER-LESSON-FROM-THE-PINNED-EXPORT"
Q_CURRENT = "FLOW7-QUESTIONER-LESSON-FROM-CURRENT-AND-THE-CLONE-HEAD"
Q_WORKTREE = "FLOW7-QUESTIONER-LESSON-FROM-THE-CLONE-WORKING-TREE"
#: A full object id the clone does not hold.
ABSENT_COMMIT = "abcdef0123456789" * 2 + "abcdef01"
PIN = "--knowledge-commit"

#: One answer every captured call carries, so one scripted oracle submission serves them all
#: (as `test_triplet_launcher` does).
_BASE = {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon", "host": "web-1",
                   "ts": "2026-07-28T15:00:00Z"}]}


def _calls() -> list:
    return [S.Call("idp", "query", S.query_params("user:alice"), _BASE),
            S.Call("edr", "query", S.query_params("host:db-1"), _BASE)]


def _questioner_lesson(marker: str) -> str:
    return ("---\nname: p4-branch-questioner\nsystems:\n- idp\n---\n"
            f"{marker}\n")


def _estate_settings(scratch: Path, est, tenant_id: str) -> dict:
    """The #1224 estate's settings half (its grant table, alert mapping, …) as `files` for
    `published_tenant`: written by the same planter `Estate.place` uses, every committed fixture
    settings file it does not write deleted — so the published tenant grants exactly what the
    estate's stub adapters serve."""
    # (#1366: the estate's systems are stub adapters that need no settings, so the tenant's records are the estate's own
    # bare ones, handed to the launcher's directory in `_launch`; not the retired fixture's seven, which `configs={}`
    # used to mean "replace".)
    knowledge = tenants.place_tenant(scratch, tenant_id, table=est.table(), configs={})
    wanted = {f"settings/{rel}": data
              for rel, data in files_under(knowledge / "settings").items()}
    stale = {f"settings/{rel}": None for rel in files_under(FIXTURE_SETTINGS)
             if f"settings/{rel}" not in wanted}
    return {**stale, **wanted}


@dataclass
class Scene:
    t: object
    est: object
    k1: str
    k2: str
    src: Path


@pytest.fixture
def scene(tmp_path, data_root):
    from ._support import FIXTURE_TENANT_ID

    est = S.estate(tmp_path)
    files = {**_estate_settings(tmp_path / "estate-settings", est, FIXTURE_TENANT_ID),
             QPATH: _questioner_lesson(Q_EXPORT)}
    with published_tenant(tmp_path / "forge", root=data_root, files=files) as t:
        k1 = t.commit
        _base, src = S.source_run(tmp_path, est, calls=_calls(), tenant_id=t.tenant_id)
        k2 = t.merge({QPATH: _questioner_lesson(Q_CURRENT)}, message="a later questioner lesson")
        assert t.publish().commit == k2
        (t.clone / QPATH).write_text(_questioner_lesson(Q_WORKTREE), encoding="utf-8")
        shutil.rmtree(export_dir(t.tenant, k1))
        yield Scene(t=t, est=est, k1=k1, k2=k2, src=Path(src))


def _stamp_source(scene: Scene, *, knowledge: object, **fields) -> dict:
    """Rewrite the source run's provenance stamp: the knowledge revision it ran with, plus any
    code-half fields (`commit`, `dirty`, `scope`)."""
    doc = T.provenance_record(tenant_id=scene.t.tenant_id, knowledge=knowledge, **fields)
    (scene.src / "provenance.json").write_text(json.dumps(doc), encoding="utf-8")
    return doc


@dataclass
class Launch:
    rc: object
    message: str
    spawn: object
    questioner: object
    minted: int = 0
    fetches: tuple = ()


def _launch(scene: Scene, *, argv_extra=(), **seams) -> Launch:
    """The real launcher over the scene's tenant and source run (the `S.launch` recipe, with
    the scene's own tenant and stamp)."""
    spawn = seams.pop("spawn", None) or T.FakeSpawn()  # lint-default: ok — a test builder's fresh per-call double
    questioner = S.questioner_for()
    seams.setdefault("preflight", S.no_preflight)
    seams.setdefault("roster", scene.est.roster())
    seams.setdefault("judge", S.quiet_judge())
    seams.setdefault("oracle", S.oracle(then=S.submit()).model)
    seams.setdefault("verifier", S.passing_verifier().model)
    message = ""
    minted = None
    argv = ["--tenant", scene.t.tenant_id, scene.src.name, str(T.BRANCH_MESSAGE_ID), *argv_extra]
    from defender.learning.author.version_control.auth import ForgejoIdentity
    from defender.tests.support.tenancy._host1214 import counting_calls

    fetch = seams.get("fetch")
    try:
        with counting_calls(mint=ForgejoIdentity.token) as minted:
            rc = S.mod("cli.learning.branch").main(
                argv, spawn=spawn, questioner=questioner, directory=directory_for_argv(argv, records=R.bare_records(*scene.est.systems)), **seams)
    except SystemExit as stop:
        rc, message = (stop.code, "") if isinstance(stop.code, int) else (2, str(stop.code))
    S.log_refusal(rc, message)
    return Launch(rc=rc, message=message, spawn=spawn, questioner=questioner, minted=minted.counts["mint"] if minted is not None else 0,
                  fetches=tuple(fetch.calls) if fetch is not None else ())


def _pins(argv: list[str]) -> list[str]:
    return [argv[i + 1] for i, tok in enumerate(argv[:-1]) if tok == PIN]


def _assert_siblings_pinned(launch: Launch, commit: str) -> None:
    assert launch.spawn.launches, (
        f"no sibling was started (rc={launch.rc!r}, refusal={launch.message!r})")
    for started in launch.spawn.launches:
        assert _pins(started["argv"]) == [commit], (
            f"a sibling was not pinned to the source's knowledge commit {commit}: "
            f"{started['argv']}")


def test_flow7_siblings_are_pinned_to_the_source_knowledge_commit_materialised_first(scene):
    """Every sibling carries the source's `K1`, not `current`'s `K2`; no `exports/K1/` is made (#1618 K8)."""
    t = scene.t
    _stamp_source(scene, knowledge={"commit": scene.k1})
    launch = _launch(scene, live_tree=T.source_capture(knowledge={"commit": scene.k1}))

    _assert_siblings_pinned(launch, scene.k1)
    assert not export_dir(t.tenant, scene.k1).exists(), "an export was made: #1618 K8 has no exports"


def test_flow7_the_questioner_reads_its_corpus_from_the_pinned_export(scene):
    """Call 1 of the question-writer is shown the `K1` export's questioner lesson, never
    `current`'s or the clone working tree's."""
    _stamp_source(scene, knowledge={"commit": scene.k1})
    launch = _launch(scene, live_tree=T.source_capture(knowledge={"commit": scene.k1}))

    assert launch.questioner.prompts, (
        f"the questioner was never called (rc={launch.rc!r}, refusal={launch.message!r})")
    first = launch.questioner.prompts[0]
    assert Q_EXPORT in first, "the pinned export's questioner lesson never reached call 1"
    wrong = [m for m in (Q_CURRENT, Q_WORKTREE) if m in first]
    assert not wrong, f"the questioner was shown a lesson from the wrong revision: {wrong}"


def test_o_b_the_live_capture_stamps_the_pinned_export_so_the_anchor_survives_a_publish(scene):
    """With no `live_tree` seam, the launcher's own live capture is judged against the source:
    its knowledge half is the pinned export (`K1`), not the clone's HEAD (`K2`), so the launch
    proceeds pinned. `--allow-dirty` is passed only when the real checkout is dirty, so on a
    clean checkout (CI) an unproven live knowledge revision is a refusal, not a waiver."""
    from defender.records import _provenance
    from defender._git import REPO_ROOT

    code = _provenance.capture_tree(Path(REPO_ROOT))
    assert code.commit, f"fixture bug: the checkout's code commit is unreadable ({code})"
    _stamp_source(scene, knowledge={"commit": scene.k1}, commit=code.commit, dirty=False,
                  scope=code.scope)
    assert git(scene.t.clone, "rev-parse", "HEAD") == scene.k2, "fixture bug: HEAD is K1"

    launch = _launch(scene, argv_extra=("--allow-dirty",) if code.dirty else ())

    assert not launch.message, f"the launch was refused: {launch.message}"
    _assert_siblings_pinned(launch, scene.k1)


def test_flow7_a_source_knowledge_commit_absent_from_the_clone_refuses_before_spending(scene):
    """A knowledge commit the clone does not hold cannot be materialised: refused naming it,
    before the question-writer is paid for or any sibling starts. Control: the pinned launch."""
    _stamp_source(scene, knowledge={"commit": ABSENT_COMMIT})
    launch = _launch(scene, live_tree=T.source_capture(knowledge={"commit": ABSENT_COMMIT}))

    assert launch.rc not in (0, None), "a launch whose knowledge cannot be materialised ran"
    assert ABSENT_COMMIT in launch.message, f"the refusal does not name the commit: {launch.message!r}"
    assert not launch.questioner.prompts, "the questioner was paid for before the refusal"
    assert not launch.spawn.launches, "a sibling started on knowledge that cannot be pinned"
    assert not export_dir(scene.t.tenant, ABSENT_COMMIT).exists()


@pytest.mark.parametrize("argv_extra", [(), ("--allow-dirty",)], ids=["plain", "allow-dirty"])
@pytest.mark.parametrize(("knowledge", "cause"), [
    ("unversioned", "unversioned"),
    ({"unavailable": "OD9-REASON-the-source-clone-could-not-be-read"},
     "OD9-REASON-the-source-clone-could-not-be-read"),
], ids=["unversioned", "unavailable"])
def test_od9_a_source_with_no_knowledge_commit_refuses_naming_why_even_with_allow_dirty(
        scene, knowledge, cause, argv_extra):
    """An `unversioned` or `unavailable` source stamp names no commit to pin siblings to:
    refused naming why, and `--allow-dirty` does not waive it (there is nothing to pin, not
    merely nothing proven). Control: the pinned launch above."""
    _stamp_source(scene, knowledge=knowledge)
    launch = _launch(scene, argv_extra=argv_extra, live_tree=T.source_capture(knowledge=knowledge))

    assert launch.rc not in (0, None), "a source with no knowledge commit launched"
    assert cause in launch.message, f"the refusal does not name why ({cause!r}): {launch.message!r}"
    assert not launch.spawn.launches, "a sibling started with no knowledge commit to pin"
    assert not launch.questioner.prompts, "the questioner was paid for before the refusal"


# --- #1618: the launcher reads Forgejo's commit (F4, K4, K5) ---------------------------------------

def _asking_forgejo(scene: Scene, **seams):
    """The launch with the one fetch seam (`fetch=`, the real child over the scene's remote; #1618 FORCED): the launcher's own
    process holds no credential, so there is no `identity=`."""
    return _launch(scene, fetch=K.fetch_seam(scene.t), **seams)


def test_1618_k5_the_questioner_corpus_is_the_pinned_commit_fetched_by_id_from_forgejo(scene):
    """Call 1 shows the questioner lesson at the source's `K1` while the git listener served the launch (the fetch by id),
    and no export folder, clone read or `current` stands behind it. (F4, K5)"""
    _stamp_source(scene, knowledge={"commit": scene.k1})
    served = len(scene.t.server.seen)

    launch = _asking_forgejo(scene, live_tree=T.source_capture(knowledge={"commit": scene.k1}))

    assert launch.questioner.prompts, f"the questioner was never called (rc={launch.rc!r}, refusal={launch.message!r})"
    assert Q_EXPORT in launch.questioner.prompts[0]
    assert not [m for m in (Q_CURRENT, Q_WORKTREE) if m in launch.questioner.prompts[0]]
    assert len(scene.t.server.seen) > served, "the corpus was not fetched from Forgejo"
    assert {c["commit"] for c in launch.fetches if c["commit"]} == {scene.k1}, "the corpus was not asked for by id"
    assert launch.minted == 0, "the launcher's own process minted a credential (O8)"
    assert not export_dir(scene.t.tenant, scene.k1).exists(), "an export was made"


def test_1618_k3_the_launchers_tenant_check_reads_mains_settings_not_the_clone(scene):
    """The tenant check judges a copy of main's tip: a merge that removes `settings/verb-grants.yaml` (the clone, `current`
    and the kept export still hold it) refuses the launch naming that file, before anything is spent. (F4, K8)"""
    _stamp_source(scene, knowledge={"commit": scene.k1})
    scene.t.merge({"settings/verb-grants.yaml": None}, message="a merge that drops the grant table")

    launch = _asking_forgejo(scene, live_tree=T.source_capture(knowledge={"commit": scene.k1}))

    assert launch.rc not in (0, None), "the launch ran over a tenant whose main has no grant table"
    assert "verb-grants" in launch.message, f"the refusal does not name the file: {launch.message!r}"
    assert not launch.questioner.prompts
    assert not launch.spawn.launches


# --- #1618 r5.1-b: an old run (no host knowledge record, a stamp naming no knowledge) cannot be branched --------------------

def _host_record(scene: Scene, commit: str | None) -> Path:
    """The source run's host-held knowledge record: naming `commit` (`fresh`), or removed (a run from before records)."""
    from defender.records import RunPaths

    path = Path(RunPaths(scene.src).knowledge_source())
    if commit is None:
        path.unlink(missing_ok=True)
    else:
        path.write_text(json.dumps({"kind": "fresh", "commit": commit, "reason": None}), encoding="utf-8")
    return path


def test_1618_r51b_a_source_with_no_host_record_and_a_stamp_naming_no_knowledge_refuses_naming_why_spends_nothing_and_never_fetches(scene):
    """The launch is refused naming why: no questioner call, no sibling, no fetch (no child ask, no git request), no fallback to
    main; the recorded-source launch on the same channel is the control. (r5.1-b, K5, D3)"""
    _host_record(scene, scene.k1)
    _stamp_source(scene, knowledge={"commit": scene.k1})
    control = _asking_forgejo(scene, live_tree=T.source_capture(knowledge={"commit": scene.k1}))
    assert control.questioner.prompts, f"control: the recorded source did not reach the questioner ({control.message!r})"
    assert control.spawn.launches, "control: no sibling started"
    assert control.fetches, "control: the launch never asked the fetch child"

    _host_record(scene, None)
    _stamp_source(scene, knowledge=T.NO_KNOWLEDGE_KEY)
    served = len(scene.t.server.seen)
    launch = _asking_forgejo(scene, live_tree=T.source_capture(knowledge={"commit": scene.k1}))

    assert launch.rc not in (0, None), "an old run with no knowledge to pin was branched"
    assert "knowledge" in launch.message.lower(), f"the refusal does not say why: {launch.message!r}"
    assert not launch.questioner.prompts, "the questioner was paid for before the refusal"
    assert not launch.spawn.launches, "a sibling started with no knowledge to pin"
    assert launch.fetches == (), f"the launch fetched with nothing to pin: {launch.fetches}"
    assert len(scene.t.server.seen) == served, "the launch made a git request (a fallback to main?)"
    assert launch.minted == 0
