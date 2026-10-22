"""#1108 P4 flow 7, O-PIN (branch side) and O-B for the branch CLI's live capture.

Design: "Branch replay: source stamp's knowledge commit → materialise → every sibling `run.py`
pinned to it; the questioner corpus is read from that export, not `PATHS`." O-PIN: "Branch
siblings are pinned to the source run's stamp, so preflight's knowledge anchor holds regardless
of publishes. The branch CLI (git-capable) materialises a missing export for that commit
first." O-B: the branch CLI's live capture (`learning/branch/cli.py:513`) stamps from an
export, never the clone's HEAD.

Entry surface: the REAL launcher, `learning.branch.cli.main(argv, spawn=, questioner=,
preflight=, judge=, roster=, oracle=, verifier=, live_tree=)`, over the P4 fixture tenant
published for real (`_support.published_tenant`) carrying the #1224 estate's grants (so the
launcher's served systems and the source run's captured calls agree). Siblings are observed on
the existing `spawn=` seam (`FakeSpawn` records each `run.py` argv); the questioner on the
existing `questioner=` seam (it records every prompt). `lessons_dir=` is NOT passed: the corpus
the questioner sees is the launcher's own choice. The pin is spelled `--knowledge-commit <sha>`
(two tokens, the design's `run.py --knowledge-commit <sha>`).

Every scene: the source ran at knowledge commit `K1`; afterwards a merge was published, so
`current` and the clone's HEAD are `K2`; the clone's working tree was then edited; and
`exports/K1/` was deleted (exports are derived, P-2) — so the launcher must materialise it.
"""
from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path

import pytest

from defender.tests.learning.oracle.live_contracts import _spec1224 as S
from defender.tests.support.learning.branch import _triplet_947 as T
from defender.tests.support.tenancy import _tenants1106 as tenants

from ._support import (
    FIXTURE_SETTINGS,
    current_commit,
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
#: (as `test_947_triplet_launcher` does).
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


def _launch(scene: Scene, *, argv_extra=(), **seams) -> Launch:
    """The real launcher over the scene's tenant and source run (the `S.launch` recipe, with
    the scene's own tenant and stamp)."""
    spawn = T.FakeSpawn()
    questioner = S.questioner_for()
    seams.setdefault("preflight", S.no_preflight)
    seams.setdefault("roster", scene.est.roster())
    seams.setdefault("judge", S.FakeJudge(default="bucket: none\nsystems: []\nfindings: []\n"))
    seams.setdefault("oracle", S.oracle(then=S.submit(_BASE, S.EMPTY_CLAIM)).model)
    seams.setdefault("verifier", S.passing_verifier().model)
    message = ""
    try:
        rc = S.mod(S.CLI).main(
            ["--tenant", scene.t.tenant_id, scene.src.name, str(T.BRANCH_MESSAGE_ID),
             *T.retired_continuation_argv(), *argv_extra],
            spawn=spawn, questioner=questioner, **seams)
    except SystemExit as stop:
        rc, message = (stop.code, "") if isinstance(stop.code, int) else (2, str(stop.code))
    S.log_refusal(rc, message)
    return Launch(rc=rc, message=message, spawn=spawn, questioner=questioner)


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
    """O-PIN / flow 7: every sibling `run.py` carries `--knowledge-commit <K1>` (the SOURCE's
    knowledge commit, not `current`'s K2); `exports/K1/` — deleted — is materialised first;
    `current` is not moved."""
    t = scene.t
    _stamp_source(scene, knowledge={"commit": scene.k1})
    launch = _launch(scene, live_tree=T.source_capture(knowledge={"commit": scene.k1}))

    _assert_siblings_pinned(launch, scene.k1)
    rebuilt = export_dir(t.tenant, scene.k1) / QPATH
    assert rebuilt.is_file(), "the source's knowledge export was not materialised"
    assert rebuilt.read_text(encoding="utf-8") == _questioner_lesson(Q_EXPORT)
    assert current_commit(t.tenant) == scene.k2, "the branch launch moved `current`"


def test_flow7_the_questioner_reads_its_corpus_from_the_pinned_export(scene):
    """Flow 7: "the questioner corpus is read from that export, not `PATHS`" — call 1 of the
    question-writer is shown the K1 export's questioner lesson, never `current`'s (K2), the
    clone working tree's, or a product-tree corpus (`lessons_dir=` is not passed)."""
    _stamp_source(scene, knowledge={"commit": scene.k1})
    launch = _launch(scene, live_tree=T.source_capture(knowledge={"commit": scene.k1}))

    assert launch.questioner.prompts, (
        f"the questioner was never called (rc={launch.rc!r}, refusal={launch.message!r})")
    first = launch.questioner.prompts[0]
    assert Q_EXPORT in first, "the pinned export's questioner lesson never reached call 1"
    wrong = [m for m in (Q_CURRENT, Q_WORKTREE) if m in first]
    assert not wrong, f"the questioner was shown a lesson from the wrong revision: {wrong}"


def test_o_b_the_live_capture_stamps_the_pinned_export_so_the_anchor_survives_a_publish(scene):
    """O-B (branch CLI live capture) + O-PIN: with NO `live_tree` seam, the launcher's own live
    capture is judged against the source; its knowledge half is the export the family is pinned
    to (K1), not the clone's HEAD (K2, published after the source ran) — so the knowledge
    anchor holds regardless of publishes and the launch proceeds, pinned to K1.

    The code half is the real checkout's (the source stamp names `REPO_ROOT`'s HEAD, scope
    `defender`); `--allow-dirty` is passed ONLY when that checkout is dirty, so on a clean
    checkout (CI) an unproven live knowledge revision (e.g. `unversioned` from capturing an
    export folder as if it were a clone) is a refusal, not a waiver."""
    from defender.records import _provenance
    from defender.run_common import REPO_ROOT

    code = _provenance.capture_tree(Path(REPO_ROOT))
    assert code.commit, f"fixture bug: the checkout's code commit is unreadable ({code})"
    _stamp_source(scene, knowledge={"commit": scene.k1}, commit=code.commit, dirty=False,
                  scope=code.scope)
    assert git(scene.t.clone, "rev-parse", "HEAD") == scene.k2, "fixture bug: HEAD is K1"

    launch = _launch(scene, argv_extra=("--allow-dirty",) if code.dirty else ())

    assert not launch.message, f"the launch was refused: {launch.message}"
    _assert_siblings_pinned(launch, scene.k1)


def test_flow7_a_source_knowledge_commit_absent_from_the_clone_refuses_before_spending(scene):
    """Flow 7: a source whose knowledge commit the clone does not hold cannot be materialised,
    so the launch is refused naming the commit — before the question-writer is paid for and
    before any sibling starts. (The positive control is the pinned launch above.)"""
    _stamp_source(scene, knowledge={"commit": ABSENT_COMMIT})
    launch = _launch(scene, live_tree=T.source_capture(knowledge={"commit": ABSENT_COMMIT}))

    assert launch.rc not in (0, None), "a launch whose knowledge cannot be materialised ran"
    assert ABSENT_COMMIT in launch.message, f"the refusal does not name the commit: {launch.message!r}"
    assert not launch.questioner.prompts, "the questioner was paid for before the refusal"
    assert not launch.spawn.launches, "a sibling started on knowledge that cannot be pinned"
    assert not export_dir(scene.t.tenant, ABSENT_COMMIT).exists()
