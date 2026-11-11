from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from defender.learning.author import shared as author_shared
from defender.learning.author.lessons import run as lessons_run
from defender.learning.author.questioner import run as questioner_run
from defender.learning.core import config, drains
from defender.learning.core.config import (
    AUTHOR_DRAIN_LABEL,
    LEAD_AUTHOR_DRAIN_LABEL,
    FatalConfigError,
    LoopPaths,
)
from defender._tree_listing import entry_kind
from defender.tests.support.shared._locations_1210 import location_path
from defender.learning.core.lane_trees import DrainTrees, open_drain_trees
from defender.tests.support.learning.core._store1278 import world as store_world  # noqa: F401
from defender.tests.support.learning.core._store1278 import call, finding, migrated_database  # noqa: F401
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401
from defender.tests.support.learning.curation._curator1134 import (
    is_link_to,
    leaf_refusal,
    plant_link,
    put,
    world,
)
from defender.tests.support.learning.curation._drain719 import finding_row, make_repo
from defender.tests.support.learning.curation._tree_listing_1134 import descriptors_under
from defender.tests.learning.curation.test_mount_list import UNKNOWN_LABELS

BUILDERS = {
    "lessons": (lessons_run.build_author_config, "lessons_dir"),
    "questioner": (questioner_run.build_questioner_config, "lessons_questioner_dir"),
}
RUNNERS = {"lessons": lessons_run.run_batch, "questioner": questioner_run.run_batch}


@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_the_builders_require_the_trees_and_take_their_mounts(tmp_path, channel):
    w = world(tmp_path)
    build, attr = BUILDERS[channel]

    with pytest.raises(TypeError):
        build(w.paths)

    cfg = build(w.paths, trees=w.trees)
    assert cfg.corpus_dir == getattr(w.paths, attr)
    assert cfg.corpus is w.trees.mount(cfg.corpus_dir)
    assert cfg.tree_for == w.trees.tree_for


@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_run_batch_takes_exactly_one_of_trees_and_cfg(tmp_path, channel):
    w = world(tmp_path)
    build, _attr = BUILDERS[channel]
    run = RUNNERS[channel]
    cfg = build(w.paths, trees=w.trees)

    with pytest.raises(TypeError):
        run(paths=w.paths)
    with pytest.raises(TypeError):
        run(paths=w.paths, trees=w.trees, cfg=cfg)

    assert run(paths=w.paths, trees=w.trees) == 0
    assert run(cfg=cfg) == 0


def _refusing_trees(w) -> dict[str, Any]:
    """Each way the trees a curator is handed can fail to hold its corpus exactly, as `(paths,
    open trees)`: opened for the lead member, or trees whose mounts omit the corpora (only
    `skills/`), move them elsewhere, hold only a folder above them (`defender/`), or only a
    folder below each corpus. A member label answers its own trees, so the wrong mount sets are
    opened directly (`DrainTrees.open`)."""
    moved = (w.repo / "moved" / "lessons", w.repo / "moved" / "lessons-questioner")
    for tree in moved:
        tree.mkdir(parents=True, exist_ok=True)
    (w.corpus_dir / "below").mkdir()
    (w.sibling_dir / "below").mkdir()
    return {
        "lead_label": lambda: (w.paths, open_drain_trees(w.paths, LEAD_AUTHOR_DRAIN_LABEL)),
        "omits_the_corpora": lambda: (w.paths, DrainTrees.open((w.paths.skills_dir,))),
        "moves_the_corpora": lambda: (w.paths, DrainTrees.open(moved)),
        "mount_above": lambda: (w.paths, DrainTrees.open((w.paths.defender_dir,))),
        "mount_below": lambda: (w.paths, DrainTrees.open(
            (w.corpus_dir / "below", w.sibling_dir / "below"))),
    }


REFUSALS = ("lead_label", "omits_the_corpora", "moves_the_corpora", "mount_above",
            "mount_below")


@pytest.mark.parametrize("how", REFUSALS)
@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_trees_that_do_not_hold_the_corpus_exactly_are_fatal_config(tmp_path, channel, how):
    w = world(tmp_path)
    build, attr = BUILDERS[channel]
    paths, trees = _refusing_trees(w)[how]()
    corpus_dir = getattr(paths, attr)

    with trees:
        with pytest.raises(FatalConfigError) as got:
            author_shared.lane_corpus(trees, corpus_dir)
        said = str(got.value)
        assert str(corpus_dir) in said, said
        for mount in trees.mounts:
            assert str(mount) in said, (mount, said)
        with pytest.raises(FatalConfigError):
            build(paths, trees=trees)
        with pytest.raises(FatalConfigError):
            RUNNERS[channel](paths=paths, trees=trees)


@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_lane_corpus_is_the_trees_own_mount_whatever_opened_them(tmp_path, channel):
    w = world(tmp_path)
    build, attr = BUILDERS[channel]
    paths = LoopPaths(repo_root=w.repo)

    with DrainTrees.open((paths.lessons_dir, paths.lessons_questioner_dir)) as trees:
        corpus_dir = getattr(paths, attr)
        assert author_shared.lane_corpus(trees, corpus_dir) is trees.mount(corpus_dir)
        cfg = build(paths, trees=trees)
        assert cfg.corpus is trees.mount(corpus_dir)
        hit = cfg.tree_for(paths.lessons_questioner_dir / "y.md")
        assert hit is not None
        assert hit[0] is trees.mount(paths.lessons_questioner_dir)
        assert hit[1] == "y.md"


@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_cfg_corpus_is_the_held_mount_and_never_follows_a_link(tmp_path, channel):
    w = world(tmp_path)
    build, attr = BUILDERS[channel]
    cfg = build(w.paths, trees=w.trees)
    root = getattr(w.paths, attr)

    target = w.target("secret.md")
    body = target.read_bytes()
    plant_link(root / "linked.md", target)
    assert cfg.corpus.view().read("linked.md").text is None
    with pytest.raises(OSError) as wrote:  # noqa: PT011 — the exact class is the assertion below
        cfg.corpus.write("linked.md", b"rewritten\n", mode="replace")
    assert leaf_refusal(wrote.value), repr(wrote.value)
    with pytest.raises(OSError) as unlinked:  # noqa: PT011 — the exact class is the assertion below
        cfg.corpus.unlink("linked.md")
    assert leaf_refusal(unlinked.value), repr(unlinked.value)
    assert is_link_to(root / "linked.md", target)
    assert target.read_bytes() == body

    put(root / "plain.md", body)
    assert cfg.corpus.view().read("plain.md").text == body.decode()
    cfg.corpus.write("plain.md", b"rewritten\n", mode="replace")
    assert (root / "plain.md").read_bytes() == b"rewritten\n"


def test_cfg_tree_for_maps_both_corpora_to_their_own_mounts_and_nothing_else(tmp_path):
    w = world(tmp_path)
    cfg = w.cfg()

    own = cfg.tree_for(w.corpus_dir / "a.md")
    assert own is not None
    assert own[0] is cfg.corpus
    assert own[1] == "a.md"
    sib = cfg.tree_for(w.sibling_dir / "sub" / "b.md")
    assert sib is not None
    assert sib[0] is w.trees.mount(w.sibling_dir)
    assert sib[1] == "sub/b.md"
    assert cfg.tree_for(w.paths.skills_dir / "elastic" / "SKILL.md") is None
    assert cfg.tree_for(w.repo / "defender" / "notes.txt") is None
    with pytest.raises(ValueError):  # noqa: PT011 — DrainTrees.tree_for's refusal of a relative path
        cfg.tree_for("defender/lessons/a.md")

    plant_link(w.sibling_dir / "b.md", w.target("secret.md"))
    held, name = cfg.tree_for(w.sibling_dir / "b.md")
    assert held.view().read(name).text is None
    assert entry_kind(held.view(), name).kind == "other"


def _held_items() -> list[tuple[str, str, dict]]:
    """One claimed finding of a retired direction: the pre-author gate holds it (`retired_direction`), so
    a tick serves it without spawning any agent."""
    return [("finding", "f1", finding_row("f1", run_id="old-run", direction="adversarial"))]


def _trigger_args(paths: LoopPaths) -> tuple:
    return (paths, None, "finding", "LEARNING_AUTHOR_THRESHOLD", "author", "pending")


def _trigger(paths: LoopPaths, label, outcomes: dict) -> None:
    """The author lane's default work step over a claim of `_held_items()`, its fates written to `outcomes`."""
    drains._maybe_trigger_author(*_trigger_args(paths), label=label, items=_held_items(), outcomes=outcomes)


def _is_held(outcomes: dict) -> bool:
    """The claim held its one finding (the gate's `retired_direction`), and decided nothing else."""
    held = outcomes.get(("finding", "f1"))
    return len(outcomes) == 1 and held is not None and held.name == "held" and "retired_direction" in held.reason


def test_the_trigger_requires_the_label_and_runs_the_batch_under_its_trees(tmp_path, monkeypatch):
    w = world(tmp_path)
    outcomes: dict = {}

    with pytest.raises(TypeError):
        drains._maybe_trigger_author(*_trigger_args(w.paths), items=_held_items(), outcomes=outcomes)
    assert outcomes == {}

    _trigger(w.paths, AUTHOR_DRAIN_LABEL, outcomes)

    assert _is_held(outcomes), outcomes


def test_the_trigger_opens_the_trees_of_the_label_it_is_handed_and_no_other(tmp_path, monkeypatch):
    w = world(tmp_path)
    w.trees.close()
    outcomes: dict = {}

    with pytest.raises(FatalConfigError):
        _trigger(w.paths, LEAD_AUTHOR_DRAIN_LABEL, outcomes)
    assert outcomes == {}
    for non_member in UNKNOWN_LABELS:
        with pytest.raises(AttributeError):
            _trigger(w.paths, non_member, outcomes)
        assert outcomes == {}
        assert descriptors_under(w.repo) == []

    _trigger(w.paths, AUTHOR_DRAIN_LABEL, outcomes)

    assert _is_held(outcomes), outcomes


def _drafts(t: Any) -> Path:
    return Path(location_path(t.tenant.tenant_root)) / "drafts"


def _items(w: Any) -> dict[tuple[str, str], Any]:
    return {(i.kind, i.key): i for i in call(w.dsn, "work", w.t.tenant_id)}


#: A world finding no declared system is named by: the questioner curator serves it without a model.
_NO_SYSTEM_WORLD_ROW = {"schema_version": 1, "finding_id": "w1", "subject": "world", "type": "lead-set",
                        "finding": "a world finding"}


def _publish_held(w: Any) -> None:
    """A retired-direction finding the gate holds, in the store (it wakes the author lane at one item)."""
    row = finding_row("f1", run_id="old-run", direction="adversarial")
    call(w.dsn, "publish_findings", w.t.tenant_id, "old-run", [row], kind="finding")


@pytest.fixture
def no_questioner_corpus_world(tmp_path, data_root, migrated_database, monkeypatch):  # noqa: F811 — the imported fixture
    """The `world` of the store tests over a tenant repo that never committed `agent/lessons-questioner/`."""
    from types import SimpleNamespace

    from defender.tests.support.jobs._jobs1342 import register_tenant
    from defender.tests.tenancy.tenant_1108_p4._drain_support import drain_paths, product_repo
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant

    with published_tenant(tmp_path / "forge", root=data_root, files={
            "agent/lessons-questioner/fixture-questioner-seed.md": None}) as t:
        bind_forge(t)
        register_tenant(migrated_database, t.tenant_id)
        monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
        monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
        monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
        yield SimpleNamespace(t=t, dsn=migrated_database, paths=drain_paths(t, product_repo(tmp_path)))


@pytest.mark.postgres
def test_author_drains_real_default_seam_carries_the_label_to_the_open(store_world):  # noqa: F811 — the imported fixture
    """The drain's production `trigger_author` opens the author label's trees over the batch's
    draft: the gate holds the row (the store records it held, not failed), and nothing stays held
    under the drafts or is delivered."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain, remote_branches

    w = store_world
    _publish_held(w)

    rc = author_drain(w.t, w.paths, trigger=None, box=BoxSpy())

    assert rc == 0
    got = _items(w)
    assert got[("finding", "f1")].status == "held", got
    assert descriptors_under(_drafts(w.t)) == []
    assert remote_branches(w.t.remote) == {}
    assert w.t.forge.creates == []


@pytest.mark.postgres
def test_a_lane_the_tenant_repo_never_committed_is_still_a_held_mount(no_questioner_corpus_world):
    """The draft makes each lane's folder, so a tenant repo holding no `agent/lessons-questioner/` still
    gives both curators their held corpus: the gate holds the findings row, and the questioner curator
    serves its row (no system to teach: skipped), neither records a failure."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain

    w = no_questioner_corpus_world
    _publish_held(w)
    call(w.dsn, "publish_findings", w.t.tenant_id, "run-w1", [_NO_SYSTEM_WORLD_ROW], kind="questioner_finding")

    rc = author_drain(w.t, w.paths, trigger=None, box=BoxSpy())

    assert rc == 0
    got = _items(w)
    assert got[("finding", "f1")].status == "held", got
    assert got[("questioner_finding", "w1")].status != "waiting", "the questioner curator never served"
    assert got[("questioner_finding", "w1")].status != "dead", got
    assert descriptors_under(_drafts(w.t)) == []


def test_a_hold_fault_at_the_open_propagates_out_of_the_seam(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    repo = make_repo(tmp_path)
    paths = LoopPaths(repo_root=repo)
    # make_repo carries both corpora; this case needs one absent
    subprocess.run(["git", "-C", str(repo), "rm", "-rq", str(paths.lessons_questioner_dir)], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "no questioner corpus"], check=True)
    outcomes: dict = {}

    with pytest.raises(FileNotFoundError):
        _trigger(paths, AUTHOR_DRAIN_LABEL, outcomes)

    assert outcomes == {}, "a held finding was named though the open failed"
    assert not os.path.lexists(paths.lessons_questioner_dir)
    assert descriptors_under(repo) == []


def _spy_paths(repo: Path, *, extra_mount: Path | None = None) -> LoopPaths:
    """A `LoopPaths` (the seam's `paths`); with `extra_mount`, the paths carry a third mount for the
    author label to hold (`extra_mount_dir`, which the caller adds to the label's tree list). A class
    per call."""

    class Spy(LoopPaths):
        @property
        def extra_mount_dir(self) -> Path:
            assert extra_mount is not None
            return extra_mount

    return Spy(repo_root=repo)


def _spy_build(monkeypatch, repo: Path, seen: list[list[str]], *,
               fault: BaseException | None = None) -> None:
    """Record what this process holds under the repo each time the curator's batch builds its config (after
    the seam opened its trees); with `fault`, raise it after recording. (#1278: the builder no longer reads the
    prompt path off the passed `paths`, so the config build itself is the observation point.)"""
    real = lessons_run.build_author_config

    def spy(*a: Any, **kw: Any) -> Any:
        seen.append(sorted(descriptors_under(repo)))
        if fault is not None:
            raise fault
        return real(*a, **kw)

    monkeypatch.setattr(lessons_run, "build_author_config", spy)  # lint-monkeypatch: ok — a recording wrapper around the real builder; no seam reports the config the drain builds for the call


def _held_roots(paths: LoopPaths) -> list[str]:
    return sorted(os.path.realpath(p) for p in AUTHOR_DRAIN_LABEL.writable_trees(paths))


@pytest.mark.parametrize("extra", [False, True], ids=["label-mounts", "a-third-mount"])
def test_the_trigger_holds_the_labels_mounts_only_while_the_batch_runs(
    tmp_path, monkeypatch, caplog, extra,
):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    caplog.set_level(logging.DEBUG)
    w = world(tmp_path)
    put(w.corpus_dir / "seeded.md", "---\nsource_finding_ids:\n- f0\n---\nbody\n")
    w.commit()
    extra_mount = w.repo / "defender" / "extra-mount" if extra else None
    if extra_mount is not None:
        extra_mount.mkdir()
        monkeypatch.setitem(
            config._WRITABLE_TREE_ATTRS, AUTHOR_DRAIN_LABEL,
            (*config._WRITABLE_TREE_ATTRS[AUTHOR_DRAIN_LABEL], "extra_mount_dir"))
    seen: list[list[str]] = []
    paths = _spy_paths(w.repo, extra_mount=extra_mount)
    _spy_build(monkeypatch, w.repo, seen)
    outcomes: dict = {}
    w.trees.close()
    assert descriptors_under(w.repo) == []

    _trigger(paths, AUTHOR_DRAIN_LABEL, outcomes)

    assert seen, "the curator's batch never built its config"
    assert all(held == _held_roots(paths) for held in seen), (seen, _held_roots(paths))
    assert len(_held_roots(paths)) == (3 if extra else 2)
    assert descriptors_under(w.repo) == [], "a held root outlived the seam"
    assert _is_held(outcomes), outcomes
    bad = [r.getMessage() for r in caplog.records if "Bad file descriptor" in r.getMessage()]
    assert bad == [], bad


@pytest.mark.parametrize("fault", ["RuntimeError", "OSError"])
def test_the_trigger_releases_the_trees_when_the_batch_raises(tmp_path, monkeypatch, fault):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    w = world(tmp_path)
    seen: list[list[str]] = []
    exc = RuntimeError("the batch blew up") if fault == "RuntimeError" else OSError(5, "io fault")
    paths = _spy_paths(w.repo)
    _spy_build(monkeypatch, w.repo, seen, fault=exc)
    outcomes: dict = {}
    w.trees.close()

    if fault == "RuntimeError":
        with pytest.raises(RuntimeError, match="the batch blew up"):
            _trigger(paths, AUTHOR_DRAIN_LABEL, outcomes)
    else:
        assert _trigger(paths, AUTHOR_DRAIN_LABEL, outcomes) is None
    assert outcomes == {}

    assert seen == [_held_roots(paths)], seen
    assert descriptors_under(w.repo) == [], "a held root outlived the raising seam"


# Retired: test_below_the_threshold_nothing_is_held. The threshold gate moved from the seam to the
# store's claim (design r8 Flows: the claim takes each kind at or over its own threshold and nothing
# below); enforced by test_store_1278::test_d8_the_claim_takes_each_kind_at_or_over_its_own_threshold_and_nothing_below.
# A seam handed a claim never sees a below-threshold item, so there is nothing left to hold or not.


def _harness() -> Path:
    return Path(drains.__file__).resolve().parents[3] / "evaluations" / "harness.py"


#: Run in a fresh interpreter, as the harness runs: materialize the scenario into the scratch
#: dir (which sets up everything the run needs), then `run_author` over it; print what it
#: reported.
_HARNESS_RUN = """
import json, sys
from pathlib import Path
evals, scenario, scratch = (Path(a) for a in sys.argv[1:4])
sys.path.insert(0, str(evals))
import harness
harness.materialize(scenario, scratch)
run, _wall = harness.run_author(scratch)
print(json.dumps({"rc": run.returncode, "stdout": run.stdout, "stderr": run.stderr}))
"""


def test_the_eval_harness_runs_an_empty_queue_scenario_in_its_scratch_repo(tmp_path):
    """The harness runs an empty-queue scenario cleanly in its own scratch dir and never reads
    the retired learning-state variable."""
    evals = _harness().parent
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "findings.jsonl").write_text("", encoding="utf-8")
    scratch = tmp_path / "scratch-repo"
    scratch.mkdir()
    decoy = tmp_path / "decoy-state"
    decoy.mkdir()
    env = {**os.environ, "PYTHONPATH": str(evals.parent),
           "DEFENDER_LEARNING_STATE_DIR": str(decoy)}  # lint-stale-ref: ok — the retired variable is set on purpose to prove it is ignored

    proc = subprocess.run(
        [sys.executable, "-c", _HARNESS_RUN, str(evals), str(scenario), str(scratch)],
        env=env, capture_output=True, text=True, timeout=120, check=False)

    assert proc.returncode == 0, proc.stderr[-4000:]
    run = json.loads(proc.stdout.strip().splitlines()[-1])
    assert run["rc"] == 0, run
    assert sorted(p.name for p in decoy.iterdir()) == []
    assert not (scratch / "defender" / "lessons").exists(), "a product-shaped corpus was made"


@pytest.mark.postgres
def test_the_trigger_holds_nothing_for_an_injected_seam(store_world):  # noqa: F811 — the imported fixture
    """An injected `trigger_author` keeps its call shape (no `label`) and the lane opens nothing
    around it: the default seam is the only place the author label is consumed."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain

    w = store_world
    _publish_held(w)
    call(w.dsn, "publish_findings", w.t.tenant_id, "run-w1", [_NO_SYSTEM_WORLD_ROW], kind="questioner_finding")
    calls: list[tuple[tuple, dict, list[str]]] = []

    def injected(*a, **kw):
        calls.append((a, kw, sorted(descriptors_under(_drafts(w.t)))))

    rc = author_drain(w.t, w.paths, trigger=injected, box=BoxSpy())

    assert rc == 0
    assert [c[0][4] for c in calls] == ["author", "questioner_curator"]
    assert all("label" not in c[1] for c in calls), calls
    assert all(c[2] == [] for c in calls), "the lane held trees around an injected seam"
