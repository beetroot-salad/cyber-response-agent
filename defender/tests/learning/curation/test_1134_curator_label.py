from __future__ import annotations

import contextlib
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
from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS
from defender.tests.support.learning.core._state1135 import state_for_paths
from defender.tests.support.learning.curation._curator1134 import (
    is_link_to,
    leaf_refusal,
    plant_link,
    put,
    world,
)
from defender.tests.support.learning.curation._drain719 import finding_row, make_repo, pending, seed, stuck_records
from defender.tests.support.learning.curation._tree_listing_1134 import descriptors_under
from defender.tests.learning.curation.test_1134_mount_list import UNKNOWN_LABELS

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
        build(w.paths, state=w.state)

    cfg = build(w.paths, state=w.state, trees=w.trees)
    assert cfg.corpus_dir == getattr(w.paths, attr)
    assert cfg.corpus is w.trees.mount(cfg.corpus_dir)
    assert cfg.tree_for == w.trees.tree_for


@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_run_batch_takes_exactly_one_of_trees_and_cfg(tmp_path, channel):
    w = world(tmp_path)
    build, _attr = BUILDERS[channel]
    run = RUNNERS[channel]
    cfg = build(w.paths, state=w.state, trees=w.trees)

    with pytest.raises(TypeError):
        run(paths=w.paths, state=w.state)
    with pytest.raises(TypeError):
        run(paths=w.paths, state=w.state, trees=w.trees, cfg=cfg)

    assert run(paths=w.paths, state=w.state, trees=w.trees) == 0
    assert run(cfg=cfg) == 0


def _refusing_trees(w) -> dict[str, Any]:
    """Each way the trees a curator is handed can fail to hold its corpus exactly, as `(paths,
    open trees)`: opened for the lead member, or trees whose mounts omit the corpora (only
    `skills/`), move them elsewhere, hold only a folder above them (`defender/`), or only a
    folder below each corpus. Since #1179's amendment a member answers its own trees, so the
    wrong mount sets are opened directly (`DrainTrees.open`) rather than through a paths double
    that lies about a member's list."""
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
            build(paths, state=w.state, trees=trees)
        with pytest.raises(FatalConfigError):
            RUNNERS[channel](paths=paths, state=w.state, trees=trees)


@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_lane_corpus_is_the_trees_own_mount_whatever_opened_them(tmp_path, channel):
    w = world(tmp_path)
    build, attr = BUILDERS[channel]
    paths = LoopPaths(repo_root=w.repo, state_dir=tmp_path / "state")

    with DrainTrees.open((paths.lessons_dir, paths.lessons_questioner_dir)) as trees:
        corpus_dir = getattr(paths, attr)
        assert author_shared.lane_corpus(trees, corpus_dir) is trees.mount(corpus_dir)
        cfg = build(paths, state=w.state, trees=trees)
        assert cfg.corpus is trees.mount(corpus_dir)
        hit = cfg.tree_for(paths.lessons_questioner_dir / "y.md")
        assert hit is not None
        assert hit[0] is trees.mount(paths.lessons_questioner_dir)
        assert hit[1] == "y.md"


@pytest.mark.parametrize("channel", sorted(BUILDERS))
def test_cfg_corpus_is_the_held_mount_and_never_follows_a_link(tmp_path, channel):
    w = world(tmp_path)
    build, attr = BUILDERS[channel]
    cfg = build(w.paths, state=w.state, trees=w.trees)
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


def _held_queue(paths: LoopPaths) -> None:
    """One per-case finding from before #1234: the pre-author gate holds it
    (`retired_direction`), so a tick serves it without spawning any agent."""
    seed(paths, FINDINGS, [finding_row("f1", run_id="old-run", direction="adversarial")])


def _trigger_args(paths: LoopPaths) -> tuple:
    return (paths, state_for_paths(paths), FINDINGS, "LEARNING_AUTHOR_THRESHOLD", "author", "pending")


def test_the_trigger_requires_the_label_and_runs_the_batch_under_its_trees(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    w = world(tmp_path)
    _held_queue(w.paths)

    with pytest.raises(TypeError):
        drains._maybe_trigger_author(*_trigger_args(w.paths))
    assert "held_reason" not in pending(w.paths, FINDINGS)[0]

    drains._maybe_trigger_author(*_trigger_args(w.paths), label=AUTHOR_DRAIN_LABEL)

    [row] = pending(w.paths, FINDINGS)
    assert "held_reason" in row, row
    assert stuck_records(w.paths, FINDINGS) == []


def test_the_trigger_opens_the_trees_of_the_label_it_is_handed_and_no_other(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    w = world(tmp_path)
    _held_queue(w.paths)
    w.trees.close()

    with pytest.raises(FatalConfigError):
        drains._maybe_trigger_author(*_trigger_args(w.paths), label=LEAD_AUTHOR_DRAIN_LABEL)
    assert "held_reason" not in pending(w.paths, FINDINGS)[0]
    for non_member in UNKNOWN_LABELS:
        with pytest.raises(AttributeError):
            drains._maybe_trigger_author(*_trigger_args(w.paths), label=non_member)
        assert "held_reason" not in pending(w.paths, FINDINGS)[0]
        assert descriptors_under(w.repo) == []

    drains._maybe_trigger_author(*_trigger_args(w.paths), label=AUTHOR_DRAIN_LABEL)

    [row] = pending(w.paths, FINDINGS)
    assert "held_reason" in row, row
    assert stuck_records(w.paths, FINDINGS) == []


@contextlib.contextmanager
def _tenant_drain(tmp_path: Path, data_root: Path, files: dict | None = None):
    """The fixture tenant published for real with its forge bound (#1108 P4), and the drain's
    learning paths over a scratch product checkout: `(tenant, paths)`."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import drain_paths, product_repo
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge, published_tenant

    with published_tenant(tmp_path / "forge", root=data_root, files=files) as t:
        bind_forge(t)
        yield t, drain_paths(t, product_repo(tmp_path))


def _drafts(t: Any) -> Path:
    return Path(location_path(t.tenant.tenant_root)) / "drafts"


def test_author_drains_real_default_seam_carries_the_label_to_the_open(
        tmp_path, data_root, monkeypatch):
    """#1134 over the P4 drain (#1108 P4 flow 4): the drain's PRODUCTION `trigger_author` opens
    the author label's trees over the batch's draft — the gate holds the row, nothing is stuck,
    nothing stays held under the drafts, and nothing is delivered."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import (
        BoxSpy, author_drain, remote_branches)

    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    with _tenant_drain(tmp_path, data_root) as (t, paths):
        _held_queue(paths)

        rc = author_drain(t, paths, trigger=None, box=BoxSpy())

        assert rc == 0
        [row] = pending(paths, FINDINGS)
        assert "held_reason" in row, row
        assert stuck_records(paths, FINDINGS) == []
        assert stuck_records(paths, QUESTIONER_FINDINGS) == []
        assert descriptors_under(_drafts(t)) == []
        assert remote_branches(t.remote) == {}
        assert t.forge.creates == []


def test_a_lane_the_tenant_repo_never_committed_is_still_a_held_mount(
        tmp_path, data_root, monkeypatch):
    """#1134 over the P4 drain: the draft makes each lane's folder (amendment 3 C2), so a tenant
    repo holding no `agent/lessons-questioner/` still gives both curators their held corpus:
    neither channel records a hold fault, the gate holds the findings row, and the questioner
    curator serves its row. (Replaces the worktree-era "a missing mount point is a hold fault":
    a host-made draft has no missing lane.)"""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain

    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")
    with _tenant_drain(tmp_path, data_root, files={
            "agent/lessons-questioner/fixture-questioner-seed.md": None}) as (t, paths):
        _held_queue(paths)
        seed(paths, QUESTIONER_FINDINGS, [{"schema_version": 1, "finding_id": "w1",
                                          "subject": "world", "type": "lead-set",
                                          "finding": "a world finding"}])

        rc = author_drain(t, paths, trigger=None, box=BoxSpy())

        assert rc == 0
        assert stuck_records(paths, FINDINGS) == []
        assert stuck_records(paths, QUESTIONER_FINDINGS) == []
        [row] = pending(paths, FINDINGS)
        assert "held_reason" in row, row
        assert pending(paths, QUESTIONER_FINDINGS) == [], "the questioner curator never served"
        assert descriptors_under(_drafts(t)) == []


def test_a_hold_fault_at_the_open_propagates_out_of_the_seam(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    repo = make_repo(tmp_path)
    paths = LoopPaths(repo_root=repo, state_dir=tmp_path / "state")
    # make_repo now carries both live corpora (#1108 P4 U5); this case needs one absent
    subprocess.run(["git", "-C", str(repo), "rm", "-rq", str(paths.lessons_questioner_dir)], check=True)
    subprocess.run(["git", "-C", str(repo), "commit", "-qm", "no questioner corpus"], check=True)
    _held_queue(paths)

    with pytest.raises(FileNotFoundError):
        drains._maybe_trigger_author(*_trigger_args(paths), label=AUTHOR_DRAIN_LABEL)

    assert "held_reason" not in pending(paths, FINDINGS)[0]
    assert not os.path.lexists(paths.lessons_questioner_dir)
    assert descriptors_under(repo) == []


def _spy_paths(repo: Path, state: Path, seen: list[list[str]], *,
               fault: BaseException | None = None, extra_mount: Path | None = None) -> LoopPaths:
    """A `LoopPaths` (the seam's `paths`) that records, each time `learning_dir` is asked for
    (the builders read it for their prompt path after the open; `runs_dir`, which they read
    until #1166, is gone; `author_lock_file`, which they used to read, is the
    state handle's now), what this process holds under the repo; with `fault`, raises it after
    recording; with `extra_mount`, the paths carry a third mount for the author label to hold
    (`extra_mount_dir`, which the caller adds to the label's tree list). A class per call."""

    class Spy(LoopPaths):
        @property
        def extra_mount_dir(self) -> Path:
            assert extra_mount is not None
            return extra_mount

        @property
        def learning_dir(self) -> Path:  # type: ignore[override]
            seen.append(sorted(descriptors_under(self.repo_root)))
            if fault is not None:
                raise fault
            return super().learning_dir

    return Spy(repo_root=repo, state_dir=state)


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
    paths = _spy_paths(w.repo, tmp_path / "state", seen, extra_mount=extra_mount)
    _held_queue(paths)
    w.trees.close()
    assert descriptors_under(w.repo) == []

    drains._maybe_trigger_author(*_trigger_args(paths), label=AUTHOR_DRAIN_LABEL)

    assert seen, "the curator's batch never built its config"
    assert all(held == _held_roots(paths) for held in seen), (seen, _held_roots(paths))
    assert len(_held_roots(paths)) == (3 if extra else 2)
    assert descriptors_under(w.repo) == [], "a held root outlived the seam"
    assert "held_reason" in pending(paths, FINDINGS)[0]
    bad = [r.getMessage() for r in caplog.records if "Bad file descriptor" in r.getMessage()]
    assert bad == [], bad


@pytest.mark.parametrize("fault", ["RuntimeError", "OSError"])
def test_the_trigger_releases_the_trees_when_the_batch_raises(tmp_path, monkeypatch, fault):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    w = world(tmp_path)
    seen: list[list[str]] = []
    exc = RuntimeError("the batch blew up") if fault == "RuntimeError" else OSError(5, "io fault")
    paths = _spy_paths(w.repo, tmp_path / "state", seen, fault=exc)
    _held_queue(paths)
    w.trees.close()

    if fault == "RuntimeError":
        with pytest.raises(RuntimeError, match="the batch blew up"):
            drains._maybe_trigger_author(*_trigger_args(paths), label=AUTHOR_DRAIN_LABEL)
    else:
        assert drains._maybe_trigger_author(*_trigger_args(paths), label=AUTHOR_DRAIN_LABEL) is None

    assert seen == [_held_roots(paths)], seen
    assert descriptors_under(w.repo) == [], "a held root outlived the raising seam"


def test_below_the_threshold_nothing_is_held(tmp_path, monkeypatch):
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "5")
    w = world(tmp_path)
    asked: list[str] = []
    seen: list[list[str]] = []

    class CountsTheAsk(LoopPaths):
        @property
        def lessons_dir(self) -> Path:  # type: ignore[override]
            asked.append("lessons_dir")
            return super().lessons_dir

        @property
        def lessons_questioner_dir(self) -> Path:  # type: ignore[override]
            asked.append("lessons_questioner_dir")
            return super().lessons_questioner_dir

    paths = CountsTheAsk(repo_root=w.repo, state_dir=tmp_path / "state")
    _held_queue(paths)
    w.trees.close()
    asked.clear()

    drains._maybe_trigger_author(*_trigger_args(paths), label=AUTHOR_DRAIN_LABEL)

    assert asked == []
    assert seen == []
    assert "held_reason" not in pending(paths, FINDINGS)[0]
    assert descriptors_under(w.repo) == []


def _harness() -> Path:
    return Path(drains.__file__).resolve().parents[3] / "evaluations" / "harness.py"


#: Run in a fresh interpreter, as the harness runs: materialize the scenario into the scratch
#: dir (which, after #1108 P4, sets up everything the run needs: no `init_git` of a product-shaped
#: scratch repo), then `run_author` over it; print what it reported.
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
    the retired `DEFENDER_LEARNING_STATE_DIR`. (Its old pin on a product-shaped
    `defender/learning/_author.lock` under the scratch repo is gone with #1108 P4's harness
    against a draft: tenant_1108_p4/test_writers.py::test_o7_the_evals_harness_...)"""
    evals = _harness().parent
    scenario = tmp_path / "scenario"
    scenario.mkdir()
    (scenario / "findings.jsonl").write_text("", encoding="utf-8")
    scratch = tmp_path / "scratch-repo"
    scratch.mkdir()
    decoy = tmp_path / "decoy-state"
    decoy.mkdir()
    env = {**os.environ, "PYTHONPATH": str(evals.parent),
           "DEFENDER_LEARNING_STATE_DIR": str(decoy)}

    proc = subprocess.run(
        [sys.executable, "-c", _HARNESS_RUN, str(evals), str(scenario), str(scratch)],
        env=env, capture_output=True, text=True, timeout=120, check=False)

    assert proc.returncode == 0, proc.stderr[-4000:]
    run = json.loads(proc.stdout.strip().splitlines()[-1])
    assert run["rc"] == 0, run
    assert sorted(p.name for p in decoy.iterdir()) == []
    assert not (scratch / "defender" / "lessons").exists(), "a product-shaped corpus was made"


def test_the_trigger_holds_nothing_for_an_injected_seam(tmp_path, data_root, monkeypatch):
    """An injected `trigger_author` keeps its call shape (no `label`) and the lane opens nothing
    around it: the default seam is the only place the author label is consumed (over the P4
    drain's draft, #1108 P4 flow 4)."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain

    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    calls: list[tuple[tuple, dict, list[str]]] = []
    with _tenant_drain(tmp_path, data_root) as (t, paths):
        _held_queue(paths)

        def injected(*a, **kw):
            calls.append((a, kw, sorted(descriptors_under(_drafts(t)))))

        rc = author_drain(t, paths, trigger=injected, box=BoxSpy())

    assert rc == 0
    assert [c[0][4] for c in calls] == ["author", "questioner_curator"]
    assert all("label" not in c[1] for c in calls), calls
    assert all(c[2] == [] for c in calls), "the lane held trees around an injected seam"
